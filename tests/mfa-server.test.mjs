import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { generateTotp } from "../server/mfa.mjs";

async function waitForServer(baseUrl, child, logs) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Nimbus exited during startup:\n${logs.join("")}`);
    try {
      const response = await fetch(`${baseUrl}/api/health`);
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`Nimbus did not become healthy:\n${logs.join("")}`);
}

test("authenticator enrollment protects login and one-time recovery codes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "nimbus-direct-mfa-server-"));
  const port = 44_000 + process.pid % 1_000;
  const baseUrl = `http://127.0.0.1:${port}`;
  const logs = [];
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd: new URL("..", import.meta.url),
    env: {
      ...process.env,
      NODE_ENV: "development",
      HOST: "127.0.0.1",
      PORT: String(port),
      DATA_DIR: directory,
      APP_SECRET: "mfa-server-secret-that-is-at-least-32-characters",
      SESSION_COOKIE_SECURE: "false",
      ALLOW_DEMO_DATA: "false",
      BOOTSTRAP_ADMIN_EMAIL: "operator@example.test",
      BOOTSTRAP_ADMIN_PASSWORD: "operator password for mfa test",
      BOOTSTRAP_ADMIN_NAME: "Operator",
      RESOURCE_SYNC_SECONDS: "3600",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => logs.push(String(chunk)));
  child.stderr.on("data", (chunk) => logs.push(String(chunk)));

  let cookie = "";
  let csrfToken = "";
  async function request(path, { method = "GET", body, expectedStatus = null } = {}) {
    const headers = { Accept: "application/json" };
    if (cookie) headers.Cookie = cookie;
    if (csrfToken && method !== "GET") headers["X-CSRF-Token"] = csrfToken;
    let requestBody;
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      requestBody = JSON.stringify(body);
    }
    const response = await fetch(`${baseUrl}${path}`, { method, headers, body: requestBody });
    const payload = response.status === 204 ? null : await response.json();
    if (expectedStatus !== null) {
      assert.equal(response.status, expectedStatus, JSON.stringify(payload));
      return { response, payload };
    }
    if (!response.ok) throw Object.assign(new Error(payload?.error || `HTTP ${response.status}`), { response, payload });
    return { response, payload };
  }

  try {
    await waitForServer(baseUrl, child, logs);
    await request("/api/auth/login", {
      method: "POST",
      body: { email: "operator@example.test", password: "definitely the wrong password" },
      expectedStatus: 401,
    });
    const login = await request("/api/auth/login", {
      method: "POST",
      body: { email: "operator@example.test", password: "operator password for mfa test" },
    });
    cookie = String(login.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = login.payload.csrfToken;
    const initialDashboard = (await request("/api/v1/dashboard")).payload;
    assert.equal(initialDashboard.security.mfa.enabled, false);
    assert.equal(initialDashboard.security.sessions.length, 1);
    assert.equal(initialDashboard.security.sessions[0].current, true);
    const initialSecurityCenter = (await request("/api/admin/state")).payload.security;
    assert.equal(initialSecurityCenter.policy.requireAdminMfa, false);
    assert.equal(initialSecurityCenter.summary.failedLogins24h, 1);
    assert.ok(initialSecurityCenter.events.items.some((item) => item.action === "auth.login_failed"));

    const enforced = (await request("/api/admin/security/policy", {
      method: "PATCH",
      body: { requireAdminMfa: true },
    })).payload.policy;
    assert.equal(enforced.requireAdminMfa, true);
    await request("/api/admin/state", { expectedStatus: 403 });
    const restrictedDashboard = (await request("/api/v1/dashboard")).payload;
    assert.equal(restrictedDashboard.security.mfa.enrollmentRequired, true);
    assert.deepEqual(restrictedDashboard.resources, []);
    assert.deepEqual(restrictedDashboard.activity.items, []);

    const setup = (await request("/api/v1/security/mfa/setup", {
      method: "POST",
      body: { currentPassword: "operator password for mfa test" },
    })).payload.enrollment;
    assert.match(setup.secret, /^[A-Z2-7]{32}$/);
    assert.match(setup.uri, /^otpauth:\/\/totp\//);
    assert.match(setup.qrCode, /^data:image\/png;base64,/);
    const confirmed = (await request("/api/v1/security/mfa/confirm", {
      method: "POST",
      body: { code: generateTotp(setup.secret) },
    })).payload;
    assert.equal(confirmed.mfa.enabled, true);
    assert.equal(confirmed.recoveryCodes.length, 10);
    const recoveryCode = confirmed.recoveryCodes[0];
    assert.equal((await request("/api/v1/dashboard")).payload.security.mfa.recoveryCodesRemaining, 10);
    assert.equal((await request("/api/admin/state")).payload.security.summary.requiredPending, 0);
    await request("/api/v1/security/mfa/disable", {
      method: "POST",
      body: {
        currentPassword: "operator password for mfa test",
        code: generateTotp(setup.secret),
      },
      expectedStatus: 409,
    });
    const relaxed = (await request("/api/admin/security/policy", {
      method: "PATCH",
      body: { requireAdminMfa: false },
    })).payload.policy;
    assert.equal(relaxed.requireAdminMfa, false);

    await request("/api/auth/logout", { method: "POST", body: {} });
    cookie = "";
    csrfToken = "";
    const challenged = await request("/api/auth/login", {
      method: "POST",
      body: { email: "operator@example.test", password: "operator password for mfa test" },
      expectedStatus: 202,
    });
    assert.equal(challenged.payload.mfaRequired, true);
    await request("/api/auth/mfa", {
      method: "POST",
      body: { challengeToken: challenged.payload.challengeToken, code: "000000" },
      expectedStatus: 401,
    });
    const verified = await request("/api/auth/mfa", {
      method: "POST",
      body: { challengeToken: challenged.payload.challengeToken, code: generateTotp(setup.secret) },
    });
    cookie = String(verified.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = verified.payload.csrfToken;
    assert.equal(verified.payload.user.mfaEnabled, true);

    await request("/api/auth/logout", { method: "POST", body: {} });
    cookie = "";
    csrfToken = "";
    const recoveryChallenge = await request("/api/auth/login", {
      method: "POST",
      body: { email: "operator@example.test", password: "operator password for mfa test" },
      expectedStatus: 202,
    });
    const recovered = await request("/api/auth/mfa", {
      method: "POST",
      body: { challengeToken: recoveryChallenge.payload.challengeToken, code: recoveryCode },
    });
    cookie = String(recovered.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = recovered.payload.csrfToken;
    assert.equal((await request("/api/v1/dashboard")).payload.security.mfa.recoveryCodesRemaining, 9);

    const disabled = (await request("/api/v1/security/mfa/disable", {
      method: "POST",
      body: {
        currentPassword: "operator password for mfa test",
        code: generateTotp(setup.secret),
      },
    })).payload;
    assert.equal(disabled.mfa.enabled, false);
    await request("/api/auth/logout", { method: "POST", body: {} });
    cookie = "";
    csrfToken = "";
    const passwordOnly = await request("/api/auth/login", {
      method: "POST",
      body: { email: "operator@example.test", password: "operator password for mfa test" },
    });
    assert.equal(passwordOnly.payload.user.mfaEnabled, false);
    cookie = String(passwordOnly.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = passwordOnly.payload.csrfToken;
    const assistedUser = (await request("/api/admin/users", {
      method: "POST",
      body: {
        email: "assisted@example.test",
        displayName: "Assisted Admin",
        password: "assisted admin password",
        role: "admin",
        customerId: null,
      },
    })).payload.user;
    await request("/api/auth/logout", { method: "POST", body: {} });
    cookie = "";
    csrfToken = "";
    const assistedLogin = await request("/api/auth/login", {
      method: "POST",
      body: { email: "assisted@example.test", password: "assisted admin password" },
    });
    cookie = String(assistedLogin.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = assistedLogin.payload.csrfToken;
    const assistedSetup = (await request("/api/v1/security/mfa/setup", {
      method: "POST",
      body: { currentPassword: "assisted admin password" },
    })).payload.enrollment;
    await request("/api/v1/security/mfa/confirm", {
      method: "POST",
      body: { code: generateTotp(assistedSetup.secret) },
    });
    await request("/api/auth/logout", { method: "POST", body: {} });
    cookie = "";
    csrfToken = "";
    const operatorLogin = await request("/api/auth/login", {
      method: "POST",
      body: { email: "operator@example.test", password: "operator password for mfa test" },
    });
    cookie = String(operatorLogin.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = operatorLogin.payload.csrfToken;
    assert.equal((await request("/api/admin/state")).payload.users.find((item) => item.id === assistedUser.id).mfaEnabled, true);
    await request(`/api/admin/users/${encodeURIComponent(assistedUser.id)}/mfa/reset`, {
      method: "POST",
      body: { currentPassword: "operator password for mfa test" },
    });
    assert.equal((await request("/api/admin/state")).payload.users.find((item) => item.id === assistedUser.id).mfaEnabled, false);
    assert.ok((await request("/api/admin/state")).payload.audit.items.some((item) => item.action === "admin.user.mfa_reset"));
  } finally {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await Promise.race([once(child, "exit"), new Promise((resolve) => setTimeout(resolve, 2_000))]);
    }
    await rm(directory, { recursive: true, force: true });
  }
});
