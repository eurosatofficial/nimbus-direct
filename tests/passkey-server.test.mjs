import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

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

test("passkey endpoints expose only short-lived one-time WebAuthn challenges", async () => {
  const directory = await mkdtemp(join(tmpdir(), "nimbus-direct-passkey-server-"));
  const port = 48_000 + process.pid % 1_000;
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
      APP_SECRET: "passkey-server-secret-that-is-at-least-32-characters",
      SESSION_COOKIE_SECURE: "false",
      ALLOW_DEMO_DATA: "false",
      BOOTSTRAP_ADMIN_EMAIL: "operator@example.test",
      BOOTSTRAP_ADMIN_PASSWORD: "operator password for passkey test",
      BOOTSTRAP_ADMIN_NAME: "Operator",
      RESOURCE_SYNC_SECONDS: "3600",
      WEBAUTHN_RP_ID: "127.0.0.1",
      WEBAUTHN_ORIGIN: baseUrl,
      WEBAUTHN_RP_NAME: "Nimbus Test",
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
    assert.deepEqual((await request("/api/auth/passkeys/status")).payload, { enabled: true });

    const loginChallenge = (await request("/api/auth/passkeys/options", { method: "POST", body: {} })).payload;
    assert.equal(loginChallenge.options.rpId, "127.0.0.1");
    assert.equal(loginChallenge.options.userVerification, "required");
    assert.ok(loginChallenge.challengeToken);
    assert.equal("challenge" in loginChallenge, false);
    await request("/api/auth/passkeys/verify", {
      method: "POST",
      body: { challengeToken: loginChallenge.challengeToken, response: { id: "unknown" } },
      expectedStatus: 401,
    });
    await request("/api/auth/passkeys/verify", {
      method: "POST",
      body: { challengeToken: loginChallenge.challengeToken, response: { id: "unknown" } },
      expectedStatus: 401,
    });

    const login = await request("/api/auth/login", {
      method: "POST",
      body: { email: "operator@example.test", password: "operator password for passkey test" },
    });
    cookie = String(login.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = login.payload.csrfToken;
    await request("/api/v1/security/passkeys/registration/options", {
      method: "POST",
      body: { currentPassword: "incorrect password" },
      expectedStatus: 400,
    });
    const registration = (await request("/api/v1/security/passkeys/registration/options", {
      method: "POST",
      body: { currentPassword: "operator password for passkey test" },
    })).payload;
    assert.equal(registration.options.rp.id, "127.0.0.1");
    assert.equal(registration.options.authenticatorSelection.residentKey, "required");
    assert.ok(registration.challengeToken);
    assert.equal("publicKey" in registration, false);

    await request("/api/v1/security/passkeys/registration/verify", {
      method: "POST",
      body: { challengeToken: registration.challengeToken, name: "Fake", response: {} },
      expectedStatus: 400,
    });
    await request("/api/v1/security/passkeys/registration/verify", {
      method: "POST",
      body: { challengeToken: registration.challengeToken, name: "Fake", response: {} },
      expectedStatus: 401,
    });
    assert.deepEqual((await request("/api/v1/dashboard")).payload.security.passkeys.items, []);
  } finally {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await Promise.race([once(child, "exit"), new Promise((resolve) => setTimeout(resolve, 2_000))]);
    }
    await rm(directory, { recursive: true, force: true });
  }
});
