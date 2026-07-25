import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import { openStore } from "../server/store.mjs";

const APP_SECRET = "account-server-secret-that-is-at-least-32-characters";

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

test("invitation and recovery HTTP flows never expose account tokens", async () => {
  const directory = await mkdtemp(join(tmpdir(), "nimbus-direct-account-server-"));
  const port = 45_000 + process.pid % 1_000;
  const baseUrl = `http://127.0.0.1:${port}`;
  let invitedUser;
  let recoveryUser;
  let invitation;
  let recovery;
  let recoverySession;
  const seed = await openStore(directory, { appSecret: APP_SECRET });
  try {
    await seed.createUser({
      email: "admin@example.test",
      displayName: "Admin",
      password: "administrator account password",
      role: "admin",
    });
    const customer = seed.createCustomer({ id: "acme", name: "Acme" });
    invitedUser = await seed.createInvitedUser({
      email: "invited@example.test",
      displayName: "Invited User",
      customerId: customer.id,
    });
    recoveryUser = await seed.createUser({
      email: "recovery@example.test",
      displayName: "Recovery User",
      password: "original recovery password",
      customerId: customer.id,
    });
    invitation = seed.createAccountToken({ userId: invitedUser.id, purpose: "invitation" });
    recovery = seed.createAccountToken({ userId: recoveryUser.id, purpose: "password_reset" });
    recoverySession = seed.createSession({ userId: recoveryUser.id, ttlMs: 60_000 });
    seed.saveEmailSettings({
      enabled: true,
      host: "127.0.0.1",
      port: 1,
      security: "tls",
      username: "",
      fromName: "Nimbus Direct",
      fromEmail: "nimbus@example.test",
      appUrl: baseUrl,
    });
  } finally {
    seed.close();
  }

  const logs = [];
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd: new URL("..", import.meta.url),
    env: {
      ...process.env,
      NODE_ENV: "development",
      HOST: "127.0.0.1",
      PORT: String(port),
      DATA_DIR: directory,
      APP_SECRET,
      SESSION_COOKIE_SECURE: "false",
      ALLOW_DEMO_DATA: "false",
      RESOURCE_SYNC_SECONDS: "3600",
      EMAIL_QUEUE_SECONDS: "3600",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => logs.push(String(chunk)));
  child.stderr.on("data", (chunk) => logs.push(String(chunk)));

  let cookie = "";
  let csrfToken = "";
  function countRecoverySessions() {
    const inspection = new DatabaseSync(join(directory, "nimbus-direct.sqlite"), { readOnly: true });
    const count = inspection.prepare("SELECT COUNT(*) AS count FROM sessions WHERE user_id=?").get(recoveryUser.id).count;
    inspection.close();
    return count;
  }
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
    const invitationCheck = (await request("/api/auth/account-token", {
      method: "POST",
      body: { purpose: "invitation", token: invitation.token },
    })).payload;
    assert.equal(invitationCheck.valid, true);
    assert.equal(invitationCheck.emailHint.includes("invited@example.test"), false);
    await request("/api/auth/account/complete", {
      method: "POST",
      body: {
        purpose: "invitation",
        token: invitation.token,
        password: "invited private password",
        confirmPassword: "invited private password",
      },
    });
    await request("/api/auth/account-token", {
      method: "POST",
      body: { purpose: "invitation", token: invitation.token },
      expectedStatus: 400,
    });
    const invitedLogin = await request("/api/auth/login", {
      method: "POST",
      body: { email: invitedUser.email, password: "invited private password" },
    });
    cookie = String(invitedLogin.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = invitedLogin.payload.csrfToken;
    await request("/api/auth/logout", { method: "POST", body: {} });
    cookie = "";
    csrfToken = "";

    await request("/api/auth/account/complete", {
      method: "POST",
      body: {
        purpose: "password_reset",
        token: recovery.token,
        password: "replacement recovery password",
        confirmPassword: "replacement recovery password",
      },
    });
    assert.equal(countRecoverySessions(), 0);
    await request("/api/auth/login", {
      method: "POST",
      body: { email: recoveryUser.email, password: "original recovery password" },
      expectedStatus: 401,
    });
    const recoveredLogin = await request("/api/auth/login", {
      method: "POST",
      body: { email: recoveryUser.email, password: "replacement recovery password" },
    });
    cookie = String(recoveredLogin.response.headers.get("set-cookie") || "").split(";")[0];
    assert.equal(cookie.includes(recoverySession.token), false);
    csrfToken = recoveredLogin.payload.csrfToken;
    await request("/api/auth/logout", { method: "POST", body: {} });
    cookie = "";
    csrfToken = "";
    assert.equal(countRecoverySessions(), 0);

    const knownForgot = (await request("/api/auth/password/forgot", {
      method: "POST",
      body: { email: recoveryUser.email },
    })).payload;
    const unknownForgot = (await request("/api/auth/password/forgot", {
      method: "POST",
      body: { email: "missing@example.test" },
    })).payload;
    assert.deepEqual(knownForgot, unknownForgot);
    assert.equal(countRecoverySessions(), 0);

    const adminLogin = await request("/api/auth/login", {
      method: "POST",
      body: { email: "admin@example.test", password: "administrator account password" },
    });
    cookie = String(adminLogin.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = adminLogin.payload.csrfToken;
    const created = (await request("/api/admin/invitations", {
      method: "POST",
      body: { email: "second@example.test", displayName: "Second Admin", role: "admin" },
    })).payload;
    assert.equal(created.user.passwordSet, false);
    assert.equal(JSON.stringify(created).includes("token"), false);
    assert.ok(created.invitation.expiresAt > Date.now());
    await request(`/api/admin/users/${encodeURIComponent(created.user.id)}/invitation/resend`, {
      method: "POST",
      body: {},
    });
    await request(`/api/admin/users/${encodeURIComponent(created.user.id)}/invitation/revoke`, {
      method: "POST",
      body: {},
    });
    const finalState = (await request("/api/admin/state")).payload;
    const pending = finalState.users.find((user) => user.id === created.user.id);
    assert.equal(pending.passwordSet, false);
    assert.equal(pending.invitationExpiresAt, null);
    assert.ok(finalState.audit.items.some((entry) => entry.action === "admin.user.invited"));
    assert.ok(finalState.audit.items.some((entry) => entry.action === "admin.user.invitation_resent"));
    assert.ok(finalState.audit.items.some((entry) => entry.action === "admin.user.invitation_revoked"));
    assert.equal(JSON.stringify(finalState).includes(invitation.token), false);
    assert.equal(JSON.stringify(finalState).includes(recovery.token), false);
    assert.equal(countRecoverySessions(), 0);
  } finally {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await Promise.race([once(child, "exit"), new Promise((resolve) => setTimeout(resolve, 2_000))]);
      if (child.exitCode === null) {
        child.kill("SIGKILL");
        await once(child, "exit");
      }
    }
    const verified = await openStore(directory, { appSecret: APP_SECRET });
    try {
      const accountRows = verified.database.prepare("SELECT * FROM account_tokens").all();
      assert.equal(JSON.stringify(accountRows).includes(invitation.token), false);
      assert.equal(JSON.stringify(accountRows).includes(recovery.token), false);
    } finally {
      verified.close();
      await rm(directory, { recursive: true, force: true });
    }
  }
});
