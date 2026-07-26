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

test("public demo remains browsable while every product mutation is rejected centrally", async () => {
  const directory = await mkdtemp(join(tmpdir(), "nimbus-direct-read-only-"));
  const port = 45_000 + process.pid % 1_000;
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
      APP_SECRET: "public-demo-server-secret-that-is-at-least-32-characters",
      SESSION_COOKIE_SECURE: "false",
      ALLOW_DEMO_DATA: "true",
      DEMO_READ_ONLY: "true",
      BOOTSTRAP_ADMIN_EMAIL: "admin-demo@example.test",
      BOOTSTRAP_ADMIN_PASSWORD: "shared admin demo password",
      BOOTSTRAP_CUSTOMER_ID: "demo-customer",
      BOOTSTRAP_CUSTOMER_NAME: "Nimbus Demo Customer",
      BOOTSTRAP_CUSTOMER_EMAIL: "customer-demo@example.test",
      BOOTSTRAP_CUSTOMER_PASSWORD: "shared customer demo password",
      RESOURCE_SYNC_SECONDS: "3600",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => logs.push(String(chunk)));
  child.stderr.on("data", (chunk) => logs.push(String(chunk)));

  let cookie = "";
  let csrfToken = "";
  async function request(path, { method = "GET", body, headers = {} } = {}) {
    const requestHeaders = { Accept: "application/json", ...headers };
    if (cookie) requestHeaders.Cookie = cookie;
    if (csrfToken && !["GET", "HEAD"].includes(method)) requestHeaders["X-CSRF-Token"] = csrfToken;
    let requestBody = body;
    if (body !== undefined && !Buffer.isBuffer(body)) {
      requestHeaders["Content-Type"] = "application/json";
      requestBody = JSON.stringify(body);
    }
    const response = await fetch(`${baseUrl}${path}`, { method, headers: requestHeaders, body: requestBody });
    const payload = response.status === 204 ? null : await response.json();
    return { response, payload };
  }
  async function login(email, password) {
    const result = await request("/api/auth/login", { method: "POST", body: { email, password } });
    assert.equal(result.response.status, 200);
    assert.equal(result.payload.demoReadOnly, true);
    cookie = String(result.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = result.payload.csrfToken;
  }
  async function expectReadOnly(path, options) {
    const result = await request(path, options);
    assert.equal(result.response.status, 403, `${options.method} ${path}`);
    assert.equal(result.payload.error, "demo_read_only");
    return result;
  }

  try {
    await waitForServer(baseUrl, child, logs);
    const anonymousSession = await request("/api/auth/session");
    assert.equal(anonymousSession.response.status, 401);
    assert.equal(anonymousSession.payload.demoReadOnly, true);

    await login("admin-demo@example.test", "shared admin demo password");
    const adminState = await request("/api/admin/state");
    assert.equal(adminState.response.status, 200);
    assert.equal(adminState.payload.mode, "demo_read_only");
    assert.equal(adminState.payload.demoReadOnly, true);
    assert.deepEqual(adminState.payload.clusters.map((cluster) => cluster.id), ["demo-eu"]);
    assert.equal(adminState.payload.emailSettings.configured, false);
    assert.equal(adminState.payload.audit.total, 0);
    const adminDashboard = await request("/api/v1/dashboard");
    assert.equal(adminDashboard.payload.capabilities.demoReadOnly, true);
    const adminResource = adminDashboard.payload.resources[0];
    assert.ok(adminResource);

    await expectReadOnly("/api/admin/operations/refresh", { method: "POST", body: {} });
    await expectReadOnly("/api/admin/security/policy", { method: "PATCH", body: { newLoginEmail: true } });
    await expectReadOnly(`/api/v1/resources/${encodeURIComponent(adminResource.id)}/actions`, {
      method: "POST",
      body: { action: "stop" },
    });
    await expectReadOnly("/api/auth/password/forgot", {
      method: "POST",
      body: { email: "admin-demo@example.test" },
    });
    const adminLogout = await request("/api/auth/logout", { method: "POST", body: {} });
    assert.equal(adminLogout.response.status, 204);
    cookie = "";
    csrfToken = "";

    await login("customer-demo@example.test", "shared customer demo password");
    const dashboard = await request("/api/v1/dashboard");
    assert.equal(dashboard.response.status, 200);
    assert.equal(dashboard.payload.mode, "demo_read_only");
    assert.equal(dashboard.payload.resources.length, 3);
    assert.equal(dashboard.payload.security.sessions.length, 1);
    assert.equal(dashboard.payload.security.sessions[0].current, true);
    assert.equal(dashboard.payload.security.sessions[0].ipAddress, "Hidden in public demo");
    const resource = dashboard.payload.resources[0];
    const detail = await request(`/api/v1/resources/${encodeURIComponent(resource.id)}`);
    assert.equal(detail.response.status, 200);
    assert.equal(detail.payload.instance.id, resource.id);
    assert.equal((await request("/api/v1/network")).response.status, 200);
    assert.equal((await request("/api/v1/support/tickets")).response.status, 200);

    await expectReadOnly(`/api/v1/resources/${encodeURIComponent(resource.id)}/actions`, {
      method: "POST",
      body: { action: "stop" },
    });
    await expectReadOnly(`/api/v1/resources/${encodeURIComponent(resource.id)}/console`, { method: "POST", body: {} });
    await expectReadOnly(`/api/v1/resources/${encodeURIComponent(resource.id)}/snapshots`, {
      method: "POST",
      body: { name: "must-not-exist" },
    });
    await expectReadOnly(`/api/v1/resources/${encodeURIComponent(resource.id)}/media/mount`, {
      method: "POST",
      body: { isoImageId: "not-used" },
    });
    await expectReadOnly("/api/v1/support/tickets", {
      method: "POST",
      body: { subject: "Must not exist", category: "technical", priority: "normal", message: "Blocked." },
    });
    await expectReadOnly("/api/v1/profile", { method: "PATCH", body: { displayName: "Changed" } });
    await expectReadOnly("/api/v1/password", {
      method: "POST",
      body: { currentPassword: "shared customer demo password", password: "replacement demo password" },
    });
    await expectReadOnly("/api/v1/security/mfa/setup", {
      method: "POST",
      body: { currentPassword: "shared customer demo password" },
    });
    await expectReadOnly("/api/v1/notifications/preferences", {
      method: "PATCH",
      body: { inAppEnabled: false },
    });

    const unchanged = await request(`/api/v1/resources/${encodeURIComponent(resource.id)}`);
    assert.equal(unchanged.payload.instance.status, resource.status);
    assert.equal((await request("/api/v1/support/tickets")).payload.tickets.total, 0);
    assert.equal((await request("/api/v1/dashboard")).payload.activity.total, 0);
    const customerLogout = await request("/api/auth/logout", { method: "POST", body: {} });
    assert.equal(customerLogout.response.status, 204);
  } finally {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await Promise.race([once(child, "exit"), new Promise((resolve) => setTimeout(resolve, 2_000))]);
    }
    await rm(directory, { recursive: true, force: true });
  }
});
