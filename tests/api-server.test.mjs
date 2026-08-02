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

test("Nimbus API authenticates a device and preserves assignment authorization", async () => {
  const directory = await mkdtemp(join(tmpdir(), "nimbus-direct-api-server-"));
  const port = 47_000 + process.pid % 1_000;
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
      APP_SECRET: "api-server-integration-secret-at-least-32-characters",
      SESSION_COOKIE_SECURE: "false",
      ALLOW_DEMO_DATA: "true",
      BOOTSTRAP_ADMIN_EMAIL: "admin-api@example.test",
      BOOTSTRAP_ADMIN_PASSWORD: "administrator API server password",
      BOOTSTRAP_CUSTOMER_ID: "acme",
      BOOTSTRAP_CUSTOMER_NAME: "Acme",
      BOOTSTRAP_CUSTOMER_EMAIL: "customer-api@example.test",
      BOOTSTRAP_CUSTOMER_PASSWORD: "customer API server password",
      RESOURCE_SYNC_SECONDS: "3600",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => logs.push(String(chunk)));
  child.stderr.on("data", (chunk) => logs.push(String(chunk)));

  async function request(path, { method = "GET", body, accessToken } = {}) {
    const headers = { Accept: "application/json" };
    if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
    let requestBody;
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      requestBody = JSON.stringify(body);
    }
    const response = await fetch(`${baseUrl}${path}`, { method, headers, body: requestBody });
    const payload = response.status === 204 ? null : await response.json();
    return { response, payload };
  }

  try {
    await waitForServer(baseUrl, child, logs);
    const discovery = await request("/api/v1");
    assert.equal(discovery.response.status, 200);
    assert.equal(discovery.payload.version, "v1");
    assert.equal(discovery.payload.authentication.refreshRotation, true);
    const openapi = await request("/api/v1/openapi.json");
    assert.equal(openapi.response.status, 200);
    assert.equal(openapi.payload.openapi, "3.1.0");

    const login = await request("/api/v1/auth/token", {
      method: "POST",
      body: {
        email: "customer-api@example.test",
        password: "customer API server password",
        deviceName: "Integration phone",
        platform: "android",
        appVersion: "1.0.0-test",
      },
    });
    assert.equal(login.response.status, 200);
    assert.match(login.payload.accessToken, /^nmb_at_/);
    assert.match(login.payload.refreshToken, /^nmb_rt_/);
    assert.equal(login.payload.user.customerId, "acme");

    const accessToken = login.payload.accessToken;
    const resources = await request("/api/v1/resources", { accessToken });
    assert.equal(resources.response.status, 200);
    assert.equal(resources.payload.resources.total, 3);
    assert.ok(resources.payload.resources.items.every((resource) => resource.customerId === "acme"));

    const ownResource = resources.payload.resources.items[0];
    const action = await request(`/api/v1/resources/${encodeURIComponent(ownResource.id)}/actions`, {
      method: "POST",
      accessToken,
      body: { action: "reboot" },
    });
    assert.equal(action.response.status, 200);
    assert.equal(action.payload.completed, true);

    const hiddenResource = await request(`/api/v1/resources/${encodeURIComponent("demo-eu:qemu:203")}`, { accessToken });
    assert.equal(hiddenResource.response.status, 404);
    assert.equal(hiddenResource.payload.error, "resource_not_found");
    const admin = await request("/api/v1/admin/state", { accessToken });
    assert.equal(admin.response.status, 403);
    assert.equal(admin.payload.error, "admin_required");

    const adminLogin = await request("/api/v1/auth/token", {
      method: "POST",
      body: {
        email: "admin-api@example.test",
        password: "administrator API server password",
        deviceName: "Administrator phone",
        platform: "ios",
        appVersion: "0.2.1-test",
      },
    });
    assert.equal(adminLogin.response.status, 200);
    const adminResources = await request("/api/v1/resources?limit=200", {
      accessToken: adminLogin.payload.accessToken,
    });
    assert.equal(adminResources.response.status, 200);
    assert.equal(adminResources.payload.resources.total, 5);
    const unassignedResource = adminResources.payload.resources.items
      .find((resource) => resource.id === "demo-eu:qemu:203");
    assert.equal(unassignedResource.customerId, null);
    assert.ok(unassignedResource.permissions.includes("start"));
    assert.ok(unassignedResource.permissions.includes("console"));
    assert.ok(unassignedResource.permissions.includes("snapshot_create"));
    assert.ok(unassignedResource.permissions.includes("iso_mount"));
    const adminAction = await request(`/api/v1/resources/${encodeURIComponent(unassignedResource.id)}/actions`, {
      method: "POST",
      accessToken: adminLogin.payload.accessToken,
      body: { action: "start" },
    });
    assert.equal(adminAction.response.status, 200);
    assert.equal(adminAction.payload.completed, true);

    const refreshed = await request("/api/v1/auth/refresh", {
      method: "POST",
      body: { refreshToken: login.payload.refreshToken },
    });
    assert.equal(refreshed.response.status, 200);
    assert.notEqual(refreshed.payload.accessToken, accessToken);
    const expiredAccess = await request("/api/v1/me", { accessToken });
    assert.equal(expiredAccess.response.status, 401);
    const me = await request("/api/v1/me", { accessToken: refreshed.payload.accessToken });
    assert.equal(me.response.status, 200);
    assert.equal(me.payload.capabilities.mobileApi, true);
    const pushToken = "cd".repeat(32);
    const registeredPush = await request("/api/v1/push/devices", {
      method: "POST",
      accessToken: refreshed.payload.accessToken,
      body: {
        token: pushToken,
        platform: "ios",
        environment: "sandbox",
        appVersion: "0.2.0",
      },
    });
    assert.equal(registeredPush.response.status, 200);
    assert.equal(registeredPush.payload.registered, true);
    assert.equal(registeredPush.payload.pushAvailable, false);
    const unregisteredPush = await request("/api/v1/push/devices/unregister", {
      method: "POST",
      accessToken: refreshed.payload.accessToken,
      body: { token: pushToken },
    });
    assert.equal(unregisteredPush.response.status, 204);

    const reused = await request("/api/v1/auth/refresh", {
      method: "POST",
      body: { refreshToken: login.payload.refreshToken },
    });
    assert.equal(reused.response.status, 401);
    assert.equal(reused.payload.error, "refresh_token_reused");
    const revoked = await request("/api/v1/me", { accessToken: refreshed.payload.accessToken });
    assert.equal(revoked.response.status, 401);
  } finally {
    child.kill("SIGTERM");
    if (child.exitCode === null) await once(child, "exit");
    await rm(directory, { recursive: true, force: true });
  }
});
