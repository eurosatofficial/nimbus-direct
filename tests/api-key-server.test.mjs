import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openStore } from "../server/store.mjs";

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

test("integration-key HTTP routes enforce groups, resources, and forbidden credential endpoints", async () => {
  const directory = await mkdtemp(join(tmpdir(), "nimbus-direct-api-key-server-"));
  const appSecret = "api-key-server-integration-secret-at-least-32-characters";
  const store = await openStore(directory, { appSecret });
  let keySecret;
  let overviewOnlySecret;
  const allowedResourceId = "demo-eu:qemu:101";
  const otherResourceId = "demo-eu:qemu:105";
  try {
    const customer = store.createCustomer({ id: "acme", name: "Acme" });
    const user = await store.createUser({
      email: "automation@example.test",
      displayName: "Automation",
      password: "customer API key server password",
      customerId: customer.id,
    });
    const admin = await store.createUser({
      email: "admin@example.test",
      displayName: "Admin",
      password: "administrator API key server password",
      role: "admin",
    });
    store.createCluster({
      id: "demo-eu",
      name: "Demo",
      apiUrl: "https://pve.example.test:8006",
      tokenId: "nimbus@pve!panel",
      tokenSecret: "proxmox-secret-value",
    });
    store.syncResources("demo-eu", [
      { type: "qemu", vmid: 101, node: "pve-a", name: "web", status: "running" },
      { type: "qemu", vmid: 105, node: "pve-b", name: "db", status: "running" },
    ]);
    for (const resourceId of [allowedResourceId, otherResourceId]) {
      store.assignResource({
        customerId: customer.id,
        resourceId,
        permissions: ["view_status", "view_usage", "start", "shutdown", "reboot"],
      });
    }
    store.updateUserApiPolicy(user.id, {
      enabled: true,
      groups: ["server_overview", "power_management"],
      resourceIds: [],
      maxActiveKeys: 3,
      maxLifetimeDays: 365,
      allowNoExpiry: false,
    }, admin.id);
    keySecret = store.createUserApiKey(user.id, {
      name: "Home Assistant",
      groups: ["server_overview", "power_management"],
      resourceIds: [allowedResourceId],
      expiresAt: Date.now() + 30 * 86_400_000,
    }).secret;
    overviewOnlySecret = store.createUserApiKey(user.id, {
      name: "Monitoring",
      groups: ["server_overview"],
      resourceIds: [allowedResourceId],
      expiresAt: Date.now() + 30 * 86_400_000,
    }).secret;
  } finally {
    store.close();
  }

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
      APP_SECRET: appSecret,
      SESSION_COOKIE_SECURE: "false",
      ALLOW_DEMO_DATA: "true",
      RESOURCE_SYNC_SECONDS: "3600",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => logs.push(String(chunk)));
  child.stderr.on("data", (chunk) => logs.push(String(chunk)));

  async function request(path, { method = "GET", body, token = keySecret } = {}) {
    const headers = { Accept: "application/json", Authorization: `Bearer ${token}` };
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
    const resources = await request("/api/v1/resources");
    assert.equal(resources.response.status, 200);
    assert.equal(resources.payload.resources.total, 1);
    assert.equal(resources.payload.resources.items[0].id, allowedResourceId);

    const power = await request(`/api/v1/resources/${encodeURIComponent(allowedResourceId)}/actions`, {
      method: "POST",
      body: { action: "reboot" },
    });
    assert.equal(power.response.status, 200);

    const hidden = await request(`/api/v1/resources/${encodeURIComponent(otherResourceId)}`);
    assert.equal(hidden.response.status, 403);
    assert.equal(hidden.payload.error, "api_key_resource_denied");

    const missingGroup = await request(`/api/v1/resources/${encodeURIComponent(allowedResourceId)}/actions`, {
      method: "POST",
      token: overviewOnlySecret,
      body: { action: "reboot" },
    });
    assert.equal(missingGroup.response.status, 403);
    assert.equal(missingGroup.payload.error, "api_key_scope_denied");

    for (const [path, method] of [
      ["/api/v1/api-keys", "GET"],
      ["/api/v1/dashboard", "GET"],
      ["/api/v1/security/mfa/setup", "POST"],
      [`/api/v1/resources/${encodeURIComponent(allowedResourceId)}/config`, "PUT"],
    ]) {
      const result = await request(path, { method, body: method === "GET" ? undefined : {} });
      assert.equal(result.response.status, 403, `${method} ${path}`);
      assert.equal(result.payload.error, "api_key_route_forbidden");
    }
  } finally {
    child.kill("SIGTERM");
    if (child.exitCode === null) await once(child, "exit");
    await rm(directory, { recursive: true, force: true });
  }
});
