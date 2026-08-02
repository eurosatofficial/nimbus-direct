import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openStore } from "../server/store.mjs";

const APP_SECRET = "integration-key-test-secret-that-is-long-and-unique";

async function temporaryStore(callback) {
  const directory = await mkdtemp(join(tmpdir(), "nimbus-direct-api-keys-"));
  const store = await openStore(directory, { appSecret: APP_SECRET });
  try { return await callback(store); }
  finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
}

test("integration keys are hashed, group-scoped, resource-scoped, and live-policy constrained", async () => {
  await temporaryStore(async (store) => {
    const customer = store.createCustomer({ id: "acme", name: "Acme" });
    const user = await store.createUser({
      email: "automation@example.com",
      displayName: "Automation",
      password: "customer password for API key tests",
      customerId: customer.id,
    });
    const admin = await store.createUser({
      email: "admin@example.com",
      displayName: "Admin",
      password: "administrator password for tests",
      role: "admin",
    });
    store.createCluster({
      id: "production",
      name: "Production",
      apiUrl: "https://pve.example.test:8006",
      tokenId: "nimbus@pve!panel",
      tokenSecret: "proxmox-secret-value",
    });
    store.syncResources("production", [
      { type: "qemu", vmid: 101, node: "pve-a", name: "web", status: "running" },
      { type: "qemu", vmid: 105, node: "pve-b", name: "db", status: "running" },
    ]);
    const web = "production:qemu:101";
    const db = "production:qemu:105";
    store.assignResource({
      customerId: customer.id,
      resourceId: web,
      permissions: ["view_status", "view_usage", "start", "stop", "shutdown", "reboot"],
    });
    store.assignResource({
      customerId: customer.id,
      resourceId: db,
      permissions: ["view_status", "view_usage", "start", "shutdown", "reboot"],
    });

    const policy = store.updateUserApiPolicy(user.id, {
      enabled: true,
      groups: ["server_overview", "power_management"],
      resourceIds: [],
      maxActiveKeys: 2,
      maxLifetimeDays: 365,
      allowNoExpiry: false,
    }, admin.id);
    assert.equal(policy.enabled, true);
    assert.equal(policy.allVisibleResources, true);

    const input = {
      name: "Home Assistant",
      groups: ["server_overview", "power_management"],
      resourceIds: [web, db],
      expiresAt: Date.now() + 30 * 86_400_000,
    };
    const preview = store.previewUserApiKey(user.id, input);
    assert.equal(preview.permissionGroups.find((group) => group.id === "power_management").effective, true);
    assert.equal(preview.actions.find((action) => action.id === "start").state, "allowed");
    assert.equal(preview.actions.find((action) => action.id === "stop").state, "partial");
    assert.equal(preview.actions.find((action) => action.id === "reset").state, "denied");

    const created = store.createUserApiKey(user.id, input);
    assert.match(created.secret, /^nmb_key_/);
    assert.equal(created.key.name, "Home Assistant");
    const stored = store.database.prepare("SELECT * FROM user_api_keys WHERE id=?").get(created.key.id);
    assert.equal(JSON.stringify(stored).includes(created.secret), false);

    const session = store.getIntegrationApiSession(created.secret, { ipAddress: "10.0.0.50" });
    assert.equal(session.authType, "api_key");
    assert.deepEqual(session.apiKeyGroups.sort(), ["power_management", "server_overview"]);
    assert.deepEqual(session.apiKeyResourceIds.sort(), [web, db]);

    store.updateUserApiPolicy(user.id, {
      enabled: true,
      groups: ["server_overview"],
      resourceIds: [web],
      maxActiveKeys: 2,
      maxLifetimeDays: 365,
      allowNoExpiry: false,
    }, admin.id);
    const narrowed = store.getIntegrationApiSession(created.secret);
    assert.deepEqual(narrowed.apiKeyGroups, ["server_overview"]);
    assert.deepEqual(narrowed.apiKeyResourceIds, [web]);

    store.database.prepare("DELETE FROM resources WHERE id=?").run(web);
    assert.equal(store.getUserApiPolicy(user.id).allVisibleResources, false);
    assert.deepEqual(store.getIntegrationApiSession(created.secret).apiKeyResourceIds, []);

    assert.equal(store.revokeUserApiKey(user.id, created.key.id), true);
    assert.equal(store.getIntegrationApiSession(created.secret), null);
    assert.equal(store.revokeUserApiKey(user.id, created.key.id), false);
  });
});

test("API policy validation, expiry, key limits, and disablement fail closed", async () => {
  await temporaryStore(async (store) => {
    const customer = store.createCustomer({ id: "acme", name: "Acme" });
    const user = await store.createUser({
      email: "customer@example.com",
      displayName: "Customer",
      password: "customer password for API key tests",
      customerId: customer.id,
    });
    const admin = await store.createUser({
      email: "admin@example.com",
      displayName: "Admin",
      password: "administrator password for tests",
      role: "admin",
    });
    store.createCluster({
      id: "production",
      name: "Production",
      apiUrl: "https://pve.example.test:8006",
      tokenId: "nimbus@pve!panel",
      tokenSecret: "proxmox-secret-value",
    });
    store.syncResources("production", [{ type: "qemu", vmid: 101, node: "pve-a", name: "web", status: "running" }]);
    const resourceId = "production:qemu:101";
    store.assignResource({ customerId: customer.id, resourceId, permissions: ["view_status"] });

    assert.throws(
      () => store.previewUserApiKey(user.id, {
        name: "Disabled",
        groups: ["server_overview"],
        resourceIds: [resourceId],
        expiresAt: Date.now() + 86_400_000,
      }),
      (error) => error.code === "api_access_disabled",
    );
    store.updateUserApiPolicy(user.id, {
      enabled: true,
      groups: ["server_overview"],
      maxActiveKeys: 1,
      maxLifetimeDays: 30,
      allowNoExpiry: false,
      resourceIds: [],
    }, admin.id);
    assert.throws(
      () => store.createUserApiKey(user.id, { name: "No expiry", groups: ["server_overview"], resourceIds: [resourceId] }),
      (error) => error.code === "api_key_expiry_required",
    );
    const first = store.createUserApiKey(user.id, {
      name: "Monitoring",
      groups: ["server_overview"],
      resourceIds: [resourceId],
      expiresAt: Date.now() + 10 * 86_400_000,
    });
    assert.throws(
      () => store.createUserApiKey(user.id, {
        name: "Second",
        groups: ["server_overview"],
        resourceIds: [resourceId],
        expiresAt: Date.now() + 10 * 86_400_000,
      }),
      (error) => error.code === "api_key_limit_reached",
    );
    store.updateUserApiPolicy(user.id, {
      enabled: false,
      groups: ["server_overview"],
      maxActiveKeys: 1,
      maxLifetimeDays: 30,
      allowNoExpiry: false,
      resourceIds: [],
    }, admin.id);
    assert.equal(store.getIntegrationApiSession(first.secret), null);
    assert.equal(store.getUserApiKey(user.id, first.key.id).status, "revoked");
  });
});
