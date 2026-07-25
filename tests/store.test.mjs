import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { bootstrapStore, openStore } from "../server/store.mjs";

const APP_SECRET = "store-test-secret-that-is-long-and-unique";

async function temporaryDirectory(prefix, callback) {
  const directory = await mkdtemp(join(tmpdir(), prefix));
  try { return await callback(directory); }
  finally { await rm(directory, { recursive: true, force: true }); }
}

test("direct assignments authorize by customer, resource, and permission", async () => {
  await temporaryDirectory("nimbus-direct-store-", async (directory) => {
    const store = await openStore(directory, { appSecret: APP_SECRET });
    try {
      const acme = store.createCustomer({ id: "acme", name: "Acme", planName: "Gold" });
      const beta = store.createCustomer({ id: "beta", name: "Beta" });
      const admin = await store.createUser({ email: "admin@example.com", displayName: "Admin", password: "admin password for tests", role: "admin" });
      const acmeUser = await store.createUser({ email: "acme@example.com", displayName: "Acme Ops", password: "customer password test", customerId: acme.id });
      const betaUser = await store.createUser({ email: "beta@example.com", displayName: "Beta Ops", password: "customer password test", customerId: beta.id });

      store.createCluster({
        id: "production", name: "Production", apiUrl: "https://pve.example.test:8006",
        tokenId: "nimbus@pve!panel", tokenSecret: "proxmox-secret-value",
      });
      const rawCredential = store.database.prepare("SELECT * FROM proxmox_credentials WHERE cluster_id='production'").get();
      assert.equal(rawCredential.token_secret_encrypted.includes("proxmox-secret-value"), false);
      assert.equal(store.getClusterConnection("production").tokenSecret, "proxmox-secret-value");
      assert.throws(() => store.updateCluster("production", { apiUrl: "http://pve.example.test:8006" }), /must use HTTPS/);

      store.syncResources("production", [
        { type: "qemu", vmid: 101, node: "pve-a", name: "web", status: "running", vcpu: 4, memory: 8, memoryUsed: 2, cpu: 25 },
        { type: "lxc", vmid: 301, node: "pve-b", name: "cache", status: "running", vcpu: 2, memory: 4, memoryUsed: 1, cpu: 10 },
      ]);
      const webId = "production:qemu:101";
      store.assignResource({ customerId: acme.id, resourceId: webId, permissions: ["view_status", "start", "console"] });

      assert.equal(store.authorizeResource(acme.id, webId, "start").vmid, 101);
      assert.equal(store.authorizeResource(acme.id, webId, "reset"), null);
      assert.equal(store.authorizeResource(beta.id, webId, "start"), null);
      assert.deepEqual(store.listResources({ customerId: beta.id }), []);

      // A partial/failed inventory refresh marks a missing guest stale but never
      // removes or transfers the local customer assignment.
      store.syncResources("production", [
        { type: "lxc", vmid: 301, node: "pve-b", name: "cache", status: "running" },
      ]);
      assert.equal(store.getResource(webId).stale, true);
      assert.equal(store.authorizeResource(acme.id, webId, "start").customerId, "acme");

      // Reassignment is a local database operation; Proxmox pools are absent.
      store.assignResource({ customerId: beta.id, resourceId: webId, permissions: ["view_status", "reboot"] });
      assert.equal(store.authorizeResource(acme.id, webId, "view_status"), null);
      assert.equal(store.authorizeResource(beta.id, webId, "reboot").customerId, "beta");

      const session = store.createSession({ userId: betaUser.id, ttlMs: 60_000 });
      assert.equal(store.getSession(session.token).user.customerId, "beta");
      assert.equal(store.getSession("not-a-session"), null);

      store.writeAudit({ customerId: "beta", userId: betaUser.id, actorRole: "customer", action: "resource.reboot.requested", resourceId: webId });
      assert.equal(store.listAudit("beta").total, 1);
      assert.equal(store.listAudit("acme").total, 0);

      const task = store.createTask({ customerId: "beta", userId: betaUser.id, clusterId: "production", node: "pve-a", upid: "UPID:pve-a:1", resourceId: webId, action: "reboot", idempotencyKey: "one" });
      assert.equal("upid" in task, false);
      assert.equal(task.resourceId, webId);
      assert.equal(task.completed, false);
      assert.equal(store.getTask(task.id, betaUser).customer_id, "beta");
      assert.equal(store.getTask(task.id, acmeUser), undefined);
      assert.equal(store.listTasks(betaUser, { resourceId: webId })[0].id, task.id);
      assert.deepEqual(store.listTasks(acmeUser, { resourceId: webId }), []);
      assert.equal(store.getActiveTask(webId).id, task.id);
      assert.equal(store.getTaskByIdempotency(betaUser.id, "one").id, task.id);
      assert.equal(store.updateTask(task.id, { status: "stopped", exitStatus: "OK", completedAt: 1700000000000 }).exit_status, "OK");
      assert.equal(store.getActiveTask(webId), undefined);
      assert.deepEqual(store.publicTask(store.getTask(task.id, betaUser)), {
        id: task.id,
        resourceId: webId,
        node: "pve-a",
        action: "reboot",
        status: "stopped",
        state: "success",
        completed: true,
        success: true,
        message: "Completed successfully.",
        createdAt: task.createdAt,
        completedAt: 1700000000000,
        lastCheckedAt: store.getTask(task.id, betaUser).last_checked_at,
      });

      const consoleSession = store.createConsoleSession({ userId: betaUser.id, resourceId: webId, ticket: "PVEVNC:short-lived-ticket", port: 5900 });
      assert.equal(store.getConsoleSession(consoleSession.token, acmeUser.id), null);
      assert.equal(store.getConsoleSession(consoleSession.token, betaUser.id).resourceId, webId);
      assert.equal(store.getConsoleSession(consoleSession.token, betaUser.id).password, "PVEVNC:short-lived-ticket");
      assert.equal(store.consumeConsoleSession(consoleSession.token, betaUser.id).ticket, "PVEVNC:short-lived-ticket");
      assert.equal(store.consumeConsoleSession(consoleSession.token, betaUser.id), null);

      assert.throws(() => store.updateUser(admin.id, { status: "disabled" }), (error) => error.code === "last_admin");
    } finally { store.close(); }
  });
});

test("bootstrap creates an independent administrator and optional first customer", async () => {
  await temporaryDirectory("nimbus-direct-bootstrap-", async (directory) => {
    const store = await openStore(directory, { appSecret: APP_SECRET });
    try {
      const bootstrap = {
        email: "operator@example.com", password: "operator bootstrap password", displayName: "Operator",
        customerId: "acme", customerName: "Acme Studio", customerEmail: "customer@example.com",
        customerPassword: "customer bootstrap password", customerDisplayName: "Acme Ops", planName: "Gold",
      };
      assert.equal(await bootstrapStore(store, bootstrap), true);
      assert.equal(await bootstrapStore(store, bootstrap), false);
      assert.equal(store.listUsers().length, 2);
      assert.equal(store.listUsers().find((user) => user.role === "admin").customerId, null);
      assert.equal(store.listUsers().find((user) => user.role === "customer").customerId, "acme");
      assert.equal(store.getCustomer("acme").planName, "Gold");
    } finally { store.close(); }
  });
});

test("ISO policies enforce customer ownership, quota accounting, and active mounts", async () => {
  await temporaryDirectory("nimbus-direct-iso-store-", async (directory) => {
    const store = await openStore(directory, { appSecret: APP_SECRET });
    try {
      const acme = store.createCustomer({ id: "acme", name: "Acme" });
      const beta = store.createCustomer({ id: "beta", name: "Beta" });
      const acmeUser = await store.createUser({ email: "iso-acme@example.com", displayName: "Acme Ops", password: "customer password test", customerId: acme.id });
      const betaUser = await store.createUser({ email: "iso-beta@example.com", displayName: "Beta Ops", password: "customer password test", customerId: beta.id });
      store.createCluster({
        id: "production",
        name: "Production",
        apiUrl: "https://pve.example.test:8006",
        tokenId: "nimbus@pve!panel",
        tokenSecret: "proxmox-secret-value",
      });
      store.syncResources("production", [
        { type: "qemu", vmid: 101, node: "pve-a", name: "web", status: "running" },
      ]);
      const resourceId = "production:qemu:101";
      store.assignResource({
        customerId: acme.id,
        resourceId,
        permissions: ["view_status", "iso_view", "iso_upload", "iso_mount", "iso_delete"],
      });
      assert.equal(store.authorizeResource(acme.id, resourceId, "iso_upload").vmid, 101);

      const policy = store.createIsoPolicy({
        clusterId: "production",
        storageId: "local",
        displayName: "Local ISO library",
        maxUploadBytes: 2 * 1024 ** 3,
        customerQuotaBytes: 5 * 1024 ** 3,
        allowDelete: true,
      });
      assert.equal(policy.allowDelete, true);
      assert.equal(store.listIsoPolicies({ clusterId: "production", activeOnly: true }).length, 1);

      const image = store.createIsoImage({
        customerId: acme.id,
        clusterId: "production",
        storagePolicyId: policy.id,
        storageId: "local",
        node: "pve-a",
        volumeId: "local:iso/debian-test.iso",
        fileName: "debian-test.iso",
        originalName: "Debian 13.iso",
        sizeBytes: 1024 ** 3,
        createdBy: acmeUser.id,
      });
      assert.equal(store.getIsoUsage(acme.id, policy.id), 1024 ** 3);
      assert.equal(store.getIsoImage(image.id, acmeUser).originalName, "Debian 13.iso");
      assert.equal(store.getIsoImage(image.id, betaUser), undefined);
      assert.deepEqual(store.listIsoImages(betaUser), []);

      const ready = store.updateIsoImage(image.id, { status: "ready", sha256: "abc123" });
      assert.equal(ready.sha256, "abc123");
      const mount = store.createIsoMount({ isoImageId: image.id, resourceId, driveSlot: "ide2", createdBy: acmeUser.id });
      assert.equal(mount.status, "active");
      assert.equal(store.hasActiveIsoMount(image.id), true);
      assert.throws(
        () => store.assignResource({ customerId: beta.id, resourceId, permissions: ["view_status"] }),
        (error) => error.code === "resource_iso_mounted",
      );
      assert.throws(() => store.deleteCustomer(acme.id), (error) => error.code === "customer_iso_images_exist");
      assert.throws(() => store.deleteIsoPolicy(policy.id), (error) => error.code === "iso_policy_in_use");

      assert.equal(store.ejectIsoMount(mount.id).status, "ejected");
      assert.equal(store.hasActiveIsoMount(image.id), false);
      store.updateIsoImage(image.id, { status: "deleted" });
      assert.equal(store.getIsoUsage(acme.id, policy.id), 0);
      store.deleteIsoPolicy(policy.id);
      assert.equal(store.getIsoPolicy(policy.id), undefined);
    } finally { store.close(); }
  });
});
