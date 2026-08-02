import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createNotificationService, notificationEmailTemplate } from "../server/notifications.mjs";
import { openStore } from "../server/store.mjs";

const APP_SECRET = "notification-test-secret-that-is-long-and-unique";

async function fixture(callback) {
  const directory = await mkdtemp(join(tmpdir(), "nimbus-direct-alerts-"));
  const store = await openStore(directory, { appSecret: APP_SECRET });
  try {
    const customer = store.createCustomer({ id: "acme", name: "Acme" });
    const user = await store.createUser({
      email: "ops@example.com",
      displayName: "Operations",
      password: "customer password for notification tests",
      customerId: customer.id,
    });
    const admin = await store.createUser({
      email: "admin@example.com",
      displayName: "Administrator",
      password: "administrator password for notification tests",
      role: "admin",
    });
    store.createCluster({
      id: "production", name: "Production", apiUrl: "https://pve.example.test:8006",
      tokenId: "nimbus@pve!panel", tokenSecret: "proxmox-secret-value",
    });
    store.syncResources("production", [{
      type: "qemu", vmid: 101, node: "pve-a", name: "web", status: "running",
      cpu: 95, memory: 8, memoryUsed: 7.6, storage: 100, storageUsed: 93,
    }]);
    const resourceId = "production:qemu:101";
    store.assignResource({
      customerId: customer.id,
      resourceId,
      permissions: ["view_status", "reboot"],
      alertPolicy: {
        enabled: true,
        offline: true,
        cpu: true,
        memory: true,
        storage: true,
        cpuThreshold: 90,
        memoryThreshold: 90,
        storageThreshold: 90,
        sustainMinutes: 1,
        cooldownMinutes: 5,
      },
    });
    await callback({ store, customer, user, admin, resourceId });
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
}

test("notification service delivers once per user preference and queues the branded email", async () => {
  await fixture(async ({ store, customer, user, admin, resourceId }) => {
    store.saveEmailSettings({
      enabled: true,
      host: "smtp.example.com",
      port: 587,
      security: "starttls",
      username: "",
      fromName: "Nimbus Direct",
      fromEmail: "nimbus@example.com",
    }, { userId: admin.id });
    store.updateNotificationPreferences(user.id, { emailEnabled: true });
    let processCalls = 0;
    const pushed = [];
    const service = createNotificationService({
      store,
      email: { async processDue() { processCalls += 1; } },
      push: {
        configured: true,
        async sendUser(userId, notification) {
          pushed.push({ userId, notification });
        },
      },
    });
    const result = await service.emitEvent({
      customerId: customer.id,
      resourceId,
      category: "action_success",
      type: "action.reboot",
      severity: "info",
      title: "Reboot completed",
      message: "Reboot completed successfully on web.",
      dedupKey: "task:reboot-1:completed",
    });
    assert.equal(result.created, true);
    assert.equal(result.deliveries, 1);
    assert.equal(store.listNotifications(user.id).unread, 1);
    assert.equal(store.listEmailJobs().total, 1);
    assert.equal(store.listEmailJobs().items[0].category, "notification");
    assert.equal(processCalls, 1);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(pushed.length, 1);
    assert.equal(pushed[0].userId, user.id);
    assert.equal(pushed[0].notification.resourceId, resourceId);
    assert.equal((await service.emitEvent({
      customerId: customer.id,
      resourceId,
      category: "action_success",
      type: "action.reboot",
      severity: "info",
      title: "Reboot completed",
      message: "Duplicate",
      dedupKey: "task:reboot-1:completed",
    })).created, false);
    assert.equal(store.listNotifications(user.id).total, 1);

    const content = notificationEmailTemplate(result.event, store.getResource(resourceId));
    assert.match(content.html, /nimbus <span[^>]*>direct/);
    assert.match(content.text, /QEMU 101/);
  });
});

test("sustained alerts fire once, recover once, and baseline an already stopped guest", async () => {
  await fixture(async ({ store, user, resourceId }) => {
    let timestamp = 1_800_000_000_000;
    const service = createNotificationService({
      store,
      email: { async processDue() {} },
      now: () => timestamp,
    });

    let summary = await service.evaluateResourceAlerts({ clusterId: "production" });
    assert.equal(summary.fired, 0);
    assert.equal(store.listNotifications(user.id).total, 0);
    timestamp += 60_000;
    summary = await service.evaluateResourceAlerts({ clusterId: "production" });
    assert.equal(summary.fired, 3);
    assert.equal(store.listNotifications(user.id).total, 3);
    timestamp += 60_000;
    summary = await service.evaluateResourceAlerts({ clusterId: "production" });
    assert.equal(summary.fired, 0);
    assert.equal(store.listNotifications(user.id).total, 3);

    store.syncResources("production", [{
      type: "qemu", vmid: 101, node: "pve-a", name: "web", status: "running",
      cpu: 20, memory: 8, memoryUsed: 3, storage: 100, storageUsed: 50,
    }]);
    timestamp += 60_000;
    summary = await service.evaluateResourceAlerts({ clusterId: "production" });
    assert.equal(summary.resolved, 3);
    assert.equal(store.listNotifications(user.id).total, 6);

    const expectedStop = store.createTask({
      customerId: "acme",
      userId: user.id,
      clusterId: "production",
      node: "pve-a",
      upid: "UPID:pve-a:expected-stop",
      resourceId,
      action: "shutdown",
    });
    store.database.prepare("UPDATE api_tasks SET created_at=? WHERE id=?").run(timestamp, expectedStop.id);
    store.syncResources("production", [{
      type: "qemu", vmid: 101, node: "pve-a", name: "web", status: "stopped",
      cpu: 0, memory: 8, memoryUsed: 0, storage: 100, storageUsed: 50,
    }]);
    timestamp += 60_000;
    summary = await service.evaluateResourceAlerts({ clusterId: "production" });
    assert.equal(summary.fired, 0);
    timestamp += 5 * 60_000;
    summary = await service.evaluateResourceAlerts({ clusterId: "production" });
    assert.equal(summary.fired, 0);
    assert.equal(store.listNotifications(user.id).total, 6);

    store.resetAlertStates(store.getResource(resourceId).assignmentId);
    timestamp += 60_000;
    summary = await service.evaluateResourceAlerts({ clusterId: "production" });
    assert.equal(summary.fired, 0);
    timestamp += 5 * 60_000;
    summary = await service.evaluateResourceAlerts({ clusterId: "production" });
    assert.equal(summary.fired, 0);
  });
});

test("an unavailable QEMU storage reading never creates a false recovery", async () => {
  await fixture(async ({ store, user }) => {
    let timestamp = 1_900_000_000_000;
    const service = createNotificationService({
      store,
      email: { async processDue() {} },
      now: () => timestamp,
    });
    await service.evaluateResourceAlerts({ clusterId: "production" });
    timestamp += 60_000;
    assert.equal((await service.evaluateResourceAlerts({ clusterId: "production" })).fired, 3);

    store.syncResources("production", [{
      type: "qemu", vmid: 101, node: "pve-a", name: "web", status: "running",
      cpu: 20, memory: 8, memoryUsed: 3, storage: 100, storageUsed: null,
      metadata: { storageUsage: { available: false, reason: "guest_agent_unavailable", checkedAt: timestamp } },
    }]);
    timestamp += 60_000;
    const summary = await service.evaluateResourceAlerts({ clusterId: "production" });
    assert.equal(summary.resolved, 2);
    assert.equal(store.listNotifications(user.id).total, 5);
    assert.equal(store.listNotifications(user.id).items.some((item) => item.type === "alert.storage.resolved"), false);
  });
});
