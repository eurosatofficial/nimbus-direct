import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
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
      store.assignResource({ customerId: acme.id, resourceId: webId, permissions: ["view_status", "start", "console"], snapshotLimit: 5 });

      assert.equal(store.authorizeResource(acme.id, webId, "start").vmid, 101);
      assert.equal(store.authorizeResource(acme.id, webId, "start").snapshotLimit, 5);
      assert.equal(store.authorizeResource(acme.id, webId, "reset"), null);
      assert.equal(store.authorizeResource(beta.id, webId, "start"), null);
      assert.deepEqual(store.listResources({ customerId: beta.id }), []);

      // A failed synchronization records the error but cannot hide the last
      // successfully discovered resources or alter their assignments.
      store.setClusterSync("production", { error: "proxmox_timeout" });
      assert.equal(store.listResources().some((resource) => resource.id === webId), true);
      assert.equal(store.authorizeResource(acme.id, webId, "start").customerId, "acme");

      // A successful inventory refresh hides a missing guest from every active
      // inventory and action lookup while preserving its local assignment.
      store.syncResources("production", [
        { type: "lxc", vmid: 301, node: "pve-b", name: "cache", status: "running" },
      ]);
      assert.equal(store.getResource(webId).stale, true);
      assert.equal(store.listResources().some((resource) => resource.id === webId), false);
      assert.equal(store.listResources({ clusterId: "production" }).some((resource) => resource.id === webId), false);
      assert.equal(store.listResources({ customerId: acme.id }).some((resource) => resource.id === webId), false);
      assert.equal(store.authorizeResource(acme.id, webId, "start"), null);
      assert.equal(store.listResources({ includeStale: true }).find((resource) => resource.id === webId).customerId, "acme");
      assert.equal(store.listCustomers().find((customer) => customer.id === acme.id).resourceCount, 0);
      assert.equal(store.listClusters().find((cluster) => cluster.id === "production").resourceCount, 1);

      // Reassignment is a local database operation; Proxmox pools are absent.
      assert.throws(
        () => store.assignResource({ customerId: beta.id, resourceId: webId, permissions: ["view_status", "reboot"], snapshotLimit: 2 }),
        (error) => error.code === "resource_not_found",
      );
      store.syncResources("production", [
        { type: "qemu", vmid: 101, node: "pve-a", name: "web", status: "running" },
        { type: "lxc", vmid: 301, node: "pve-b", name: "cache", status: "running" },
      ]);
      assert.equal(store.authorizeResource(acme.id, webId, "start").customerId, "acme");
      store.assignResource({ customerId: beta.id, resourceId: webId, permissions: ["view_status", "reboot"], snapshotLimit: 2 });
      assert.equal(store.authorizeResource(acme.id, webId, "view_status"), null);
      assert.equal(store.authorizeResource(beta.id, webId, "reboot").customerId, "beta");
      assert.equal(store.authorizeResource(beta.id, webId, "view_status").snapshotLimit, 2);
      assert.throws(() => store.updateAssignment(webId, { snapshotLimit: 0 }), (error) => error.code === "invalid_snapshot_limit");

      const session = store.createSession({ userId: betaUser.id, ttlMs: 60_000 });
      assert.equal(store.getSession(session.token).user.customerId, "beta");
      assert.equal(store.getSession("not-a-session"), null);
      const cappedSession = store.createSession({ userId: betaUser.id, ttlMs: 60_000, maxSessions: 2 });
      store.createSession({ userId: betaUser.id, ttlMs: 60_000, maxSessions: 2 });
      assert.equal(store.listSessions(betaUser.id).length, 2);
      assert.equal(store.getSession(session.token), null);
      assert.equal(store.getSession(cappedSession.token).user.customerId, "beta");

      const pushToken = "ab".repeat(32);
      assert.equal(store.registerPushDevice(betaUser.id, {
        token: pushToken,
        environment: "sandbox",
        appVersion: "0.2.0",
      }).registered, true);
      assert.equal(store.listPushDevices(betaUser.id)[0].token, pushToken);
      assert.equal(store.listPushDevices(betaUser.id)[0].environment, "sandbox");
      const pushRow = store.database.prepare("SELECT * FROM mobile_push_devices").get();
      assert.equal(pushRow.token_encrypted.includes(pushToken), false);
      assert.equal(pushRow.token_hash.includes(pushToken), false);
      store.disablePushDevice(pushRow.id, "Unregistered");
      assert.equal(store.listPushDevices(betaUser.id).length, 0);
      store.registerPushDevice(betaUser.id, {
        token: pushToken,
        environment: "production",
        appVersion: "0.2.0",
      });
      assert.equal(store.listPushDevices(betaUser.id)[0].environment, "production");
      assert.equal(store.unregisterPushDevice(acmeUser.id, pushToken), false);
      assert.equal(store.unregisterPushDevice(betaUser.id, pushToken), true);
      assert.equal(store.listPushDevices(betaUser.id).length, 0);

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
      const snapshotTask = store.createTask({
        customerId: "beta",
        userId: betaUser.id,
        clusterId: "production",
        node: "pve-a",
        upid: "UPID:pve-a:snapshot",
        resourceId: webId,
        action: "snapshot_create",
      });
      assert.equal(snapshotTask.message, "Proxmox is creating the snapshot.");
      const completedSnapshotTask = store.updateTask(snapshotTask.id, { status: "stopped", exitStatus: "OK", completedAt: 1700000001000 });
      assert.equal(store.publicTask(completedSnapshotTask).message, "Snapshot created successfully.");

      const consoleSession = store.createConsoleSession({
        userId: betaUser.id,
        resourceId: webId,
        ticket: "PVEVNC:short-lived-ticket",
        port: 5900,
        consoleType: "terminal",
        consoleUser: "nimbus@pve",
      });
      assert.equal(store.getConsoleSession(consoleSession.token, acmeUser.id), null);
      assert.equal(store.getConsoleSession(consoleSession.token, betaUser.id).resourceId, webId);
      assert.equal(store.getConsoleSessionByToken(consoleSession.token).userId, betaUser.id);
      assert.equal(store.getConsoleSessionByToken(consoleSession.token).resourceId, webId);
      assert.equal(store.getConsoleSession(consoleSession.token, betaUser.id).password, "PVEVNC:short-lived-ticket");
      assert.equal(store.getConsoleSession(consoleSession.token, betaUser.id).consoleType, "terminal");
      assert.equal(store.getConsoleSession(consoleSession.token, betaUser.id).consoleUser, "nimbus@pve");
      assert.equal(store.consumeConsoleSession(consoleSession.token, betaUser.id).ticket, "PVEVNC:short-lived-ticket");
      assert.equal(store.consumeConsoleSession(consoleSession.token, betaUser.id), null);
      assert.equal(store.getConsoleSessionByToken(consoleSession.token), null);

      assert.throws(() => store.updateUser(admin.id, { status: "disabled" }), (error) => error.code === "last_admin");
    } finally { store.close(); }
  });
});

test("resource synchronization preserves last-known QEMU filesystem usage", async () => {
  await temporaryDirectory("nimbus-direct-storage-usage-", async (directory) => {
    const store = await openStore(directory, { appSecret: APP_SECRET });
    try {
      store.createCluster({
        id: "production", name: "Production", apiUrl: "https://pve.example.test:8006",
        tokenId: "nimbus@pve!panel", tokenSecret: "proxmox-secret-value",
      });
      const base = {
        type: "qemu", node: "pve-a", name: "web", status: "running",
        vcpu: 4, memory: 8, memoryUsed: 2, storage: 64, cpu: 10,
      };
      store.syncResources("production", [{
        ...base,
        vmid: 101,
        storageUsed: 31.5,
        metadata: { storageUsage: { available: true, source: "qemu_guest_agent", collectedAt: 1_700_000_000_000 } },
      }]);
      assert.equal(store.getResource("production:qemu:101").storageUsed, 31.5);
      assert.equal(store.getResource("production:qemu:101").storageUsageAvailable, true);

      store.syncResources("production", [{
        ...base,
        vmid: 101,
        storageUsed: null,
        metadata: { storageUsage: { available: false, source: null, checkedAt: 1_700_000_060_000, reason: "guest_agent_unavailable" } },
      }, {
        ...base,
        vmid: 102,
        storageUsed: null,
        metadata: { storageUsage: { available: false, source: null, checkedAt: 1_700_000_060_000, reason: "guest_agent_unavailable" } },
      }]);

      const preserved = store.getResource("production:qemu:101");
      assert.equal(preserved.storageUsed, 31.5);
      assert.equal(preserved.storageUsageAvailable, true);
      assert.equal(preserved.storageUsageStale, true);
      assert.equal(preserved.storageUsageSource, "qemu_guest_agent");
      const unavailable = store.getResource("production:qemu:102");
      assert.equal(unavailable.storageUsed, 0);
      assert.equal(unavailable.storageUsageAvailable, false);
    } finally {
      store.close();
    }
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

test("maintenance publishing freezes assignment-derived recipients and preserves customer isolation", async () => {
  await temporaryDirectory("nimbus-direct-maintenance-store-", async (directory) => {
    const store = await openStore(directory, { appSecret: APP_SECRET });
    try {
      const acme = store.createCustomer({ id: "acme", name: "Acme" });
      const beta = store.createCustomer({ id: "beta", name: "Beta" });
      const admin = await store.createUser({ email: "maintenance-admin@example.com", displayName: "Admin", password: "admin password for tests", role: "admin" });
      const acmeOne = await store.createUser({ email: "maintenance-acme-one@example.com", displayName: "Acme One", password: "customer password test", customerId: acme.id, preferredLanguage: "de" });
      const acmeTwo = await store.createUser({ email: "maintenance-acme-two@example.com", displayName: "Acme Two", password: "customer password test", customerId: acme.id });
      const betaUser = await store.createUser({ email: "maintenance-beta@example.com", displayName: "Beta", password: "customer password test", customerId: beta.id });
      // Simulate an account upgraded while the new locale column still held
      // its default. The explicit historic German choice must win.
      store.database.prepare("UPDATE users SET preferred_locale='en' WHERE id=?").run(acmeOne.id);
      assert.equal(store.getUser(acmeOne.id).preferredLanguage, "de");
      store.updateNotificationPreferences(acmeOne.id, { emailEnabled: true, infrastructureAlerts: true, resolutionAlerts: true });
      store.createCluster({
        id: "production", name: "Production", apiUrl: "https://pve.example.test:8006",
        tokenId: "nimbus@pve!panel", tokenSecret: "proxmox-secret-value",
      });
      store.syncResources("production", [
        { type: "qemu", vmid: 101, node: "pve-a", name: "acme-web", status: "running" },
        { type: "qemu", vmid: 203, node: "pve-b", name: "beta-api", status: "running" },
      ]);
      const acmeResource = "production:qemu:101";
      const betaResource = "production:qemu:203";
      store.assignResource({ customerId: acme.id, resourceId: acmeResource, permissions: ["view_status", "reboot", "console"] });
      store.assignResource({ customerId: beta.id, resourceId: betaResource, permissions: ["view_status"] });

      const now = Date.now();
      const draft = store.createMaintenanceEvent({
        kind: "maintenance",
        severity: "warning",
        title: "Hypervisor maintenance",
        message: "The assigned VM may reboot once.",
        startsAt: now + 60_000,
        endsAt: now + 120_000,
        timeZone: "Europe/Berlin",
        notifyEmail: true,
        lockGroups: ["power_management"],
        targets: [{ type: "resource", id: acmeResource }],
      }, { userId: admin.id });
      assert.equal(draft.status, "draft");
      assert.equal(draft.targets[0].id, acmeResource);
      assert.deepEqual(draft.lockGroups.map((group) => group.id), ["power_management"]);
      const published = store.publishMaintenanceEvent(draft.id, { userId: admin.id });
      assert.equal(published.event.status, "scheduled");
      assert.equal(published.event.timeZone, "Europe/Berlin");
      assert.equal(published.event.recipientCount, 2);
      assert.equal(published.deliveries.filter((delivery) => delivery.emailEnabled).length, 1);
      assert.equal(published.deliveries.find((delivery) => delivery.id === acmeOne.id).preferredLanguage, "de");
      assert.equal(store.listMaintenanceForUser(acmeOne.id).total, 1);
      assert.equal(store.listMaintenanceForUser(acmeTwo.id).total, 1);
      assert.equal(store.listMaintenanceForUser(betaUser.id).total, 0);
      assert.equal(store.getMaintenanceActionLock(acmeOne.id, store.authorizeResource(acme.id, acmeResource, "view_status"), "reboot", now), null);

      store.advanceMaintenanceEvents(now + 61_000);
      const acmeLock = store.getMaintenanceActionLock(
        acmeOne.id,
        store.authorizeResource(acme.id, acmeResource, "view_status"),
        "reboot",
        now + 61_000,
      );
      assert.equal(acmeLock.group.id, "power_management");
      assert.equal(acmeLock.eventId, draft.id);
      assert.equal(store.getMaintenanceActionLock(
        acmeOne.id,
        store.authorizeResource(acme.id, acmeResource, "view_status"),
        "console",
        now + 61_000,
      ), null);
      assert.deepEqual(
        store.listActiveMaintenanceLocksForUser(
          acmeOne.id,
          [store.authorizeResource(acme.id, acmeResource, "view_status")],
          now + 61_000,
        ).items[0].resourceIds,
        [acmeResource],
      );

      const deliveryId = store.listMaintenanceForUser(acmeOne.id).items[0].deliveryId;
      assert.throws(() => store.markMaintenanceRead(deliveryId, betaUser.id), (error) => error.code === "maintenance_not_found");
      store.markMaintenanceRead(deliveryId, acmeOne.id);
      assert.equal(store.listMaintenanceForUser(acmeOne.id).unread, 0);

      // Reassigning the VM after publication cannot expose the old notice to Beta.
      store.assignResource({ customerId: beta.id, resourceId: acmeResource, permissions: ["view_status"] });
      assert.equal(store.listMaintenanceForUser(betaUser.id).total, 0);
      assert.equal(store.getMaintenanceActionLock(
        betaUser.id,
        store.authorizeResource(beta.id, acmeResource, "view_status"),
        "reboot",
        now + 61_000,
      ), null);

      assert.equal(store.getMaintenanceEvent(draft.id).status, "active");
      store.advanceMaintenanceEvents(now + 121_000);
      assert.equal(store.getMaintenanceEvent(draft.id).status, "resolved");

      const editable = store.createMaintenanceEvent({
        kind: "incident",
        severity: "critical",
        title: "Connectivity incident",
        message: "Investigation is in progress.",
        startsAt: now,
        endsAt: null,
        notifyEmail: false,
        targets: [{ type: "customer", id: beta.id }],
      }, { userId: admin.id });
      const changed = store.updateMaintenanceEvent(editable.id, {
        title: "Network connectivity incident",
        targets: [{ type: "resource", id: betaResource }],
      }, { userId: admin.id });
      assert.equal(changed.title, "Network connectivity incident");
      assert.equal(changed.targets[0].type, "resource");
      const active = store.publishMaintenanceEvent(editable.id, { userId: admin.id });
      assert.equal(active.event.status, "active");
      assert.equal(active.event.recipientCount, 1);
      const resolved = store.resolveMaintenanceEvent(editable.id, { userId: admin.id });
      assert.equal(resolved.event.status, "resolved");
      assert.equal(resolved.deliveries[0].resolutionAlerts, true);
      assert.throws(() => store.createMaintenanceEvent({
        kind: "maintenance",
        severity: "info",
        title: "Invalid action lock",
        message: "This notice must be rejected.",
        startsAt: now + 300_000,
        lockGroups: ["unrestricted_proxmox"],
        targets: [{ type: "all", id: "*" }],
      }), (error) => error.code === "invalid_maintenance_locks");
    } finally { store.close(); }
  });
});

test("support tickets remain customer-scoped while administrators can assign, note, and reply", async () => {
  await temporaryDirectory("nimbus-direct-support-store-", async (directory) => {
    const store = await openStore(directory, { appSecret: APP_SECRET });
    try {
      const acme = store.createCustomer({ id: "acme", name: "Acme" });
      const beta = store.createCustomer({ id: "beta", name: "Beta" });
      const admin = await store.createUser({
        email: "support-admin@example.com",
        displayName: "Support Admin",
        password: "support admin password",
        role: "admin",
      });
      const secondAdmin = await store.createUser({
        email: "support-two@example.com",
        displayName: "Second Admin",
        password: "second support password",
        role: "admin",
      });
      const acmeOne = await store.createUser({
        email: "support-acme-one@example.com",
        displayName: "Acme One",
        password: "customer support password",
        customerId: acme.id,
      });
      const acmeTwo = await store.createUser({
        email: "support-acme-two@example.com",
        displayName: "Acme Two",
        password: "customer support password",
        customerId: acme.id,
      });
      const betaUser = await store.createUser({
        email: "support-beta@example.com",
        displayName: "Beta User",
        password: "customer support password",
        customerId: beta.id,
      });
      store.createCluster({
        id: "production",
        name: "Production",
        apiUrl: "https://pve.example.test:8006",
        tokenId: "nimbus@pve!panel",
        tokenSecret: "proxmox-secret-value",
      });
      store.syncResources("production", [
        { type: "qemu", vmid: 101, node: "pve-a", name: "acme-web", status: "running" },
        { type: "qemu", vmid: 203, node: "pve-b", name: "beta-api", status: "running" },
      ]);
      const acmeResource = "production:qemu:101";
      const betaResource = "production:qemu:203";
      store.assignResource({ customerId: acme.id, resourceId: acmeResource, permissions: ["view_status"] });
      store.assignResource({ customerId: beta.id, resourceId: betaResource, permissions: ["view_status"] });

      const created = store.createSupportTicket({
        subject: "Network route unavailable",
        category: "network",
        priority: "high",
        resourceId: acmeResource,
        message: "The assigned VM cannot reach its gateway.",
      }, { customerId: acme.id, userId: acmeOne.id });
      assert.match(created.ticket.reference, /^ND-\d{8}-[A-Z0-9]{6}$/);
      assert.equal(created.ticket.status, "waiting_support");
      assert.equal(created.ticket.unread, false);
      assert.equal(created.messages.length, 1);
      assert.equal(store.listSupportTickets(acmeOne).total, 1);
      assert.equal(store.listSupportTickets(acmeTwo).unread, 1);
      assert.equal(store.listSupportTickets(betaUser).total, 0);
      assert.equal(store.listSupportTickets(admin).waitingSupport, 1);
      assert.throws(() => store.getSupportTicket(created.ticket.id, betaUser), (error) => error.code === "support_ticket_not_found");
      assert.throws(() => store.createSupportTicket({
        subject: "Wrong resource",
        category: "technical",
        priority: "normal",
        resourceId: betaResource,
        message: "This resource belongs to another customer.",
      }, { customerId: acme.id, userId: acmeOne.id }), (error) => error.code === "invalid_ticket_resource");

      store.markSupportTicketRead(created.ticket.id, acmeTwo);
      assert.equal(store.listSupportTickets(acmeTwo).unread, 0);
      const internal = store.addSupportTicketMessage(
        created.ticket.id,
        { message: "Check the host bridge before replying." },
        admin,
        { internal: true },
      );
      assert.equal(internal.ticket.internalNoteCount, 1);
      assert.equal(store.listSupportTickets(acmeOne).unread, 0);
      assert.equal(store.listSupportTickets(acmeOne).items[0].messageCount, 1);
      assert.equal(store.listSupportTickets(admin).items[0].messageCount, 2);
      assert.equal(store.getSupportTicket(created.ticket.id, acmeOne).messages.length, 1);
      assert.equal(store.getSupportTicket(created.ticket.id, acmeOne).ticket.internalNoteCount, 0);
      store.writeAudit({
        customerId: acme.id,
        userId: admin.id,
        actorRole: "admin",
        action: "admin.support.internal_note_added",
        resourceId: acmeResource,
        detail: { ticketId: created.ticket.id },
      });
      assert.equal(store.listAudit(acme.id).items.some((entry) => entry.action === "admin.support.internal_note_added"), true);
      assert.equal(store.listAudit(acme.id, { customerVisible: true }).items.some((entry) => entry.action === "admin.support.internal_note_added"), false);
      assert.throws(
        () => store.addSupportTicketMessage(created.ticket.id, { message: "Hidden" }, acmeOne, { internal: true }),
        (error) => error.code === "admin_required",
      );

      const publicReply = store.addSupportTicketMessage(
        created.ticket.id,
        { message: "We found the bridge issue and are applying the fix." },
        admin,
      );
      assert.equal(publicReply.ticket.status, "waiting_customer");
      assert.equal(store.getSupportTicket(created.ticket.id, acmeOne).messages.length, 2);
      assert.equal(store.addSupportTicketMessage(
        created.ticket.id,
        { message: "Connectivity is restored now." },
        acmeOne,
      ).ticket.status, "waiting_support");

      const managed = store.updateSupportTicket(created.ticket.id, {
        status: "resolved",
        priority: "normal",
        assignedTo: secondAdmin.id,
      }, admin);
      assert.equal(managed.status, "resolved");
      assert.equal(managed.assignedTo, secondAdmin.id);
      assert.deepEqual(store.listSupportTicketRecipients(created.ticket.id, "admin").map((recipient) => recipient.id), [secondAdmin.id]);
      assert.deepEqual(
        store.listSupportTicketRecipients(created.ticket.id, "customer").map((recipient) => recipient.id).sort(),
        [acmeOne.id, acmeTwo.id].sort(),
      );
      assert.throws(
        () => store.addSupportTicketMessage(created.ticket.id, { message: "Reply while resolved." }, acmeOne),
        (error) => error.code === "support_ticket_not_replyable",
      );
      assert.equal(store.reopenSupportTicket(created.ticket.id, acmeOne).status, "waiting_support");
      assert.equal(store.closeSupportTicket(created.ticket.id, acmeOne).status, "closed");
    } finally {
      store.close();
    }
  });
});

test("existing databases receive the snapshot limit column without losing assignments", async () => {
  await temporaryDirectory("nimbus-direct-upgrade-", async (directory) => {
    const legacy = new DatabaseSync(join(directory, "nimbus-direct.sqlite"));
    legacy.exec(`
      CREATE TABLE customer_resource_assignments (
        id TEXT PRIMARY KEY,
        customer_id TEXT NOT NULL,
        resource_id TEXT NOT NULL UNIQUE,
        display_name TEXT,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE sessions (
        id_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        csrf_token TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL
      ) STRICT;
      INSERT INTO customer_resource_assignments
        (id,customer_id,resource_id,display_name,status,created_at,updated_at)
        VALUES ('assignment-1','acme','production:qemu:101','Web','active',1,1);
    `);
    legacy.close();

    const store = await openStore(directory, { appSecret: APP_SECRET });
    try {
      const columns = store.database.prepare("PRAGMA table_info(customer_resource_assignments)").all().map((column) => column.name);
      assert.ok(columns.includes("snapshot_limit"));
      const sessionColumns = store.database.prepare("PRAGMA table_info(sessions)").all().map((column) => column.name);
      assert.ok(sessionColumns.includes("ip_address"));
      assert.ok(sessionColumns.includes("user_agent"));
      const userColumns = store.database.prepare("PRAGMA table_info(users)").all().map((column) => column.name);
      assert.ok(userColumns.includes("password_set"));
      assert.ok(userColumns.includes("preferred_language"));
      assert.ok(userColumns.includes("preferred_locale"));
      assert.ok(userColumns.includes("preferred_timezone"));
      const emailTables = store.database.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'email_%' ORDER BY name").all().map((row) => row.name);
      assert.deepEqual(emailTables, ["email_jobs", "email_settings"]);
      const emailColumns = store.database.prepare("PRAGMA table_info(email_settings)").all().map((column) => column.name);
      assert.ok(emailColumns.includes("app_url"));
      assert.equal(store.database.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE type='table' AND name='account_tokens'").get().count, 1);
      const notificationTables = store.database.prepare("SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'notification_%' OR name='notifications') ORDER BY name").all().map((row) => row.name);
      assert.deepEqual(notificationTables, ["notification_events", "notification_preferences", "notifications"]);
      const maintenanceTables = store.database.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'maintenance_%' ORDER BY name").all().map((row) => row.name);
      assert.deepEqual(maintenanceTables, ["maintenance_deliveries", "maintenance_events", "maintenance_targets"]);
      const maintenanceColumns = store.database.prepare("PRAGMA table_info(maintenance_events)").all().map((column) => column.name);
      assert.ok(maintenanceColumns.includes("time_zone"));
      const assignment = store.database.prepare("SELECT * FROM customer_resource_assignments WHERE id='assignment-1'").get();
      assert.equal(assignment.snapshot_limit, 3);
      assert.equal(assignment.resource_id, "production:qemu:101");
    } finally { store.close(); }
  });
});

test("notification preferences, deliveries, and alert policies remain user and assignment scoped", async () => {
  await temporaryDirectory("nimbus-direct-notification-store-", async (directory) => {
    const store = await openStore(directory, { appSecret: APP_SECRET });
    try {
      const acme = store.createCustomer({ id: "acme", name: "Acme" });
      const beta = store.createCustomer({ id: "beta", name: "Beta" });
      const acmeUser = await store.createUser({ email: "alerts-acme@example.com", displayName: "Acme Ops", password: "customer password test", customerId: acme.id });
      const betaUser = await store.createUser({ email: "alerts-beta@example.com", displayName: "Beta Ops", password: "customer password test", customerId: beta.id });
      store.createCluster({
        id: "production", name: "Production", apiUrl: "https://pve.example.test:8006",
        tokenId: "nimbus@pve!panel", tokenSecret: "proxmox-secret-value",
      });
      store.syncResources("production", [
        { type: "qemu", vmid: 101, node: "pve-a", name: "web", status: "running", cpu: 82, memory: 8, memoryUsed: 7, storage: 100, storageUsed: 91 },
      ]);
      const resourceId = "production:qemu:101";
      const assigned = store.assignResource({
        customerId: acme.id,
        resourceId,
        permissions: ["view_status"],
        alertPolicy: {
          enabled: true,
          offline: true,
          cpu: true,
          memory: true,
          storage: true,
          cpuThreshold: 80,
          memoryThreshold: 85,
          storageThreshold: 90,
          sustainMinutes: 2,
          cooldownMinutes: 30,
        },
      });
      assert.equal(assigned.alertPolicy.enabled, true);
      assert.equal(assigned.alertPolicy.storageThreshold, 90);
      assert.equal(store.listAlertAssignments({ clusterId: "production" })[0].assignmentId, assigned.assignmentId);

      assert.equal(store.getNotificationPreferences(acmeUser.id).emailEnabled, false);
      assert.equal(store.updateNotificationPreferences(acmeUser.id, { emailEnabled: true, resolutionAlerts: false }).emailEnabled, true);
      assert.equal(store.getNotificationPreferences(betaUser.id).emailEnabled, false);

      const created = store.createNotificationEvent({
        customerId: acme.id,
        resourceId,
        category: "infrastructure_alert",
        type: "alert.storage.firing",
        severity: "warning",
        title: "Storage is filling up",
        message: "Storage usage reached 91%.",
        dedupKey: "alert:assignment:storage:1:firing",
      });
      assert.equal(created.created, true);
      assert.equal(store.createNotificationEvent({
        customerId: acme.id,
        resourceId,
        category: "infrastructure_alert",
        type: "alert.storage.firing",
        severity: "warning",
        title: "Duplicate",
        message: "Duplicate",
        dedupKey: "alert:assignment:storage:1:firing",
      }).created, false);
      const delivery = store.createNotificationDelivery({ eventId: created.event.eventId, userId: acmeUser.id });
      assert.equal(delivery.created, true);
      assert.throws(
        () => store.createNotificationDelivery({ eventId: created.event.eventId, userId: betaUser.id }),
        (error) => error.code === "invalid_notification_recipient",
      );
      assert.equal(store.listNotifications(acmeUser.id).unread, 1);
      assert.equal(store.listNotifications(betaUser.id).total, 0);
      store.markNotificationRead(delivery.id, acmeUser.id);
      assert.equal(store.listNotifications(acmeUser.id).unread, 0);

      store.upsertAlertState(assigned.assignmentId, "storage", {
        status: "firing",
        conditionActive: true,
        firstObservedAt: 100,
        lastValue: 91,
        lastNotifiedAt: 200,
      });
      store.assignResource({ customerId: beta.id, resourceId, permissions: ["view_status"] });
      const reassigned = store.getResource(resourceId);
      assert.equal(reassigned.customerId, "beta");
      assert.equal(reassigned.alertPolicy.enabled, false);
      assert.equal(store.getAlertState(reassigned.assignmentId, "storage"), null);
    } finally { store.close(); }
  });
});

test("SMTP credentials and queued email content remain encrypted at rest", async () => {
  await temporaryDirectory("nimbus-direct-email-store-", async (directory) => {
    const store = await openStore(directory, { appSecret: APP_SECRET });
    try {
      const admin = await store.createUser({
        email: "mail-admin@example.com",
        displayName: "Mail admin",
        password: "admin password for mail tests",
        role: "admin",
      });
      assert.equal(store.getEmailSettings().configured, false);
      const settings = store.saveEmailSettings({
        enabled: true,
        host: "smtp.example.com",
        port: 587,
        security: "starttls",
        username: "mailer@example.com",
        password: "smtp-super-secret",
        fromName: "Nimbus Direct",
        fromEmail: "mailer@example.com",
        replyTo: "support@example.com",
      }, { userId: admin.id });
      assert.equal(settings.passwordConfigured, true);
      assert.equal("password" in settings, false);
      const rawSettings = store.database.prepare("SELECT * FROM email_settings WHERE id='default'").get();
      assert.equal(rawSettings.password_encrypted.includes("smtp-super-secret"), false);
      assert.equal(store.getEmailConnection().password, "smtp-super-secret");

      store.saveEmailSettings({
        enabled: false,
        host: "smtp.example.com",
        port: 465,
        security: "tls",
        username: "mailer@example.com",
        fromName: "Nimbus",
        fromEmail: "mailer@example.com",
      }, { userId: admin.id });
      assert.equal(store.getEmailConnection().password, "smtp-super-secret");

      const queued = store.queueEmail({
        to: "customer@example.com",
        subject: "Queued test",
        text: "Sensitive body text",
        html: "<p>Sensitive body HTML</p>",
        category: "delivery_test",
        createdBy: admin.id,
        maxAttempts: 2,
      });
      const rawJob = store.database.prepare("SELECT * FROM email_jobs WHERE id=?").get(queued.id);
      assert.equal(rawJob.payload_encrypted.includes("Sensitive body"), false);
      assert.equal(store.getEmailJobPayload(queued.id).text, "Sensitive body text");
      assert.equal(store.claimEmailJob(queued.id).attempts, 1);
      assert.equal(store.failEmailJob(queued.id, { errorCode: "smtp_timeout", retryable: true }).status, "pending");
      store.database.prepare("UPDATE email_jobs SET next_attempt_at=0 WHERE id=?").run(queued.id);
      assert.equal(store.claimEmailJob(queued.id).attempts, 2);
      assert.equal(store.failEmailJob(queued.id, { errorCode: "smtp_timeout", retryable: true }).status, "failed");
      assert.equal(store.retryEmailJob(queued.id).status, "pending");
      assert.equal(store.listEmailJobs().total, 1);
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
        permissions: ["view_status", "iso_view", "iso_upload", "iso_mount", "iso_boot", "iso_delete"],
      });
      assert.equal(store.authorizeResource(acme.id, resourceId, "iso_upload").vmid, 101);
      assert.equal(store.authorizeResource(acme.id, resourceId, "iso_boot").vmid, 101);

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
      const boot = store.createIsoBootOverride({
        resourceId,
        isoMountId: mount.id,
        driveSlot: "ide2",
        originalBoot: "order=scsi0;net0",
        armedBoot: "order=ide2;scsi0;net0",
        createdBy: acmeUser.id,
      });
      assert.equal(boot.status, "arming");
      const armedBoot = store.updateIsoBootOverride(boot.id, { status: "armed", armedAt: Date.now() });
      assert.equal(store.getActiveIsoBootOverrideForResource(resourceId).id, boot.id);
      assert.deepEqual(store.publicIsoBootOverride(armedBoot), {
        id: boot.id,
        resourceId,
        isoMountId: mount.id,
        driveSlot: "ide2",
        status: "armed",
        error: null,
        armedAt: armedBoot.armed_at,
        restoredAt: null,
        createdAt: armedBoot.created_at,
        updatedAt: armedBoot.updated_at,
      });
      assert.equal("originalBoot" in store.publicIsoBootOverride(armedBoot), false);
      assert.throws(
        () => store.createIsoBootOverride({
          resourceId,
          isoMountId: mount.id,
          driveSlot: "ide2",
          originalBoot: "order=scsi0",
          armedBoot: "order=ide2;scsi0",
          createdBy: acmeUser.id,
        }),
        (error) => error.code === "iso_boot_already_armed",
      );
      assert.throws(
        () => store.assignResource({ customerId: beta.id, resourceId, permissions: ["view_status"] }),
        (error) => error.code === "resource_iso_mounted",
      );
      assert.throws(() => store.deleteCustomer(acme.id), (error) => error.code === "customer_iso_images_exist");
      assert.throws(() => store.deleteIsoPolicy(policy.id), (error) => error.code === "iso_policy_in_use");

      store.updateIsoBootOverride(boot.id, { status: "restored", restoredAt: Date.now() });
      assert.equal(store.getActiveIsoBootOverrideForResource(resourceId), undefined);
      assert.equal(store.ejectIsoMount(mount.id).status, "ejected");
      assert.equal(store.hasActiveIsoMount(image.id), false);
      store.updateIsoImage(image.id, { status: "deleted" });
      assert.equal(store.getIsoUsage(acme.id, policy.id), 0);
      store.deleteIsoPolicy(policy.id);
      assert.equal(store.getIsoPolicy(policy.id), undefined);
    } finally { store.close(); }
  });
});

test("operations telemetry preserves last-good data and incidents acknowledge and resolve automatically", async () => {
  await temporaryDirectory("nimbus-direct-operations-store-", async (directory) => {
    const store = await openStore(directory, { appSecret: APP_SECRET });
    try {
      const admin = await store.createUser({
        email: "operations-admin@example.com",
        displayName: "Operations Admin",
        password: "operations admin password",
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
      ]);
      const task = store.createTask({
        customerId: null,
        userId: admin.id,
        clusterId: "production",
        node: "pve-a",
        upid: "UPID:pve-a:slow",
        resourceId: "production:qemu:101",
        action: "reboot",
      });
      store.database.prepare("UPDATE api_tasks SET created_at=? WHERE id=?")
        .run(Date.now() - 20 * 60_000, task.id);

      const saved = store.saveOperationsSnapshot("production", {
        nodes: [{
          node: "pve-a",
          status: "online",
          cpuPercent: 92,
          cpuCores: 16,
          memoryUsedBytes: 62 * 1024 ** 3,
          memoryTotalBytes: 64 * 1024 ** 3,
          memoryPercent: 97.2,
          rootUsedBytes: 40 * 1024 ** 3,
          rootTotalBytes: 100 * 1024 ** 3,
          rootPercent: 40,
          uptime: 86400,
        }],
        storages: [
          {
            node: "pve-a",
            storageId: "local-zfs",
            status: "available",
            type: "zfspool",
            shared: false,
            content: ["images", "rootdir"],
            usedBytes: 96 * 1024 ** 3,
            totalBytes: 100 * 1024 ** 3,
            availableBytes: 4 * 1024 ** 3,
            usagePercent: 96,
          },
          {
            node: "pve-b",
            storageId: "local-zfs",
            status: "disabled",
            type: "zfspool",
            shared: false,
            content: ["images", "rootdir"],
            usedBytes: 0,
            totalBytes: 0,
            availableBytes: 0,
            usagePercent: 0,
          },
        ],
      });
      assert.equal(saved.nodesAvailable, true);
      assert.equal(saved.storagesAvailable, true);
      assert.equal(store.getOperationsCenter().storages.some((storage) =>
        storage.node === "pve-b" && storage.storageId === "local-zfs"), false);

      let incidents = store.reconcileOperations("production");
      assert.ok(incidents.some((incident) => incident.type === "node_cpu_pressure" && incident.severity === "warning"));
      assert.ok(incidents.some((incident) => incident.type === "node_memory_pressure" && incident.severity === "critical"));
      assert.ok(incidents.some((incident) => incident.type === "storage_capacity" && incident.severity === "critical"));
      assert.ok(incidents.some((incident) => incident.type === "task_stuck"));

      const memoryIncident = incidents.find((incident) => incident.type === "node_memory_pressure");
      const acknowledged = store.acknowledgeOperationsIncident(memoryIncident.id, admin.id);
      assert.equal(acknowledged.status, "acknowledged");
      assert.equal(acknowledged.acknowledgedByName, "Operations Admin");

      // A permission failure cannot erase the previous node reading or silently
      // resolve an incident whose health scope was not evaluated.
      store.saveOperationsSnapshot("production", {
        nodes: null,
        storages: [{
          node: "pve-a",
          storageId: "local-zfs",
          status: "available",
          type: "zfspool",
          usedBytes: 50,
          totalBytes: 100,
          availableBytes: 50,
          usagePercent: 50,
        }],
        errors: { nodes: "proxmox_permission_denied" },
      });
      incidents = store.reconcileOperations("production");
      assert.equal(incidents.find((incident) => incident.id === memoryIncident.id).status, "acknowledged");
      assert.equal(store.getOperationsCenter().nodes[0].memoryPercent, 97.2);
      assert.equal(store.getOperationsCenter().clusters[0].telemetry.nodesAvailable, false);
      assert.equal(store.getOperationsCenter().clusters[0].telemetry.nodesError, "proxmox_permission_denied");

      store.updateTask(task.id, { status: "stopped", exitStatus: "OK", completedAt: Date.now() });
      store.saveOperationsSnapshot("production", {
        nodes: [{
          node: "pve-a",
          status: "online",
          cpuPercent: 20,
          cpuCores: 16,
          memoryUsedBytes: 20,
          memoryTotalBytes: 100,
          memoryPercent: 20,
          rootUsedBytes: 20,
          rootTotalBytes: 100,
          rootPercent: 20,
          uptime: 90000,
        }],
        storages: [{
          node: "pve-a",
          storageId: "local-zfs",
          status: "available",
          type: "zfspool",
          usedBytes: 50,
          totalBytes: 100,
          availableBytes: 50,
          usagePercent: 50,
        }],
        storagesAuthoritative: true,
      });
      assert.deepEqual(store.reconcileOperations("production"), []);
      const center = store.getOperationsCenter();
      assert.equal(center.summary.activeIncidents, 0);
      assert.equal(center.summary.healthyClusters, 1);
      assert.equal(store.database.prepare(`SELECT COUNT(*) AS count FROM operations_storage_metrics
        WHERE cluster_id='production' AND status IN ('unknown','disabled')`).get().count, 0);
      assert.ok(center.recentResolved.some((incident) => incident.id === memoryIncident.id));
      assert.equal(JSON.stringify(center).includes("proxmox-secret-value"), false);
    } finally {
      store.close();
    }
  });
});

test("security policy, posture, and authentication events are durable and centrally summarized", async () => {
  await temporaryDirectory("nimbus-direct-security-store-", async (directory) => {
    const store = await openStore(directory, { appSecret: APP_SECRET });
    try {
      const customer = store.createCustomer({ id: "secure-co", name: "Secure Co" });
      const admin = await store.createUser({
        email: "security-admin@example.com",
        displayName: "Security Admin",
        password: "security admin password",
        role: "admin",
      });
      const customerUser = await store.createUser({
        email: "security-customer@example.com",
        displayName: "Security Customer",
        password: "security customer password",
        customerId: customer.id,
      });

      assert.deepEqual(store.getSecurityPolicy(), {
        requireAdminMfa: false,
        requireCustomerMfa: false,
        newLoginEmail: false,
        updatedBy: null,
        updatedAt: store.getSecurityPolicy().updatedAt,
      });
      assert.throws(
        () => store.updateSecurityPolicy({ requireAdminMfa: "yes" }, admin.id),
        (error) => error.code === "invalid_security_policy",
      );
      const policy = store.updateSecurityPolicy({
        requireAdminMfa: true,
        requireCustomerMfa: true,
        newLoginEmail: true,
      }, admin.id);
      assert.equal(policy.requireAdminMfa, true);
      assert.equal(policy.requireCustomerMfa, true);
      assert.equal(policy.newLoginEmail, true);
      assert.equal(policy.updatedBy, admin.id);
      assert.equal(store.isMfaRequiredForUser(admin), true);
      assert.equal(store.isMfaRequiredForUser(customerUser), true);

      store.saveMfaSetup(customerUser.id, "JBSWY3DPEHPK3PXP");
      store.enableMfa(customerUser.id, ["ABCDE23456"]);
      store.createSession({ userId: admin.id, ttlMs: 60_000, ipAddress: "192.0.2.10" });
      store.writeAudit({
        userId: admin.id,
        actorRole: "admin",
        action: "auth.login_failed",
        detail: { stage: "password" },
        ipAddress: "192.0.2.10",
      });
      store.writeAudit({
        customerId: customer.id,
        userId: customerUser.id,
        actorRole: "customer",
        action: "auth.login",
        ipAddress: "192.0.2.20",
      });
      store.writeAudit({
        customerId: customer.id,
        userId: customerUser.id,
        actorRole: "customer",
        action: "security.mfa_enabled",
      });
      store.writeAudit({
        userId: admin.id,
        actorRole: "admin",
        action: "admin.cluster.created",
      });

      const center = store.getSecurityCenter();
      assert.equal(center.summary.activeAccounts, 2);
      assert.equal(center.summary.mfaProtected, 1);
      assert.equal(center.summary.mfaCoverage, 50);
      assert.equal(center.summary.requiredPending, 1);
      assert.equal(center.summary.activeSessions, 1);
      assert.equal(center.summary.successfulLogins24h, 1);
      assert.equal(center.summary.failedLogins24h, 1);
      assert.equal(center.events.total, 3);
      assert.ok(center.events.items.some((event) =>
        event.action === "auth.login_failed"
        && event.displayName === "Security Admin"
        && event.ipAddress === "192.0.2.10"));
      assert.equal(center.events.items.some((event) => event.action === "admin.cluster.created"), false);
    } finally {
      store.close();
    }
  });
});
