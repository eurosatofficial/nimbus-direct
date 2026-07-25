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

      // A partial/failed inventory refresh marks a missing guest stale but never
      // removes or transfers the local customer assignment.
      store.syncResources("production", [
        { type: "lxc", vmid: 301, node: "pve-b", name: "cache", status: "running" },
      ]);
      assert.equal(store.getResource(webId).stale, true);
      assert.equal(store.authorizeResource(acme.id, webId, "start").customerId, "acme");

      // Reassignment is a local database operation; Proxmox pools are absent.
      store.assignResource({ customerId: beta.id, resourceId: webId, permissions: ["view_status", "reboot"], snapshotLimit: 2 });
      assert.equal(store.authorizeResource(acme.id, webId, "view_status"), null);
      assert.equal(store.authorizeResource(beta.id, webId, "reboot").customerId, "beta");
      assert.equal(store.authorizeResource(beta.id, webId, "view_status").snapshotLimit, 2);
      assert.throws(() => store.updateAssignment(webId, { snapshotLimit: 0 }), (error) => error.code === "invalid_snapshot_limit");

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
      const emailTables = store.database.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'email_%' ORDER BY name").all().map((row) => row.name);
      assert.deepEqual(emailTables, ["email_jobs", "email_settings"]);
      const emailColumns = store.database.prepare("PRAGMA table_info(email_settings)").all().map((column) => column.name);
      assert.ok(emailColumns.includes("app_url"));
      assert.equal(store.database.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE type='table' AND name='account_tokens'").get().count, 1);
      const notificationTables = store.database.prepare("SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'notification_%' OR name='notifications') ORDER BY name").all().map((row) => row.name);
      assert.deepEqual(notificationTables, ["notification_events", "notification_preferences", "notifications"]);
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
