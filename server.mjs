import { createServer } from "node:http";
import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { connect as connectTls } from "node:tls";
import QRCode from "qrcode";
import { loadEnv, readConfig } from "./server/config.mjs";
import {
  createEmailService,
  createSmtpTransport,
  invitationEmailTemplate,
  passwordResetEmailTemplate,
  securityEmailTemplate,
} from "./server/email.mjs";
import { createTotpEnrollment, generateRecoveryCodes, verifyTotp } from "./server/mfa.mjs";
import { createNotificationService } from "./server/notifications.mjs";
import { ProxmoxRegistry } from "./server/proxmox-registry.mjs";
import { RateLimiter } from "./server/rate-limit.mjs";
import { bootstrapStore, DEFAULT_PERMISSIONS, openStore } from "./server/store.mjs";
import {
  parseCookies,
  securityHeaders,
  sessionCookie,
  sessionCookieName,
  safeEqual,
  verifyPassword,
} from "./server/security.mjs";

await loadEnv(new URL("./.env", import.meta.url));
const config = readConfig();
const store = await openStore(config.dataDir, { appSecret: config.appSecret });
const bootstrapped = await bootstrapStore(store, config.bootstrap);
const proxmox = new ProxmoxRegistry({
  getConnection: (clusterId) => store.getClusterConnection(clusterId),
  timeoutMs: config.proxmoxTimeoutMs,
});
const loginLimiter = new RateLimiter({ limit: 8, windowMs: 15 * 60 * 1000 });
const mfaLimiter = new RateLimiter({ limit: 8, windowMs: 10 * 60 * 1000 });
const securityActionLimiter = new RateLimiter({ limit: 10, windowMs: 15 * 60 * 1000 });
const forgotPasswordLimiter = new RateLimiter({ limit: 5, windowMs: 15 * 60 * 1000 });
const forgotAccountLimiter = new RateLimiter({ limit: 3, windowMs: 60 * 60 * 1000 });
const accountTokenLimiter = new RateLimiter({ limit: 12, windowMs: 15 * 60 * 1000 });
const invitationLimiter = new RateLimiter({ limit: 20, windowMs: 60 * 60 * 1000 });
const actionLimiter = new RateLimiter({ limit: 30, windowMs: 60 * 1000 });
const uploadLimiter = new RateLimiter({ limit: 5, windowMs: 60 * 60 * 1000 });
const emailConnectionTestLimiter = new RateLimiter({ limit: 12, windowMs: 5 * 60 * 1000 });
const emailMessageTestLimiter = new RateLimiter({ limit: 10, windowMs: 15 * 60 * 1000 });
const root = fileURLToPath(new URL("./public", import.meta.url));
const noVncRoot = fileURLToPath(new URL("./node_modules/@novnc/novnc", import.meta.url));
const headers = securityHeaders();
const cookieName = sessionCookieName(config.secureCookies);

const demoResources = [
  { vmid: 101, type: "qemu", name: "atlas-web-01", node: "pve-ber-01", status: "running", vcpu: 4, memory: 8, memoryUsed: 3.8, storage: 80, storageUsed: 42, ip: "10.24.1.31", cpu: 38, uptime: 834223 },
  { vmid: 105, type: "qemu", name: "atlas-db-01", node: "pve-ber-02", status: "running", vcpu: 8, memory: 16, memoryUsed: 10.2, storage: 240, storageUsed: 121, ip: "10.24.1.35", cpu: 57, uptime: 733103 },
  { vmid: 203, type: "qemu", name: "nova-api-01", node: "pve-fra-01", status: "stopped", vcpu: 4, memory: 8, memoryUsed: 0, storage: 100, storageUsed: 61, ip: "10.31.2.18", cpu: 0, uptime: 0 },
  { vmid: 301, type: "lxc", name: "cache-edge-01", node: "pve-ber-03", status: "running", vcpu: 2, memory: 4, memoryUsed: 1.7, storage: 32, storageUsed: 12, ip: "10.24.3.44", cpu: 21, uptime: 338441 },
  { vmid: 302, type: "qemu", name: "worker-gpu-01", node: "pve-fra-02", status: "suspended", vcpu: 12, memory: 32, memoryUsed: 18.4, storage: 300, storageUsed: 201, ip: "10.31.2.55", cpu: 0, uptime: 129223 },
];
const demoSnapshots = new Map();

if (config.allowDemoData && !store.listClusters().length) {
  store.createCluster({ id: "demo-eu", name: "Nimbus Demo EU", apiUrl: "https://demo.invalid:8006", tokenId: "demo@pve!panel", tokenSecret: "demo-secret-never-used" });
  store.syncResources("demo-eu", demoResources);
  const customer = store.listCustomers()[0];
  if (customer) {
    for (const resource of store.listResources({ clusterId: "demo-eu" }).slice(0, 3)) {
      store.assignResource({ customerId: customer.id, resourceId: resource.id, permissions: DEFAULT_PERMISSIONS });
    }
  }
}
if (config.allowDemoData && store.listClusters().some((cluster) => cluster.id === "demo-eu") && !store.listIsoPolicies({ clusterId: "demo-eu" }).length) {
  store.createIsoPolicy({
    clusterId: "demo-eu",
    storageId: "local",
    displayName: "Demo installation media",
    maxUploadBytes: Math.min(config.isoMaxUploadBytes, 8 * 1024 ** 3),
    customerQuotaBytes: 25 * 1024 ** 3,
    allowDelete: true,
  });
}

function log(level, message, detail = {}) {
  console[level === "error" ? "error" : "log"](JSON.stringify({ timestamp: new Date().toISOString(), level, message, ...detail }));
}

const email = createEmailService({
  store,
  log,
  transport: createSmtpTransport({ timeoutMs: config.emailSmtpTimeoutMs }),
  queueIntervalMs: config.emailQueueIntervalMs,
});
const notifications = createNotificationService({ store, email, log });

function sendJson(response, status, payload, extraHeaders = {}) {
  response.writeHead(status, { ...headers, "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extraHeaders });
  response.end(payload === null ? "" : JSON.stringify(payload));
}

async function readBody(request) {
  if (!String(request.headers["content-type"] || "").toLowerCase().startsWith("application/json")) {
    throw Object.assign(new Error("Expected application/json"), { status: 415, code: "invalid_content_type" });
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 64 * 1024) throw Object.assign(new Error("Request body is too large"), { status: 413, code: "body_too_large" });
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); }
  catch { throw Object.assign(new Error("Invalid JSON body"), { status: 400, code: "invalid_json" }); }
}

function clientIp(request) {
  if (config.trustProxy) return String(request.headers["x-forwarded-for"] || "").split(",")[0].trim() || request.socket.remoteAddress;
  return request.socket.remoteAddress;
}

function currentSession(request) {
  return store.getSession(parseCookies(request.headers.cookie)[cookieName]);
}

function requireSession(request, response) {
  const session = currentSession(request);
  if (!session) sendJson(response, 401, { error: "authentication_required" });
  return session;
}

function requireCsrf(request, response, session) {
  if (!safeEqual(request.headers["x-csrf-token"], session.csrfToken)) {
    sendJson(response, 403, { error: "invalid_csrf_token" });
    return false;
  }
  const origin = request.headers.origin;
  if (origin) {
    const expected = `${config.production ? "https" : "http"}://${request.headers.host}`;
    if (origin !== expected) {
      sendJson(response, 403, { error: "invalid_origin" });
      return false;
    }
  }
  return true;
}

function requireAdmin(response, session) {
  if (session.user.role !== "admin") {
    sendJson(response, 403, { error: "admin_required" });
    return false;
  }
  return true;
}

function audit(request, session, action, { customerId = session.user.customerId, resourceId = null, detail = {} } = {}) {
  store.writeAudit({
    customerId, userId: session.user.id, actorRole: session.user.role, action, resourceId, detail, ipAddress: clientIp(request),
  });
}

function createLoginSession(request, userId) {
  return store.createSession({
    userId,
    ttlMs: config.sessionTtlMs,
    ipAddress: clientIp(request),
    userAgent: request.headers["user-agent"],
  });
}

function sendAuthenticated(response, session) {
  sendJson(response, 200, {
    user: store.getSession(session.token).user,
    csrfToken: session.csrfToken,
    expiresAt: session.expiresAt,
  }, {
    "set-cookie": sessionCookie(session.token, {
      secure: config.secureCookies,
      maxAge: config.sessionTtlMs,
      name: cookieName,
    }),
  });
}

function verifyMfaCredential(userId, code, { allowRecovery = true } = {}) {
  const secret = store.getMfaSecret(userId);
  if (secret && verifyTotp(secret, code)) return { valid: true, recoveryCode: false };
  if (allowRecovery && store.consumeRecoveryCode(userId, code)) return { valid: true, recoveryCode: true };
  return { valid: false, recoveryCode: false };
}

function queueSecurityNotice(user, { title, message, ipAddress = null }) {
  try {
    if (!store.getEmailSettings().enabled || !user?.email) return;
    const content = securityEmailTemplate({
      displayName: user.display_name || user.displayName,
      title,
      message,
      ipAddress,
    });
    store.queueEmail({
      to: user.email,
      ...content,
      category: "account_security",
      createdBy: user.id,
      maxAttempts: 4,
    });
    void email.processDue();
  } catch (error) {
    log("error", "security_notice_queue_failed", { userId: user?.id, error: error.code || error.message });
  }
}

function accountEmailSettings() {
  const settings = store.getEmailSettings();
  if (!settings.enabled) throw Object.assign(new Error("Email delivery is disabled"), { status: 409, code: "email_disabled" });
  if (!settings.appUrl) throw Object.assign(new Error("Configure the public panel URL in the Email Center"), {
    status: 409,
    code: "account_link_url_missing",
  });
  return settings;
}

function accountActionUrl(appUrl, purpose, token) {
  const url = new URL(appUrl);
  url.searchParams.set(purpose === "invitation" ? "invite" : "reset", token);
  return url.toString();
}

function queueInvitationEmail(user, accountToken, createdBy) {
  const settings = accountEmailSettings();
  const content = invitationEmailTemplate({
    displayName: user.displayName,
    customerName: user.customerName,
    actionUrl: accountActionUrl(settings.appUrl, "invitation", accountToken.token),
    expiresAt: accountToken.expiresAt,
  });
  const job = store.queueEmail({
    to: user.email,
    ...content,
    category: "account_invitation",
    createdBy,
    maxAttempts: 4,
  });
  void email.processDue();
  return job;
}

function queuePasswordResetEmail(user, accountToken) {
  const settings = accountEmailSettings();
  const content = passwordResetEmailTemplate({
    displayName: user.display_name,
    actionUrl: accountActionUrl(settings.appUrl, "password_reset", accountToken.token),
    expiresAt: accountToken.expiresAt,
  });
  const job = store.queueEmail({
    to: user.email,
    ...content,
    category: "password_reset",
    createdBy: user.id,
    maxAttempts: 4,
  });
  void email.processDue();
  return job;
}

async function waitForUniformResponse(startedAt, minimumMs = 300) {
  const remaining = minimumMs - (Date.now() - startedAt);
  if (remaining > 0) await new Promise((resolvePromise) => setTimeout(resolvePromise, remaining));
}

function maskedEmail(value) {
  const [local, domain] = String(value || "").split("@");
  if (!local || !domain) return "";
  return `${local.slice(0, 1)}${"*".repeat(Math.min(5, Math.max(2, local.length - 1)))}@${domain}`;
}

function requireSecurityActionRate(request, response, userId) {
  const limit = securityActionLimiter.consume(`${userId}:${clientIp(request)}`);
  if (limit.allowed) return true;
  sendJson(response, 429, { error: "too_many_security_actions" }, { "retry-after": String(limit.retryAfter) });
  return false;
}

async function requireCurrentPassword(response, userId, value) {
  const user = store.getUserForAuth(userId);
  if (!user || !(await verifyPassword(String(value || ""), user.password_hash))) {
    sendJson(response, 400, { error: "current_password_invalid" });
    return null;
  }
  return user;
}

function resourceFor(user, resourceId, permission) {
  if (user.role === "admin") return store.getResource(resourceId);
  return store.authorizeResource(user.customerId, resourceId, permission);
}

function requireResource(response, user, resourceId, permission) {
  const resource = resourceFor(user, resourceId, permission);
  if (!resource) sendJson(response, 404, { error: "resource_not_found" });
  return resource;
}

function clientFor(resource) {
  return proxmox.forCluster(resource.clusterId);
}

function isDemo(resource) {
  return config.allowDemoData && resource.clusterId === "demo-eu";
}

function requireQemu(resource) {
  if (resource.type !== "qemu") {
    throw Object.assign(new Error("Installation media is available only for QEMU virtual machines"), { status: 400, code: "iso_qemu_only" });
  }
}

function snapshotName(value) {
  const name = String(value || "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/.test(name)) {
    throw Object.assign(new Error("Use 1-80 letters, numbers, dots, underscores, or hyphens"), { status: 400, code: "invalid_snapshot_name" });
  }
  return name;
}

function canViewSnapshots(resource, user) {
  return user.role === "admin"
    || ["snapshot_create", "snapshot_restore", "snapshot_delete"].some((permission) => resource.permissions.includes(permission));
}

function snapshotPolicy(resource, snapshots) {
  const limit = Math.max(1, Number(resource.snapshotLimit) || 3);
  return {
    limit,
    count: snapshots.length,
    remaining: Math.max(0, limit - snapshots.length),
  };
}

function demoSnapshotsFor(resource) {
  if (!demoSnapshots.has(resource.id)) {
    demoSnapshots.set(resource.id, [{
      name: "before-upgrade",
      description: "Known good state",
      parent: null,
      createdAt: Date.now() - 86400000 * 4,
      includesMemory: false,
    }]);
  }
  return demoSnapshots.get(resource.id);
}

function requireSnapshotMediaClear(resourceId) {
  if (store.getActiveIsoBootOverrideForResource(resourceId) || store.getActiveIsoMountForResource(resourceId)) {
    throw Object.assign(new Error("Restore the normal boot order and eject the ISO before changing snapshots"), {
      status: 409,
      code: "snapshot_media_conflict",
    });
  }
}

function isoCustomer(resource, user) {
  const customerId = resource.customerId || user.customerId;
  if (!customerId) {
    throw Object.assign(new Error("Assign this VM to a customer before managing customer installation media"), { status: 409, code: "iso_customer_required" });
  }
  return { id: customerId, scope: { role: "customer", customerId } };
}

function isoUploadMetadata(request) {
  const encodedName = String(request.headers["x-nimbus-filename"] || "");
  let originalName;
  try { originalName = decodeURIComponent(encodedName).trim(); }
  catch { throw Object.assign(new Error("The ISO filename is invalid"), { status: 400, code: "invalid_iso_filename" }); }
  if (!originalName || originalName.length > 255 || !originalName.toLowerCase().endsWith(".iso")) {
    throw Object.assign(new Error("Choose a .iso file with a filename of at most 255 characters"), { status: 400, code: "invalid_iso_filename" });
  }
  const sizeBytes = Number(request.headers["x-nimbus-size"]);
  if (!Number.isSafeInteger(sizeBytes) || sizeBytes <= 0) {
    throw Object.assign(new Error("The ISO upload size is missing or invalid"), { status: 400, code: "invalid_iso_size" });
  }
  if (sizeBytes > config.isoMaxUploadBytes) {
    throw Object.assign(new Error("The ISO is larger than the panel upload limit"), { status: 413, code: "iso_too_large" });
  }
  const cleanStem = originalName.slice(0, -4).normalize("NFKD").replace(/[^A-Za-z0-9_.-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 110) || "installation-media";
  const fileName = `${cleanStem}-${randomUUID().slice(0, 12)}.iso`;
  return { originalName, fileName, sizeBytes };
}

async function consumeDemoUpload(source, expectedBytes) {
  const hash = createHash("sha256");
  let receivedBytes = 0;
  for await (const chunk of source) {
    receivedBytes += chunk.length;
    if (receivedBytes > expectedBytes) {
      throw Object.assign(new Error("The upload exceeded its declared size"), { status: 400, code: "iso_upload_size_mismatch" });
    }
    hash.update(chunk);
  }
  if (receivedBytes !== expectedBytes) {
    throw Object.assign(new Error("The upload did not match its declared size"), { status: 400, code: "iso_upload_size_mismatch" });
  }
  return { bytes: receivedBytes, sha256: hash.digest("hex"), result: null };
}

async function refreshIsoOperation(row) {
  if (!row || !["processing", "deleting"].includes(row.status) || !row.operation_upid) return row ? store.getIsoImage(row.id) : null;
  const remote = await proxmox.forCluster(row.cluster_id).getTaskStatus(row.node, row.operation_upid);
  if (remote?.status !== "stopped") return store.getIsoImage(row.id);
  if (remote.exitstatus === "OK") {
    return store.updateIsoImage(row.id, {
      status: row.status === "deleting" ? "deleted" : "ready",
      operationUpid: null,
      errorCode: null,
    });
  }
  return store.updateIsoImage(row.id, {
    status: "error",
    operationUpid: null,
    errorCode: String(remote?.exitstatus || "proxmox_task_failed").slice(0, 120),
  });
}

async function restoreIsoBootOverride(resourceId, { finalStatus = "restored" } = {}) {
  const boot = store.getActiveIsoBootOverrideForResource(resourceId);
  if (!boot) return null;
  const resource = store.getResource(resourceId);
  if (!resource) return null;
  store.updateIsoBootOverride(boot.id, { status: "restoring", errorCode: null });
  try {
    if (!isDemo(resource)) {
      await clientFor(resource).restoreIsoBootOnce(resource, {
        originalBoot: boot.original_boot,
        armedBoot: boot.armed_boot,
      });
    }
    return store.updateIsoBootOverride(boot.id, {
      status: finalStatus,
      errorCode: null,
      restoredAt: Date.now(),
    });
  } catch (error) {
    store.updateIsoBootOverride(boot.id, {
      status: "error",
      errorCode: String(error.code || "iso_boot_restore_failed").slice(0, 120),
    });
    throw error;
  }
}

async function restoreIsoBootAfterPowerTask(task) {
  if (task.exit_status !== "OK" || !["start", "reboot", "reset"].includes(task.action)) return;
  const active = store.getActiveIsoBootOverrideForResource(task.resource_id);
  if (!active) return;
  if (Number(task.created_at) < Number(active.armed_at || active.created_at)) return;
  try {
    const restored = await restoreIsoBootOverride(task.resource_id);
    if (restored) {
      store.writeAudit({
        customerId: task.customer_id,
        userId: null,
        actorRole: "system",
        action: "resource.iso_boot.restored",
        resourceId: task.resource_id,
        detail: { bootOverrideId: restored.id, powerTaskId: task.id },
      });
    }
  } catch (error) {
    store.writeAudit({
      customerId: task.customer_id,
      userId: null,
      actorRole: "system",
      action: "resource.iso_boot.restore_failed",
      resourceId: task.resource_id,
      detail: { bootOverrideId: active.id, powerTaskId: task.id, error: error.code || "iso_boot_restore_failed" },
    });
    log("error", "iso_boot_restore_failed", { resourceId: task.resource_id, taskId: task.id, error: error.code || error.message });
  }
}

function summarize(resources) {
  const running = resources.filter((resource) => resource.status === "running");
  return {
    active: running.length,
    total: resources.length,
    cpuAverage: running.length ? Math.round(running.reduce((sum, resource) => sum + resource.cpu, 0) / running.length) : 0,
    memoryUsed: Math.round(resources.reduce((sum, resource) => sum + resource.memoryUsed, 0) * 10) / 10,
    memoryTotal: resources.reduce((sum, resource) => sum + resource.memory, 0),
    clusters: new Set(resources.map((resource) => resource.clusterId)).size,
  };
}

function expectedStatusForAction(action) {
  if (["stop", "shutdown"].includes(action)) return "stopped";
  if (action === "suspend") return "suspended";
  if (["start", "resume", "reboot", "reset"].includes(action)) return "running";
  return null;
}

function demoInstanceHistory(resource, timeframe = "day") {
  const durations = { hour: 60 * 60 * 1000, day: 24 * 60 * 60 * 1000, week: 7 * 24 * 60 * 60 * 1000, month: 30 * 24 * 60 * 60 * 1000, year: 365 * 24 * 60 * 60 * 1000 };
  const duration = durations[timeframe];
  if (!duration) throw Object.assign(new Error("Unsupported history timeframe"), { status: 400, code: "invalid_timeframe" });
  const now = Date.now();
  const points = Array.from({ length: 48 }, (_, index) => {
    const phase = index / 5 + Number(resource.vmid % 7);
    return {
      timestamp: now - duration + Math.round(duration * index / 47),
      cpu: Math.max(1, Math.min(96, Math.round(resource.cpu * .72 + Math.sin(phase) * 12 + 10))),
      memory: Math.max(1, Math.min(99, Math.round((resource.memory ? resource.memoryUsed / resource.memory * 100 : 0) + Math.cos(phase / 2) * 5))),
      netIn: Math.max(0, Math.round(450_000 + Math.sin(phase * .8) * 320_000)),
      netOut: Math.max(0, Math.round(260_000 + Math.cos(phase * .7) * 190_000)),
    };
  });
  return { timeframe, points, available: true, partial: false, sampledInstances: 1, totalInstances: 1 };
}

async function refreshStoredTask(task) {
  if (task.completed_at || task.status === "stopped") {
    await restoreIsoBootAfterPowerTask(task);
    return { task, completed: true, transitioned: false };
  }
  const remote = await proxmox.forCluster(task.cluster_id).getTaskStatus(task.node, task.upid);
  const completed = remote.status === "stopped";
  const updated = store.updateTask(task.id, {
    status: remote.status || "running",
    exitStatus: remote.exitstatus || null,
    completedAt: completed ? Date.now() : null,
  });
  if (completed && updated.exit_status === "OK") {
    const nextStatus = expectedStatusForAction(updated.action);
    if (nextStatus && store.getResource(updated.resource_id)) store.setResourceStatus(updated.resource_id, nextStatus);
  }
  if (completed) await restoreIsoBootAfterPowerTask(updated);
  return { task: updated, completed, transitioned: completed && !task.completed_at };
}

async function recordTaskCompletion(task) {
  const snapshotAction = {
    snapshot_create: task.exit_status === "OK" ? "resource.snapshot.created" : "resource.snapshot.create_failed",
    snapshot_restore: task.exit_status === "OK" ? "resource.snapshot.restored" : "resource.snapshot.restore_failed",
    snapshot_delete: task.exit_status === "OK" ? "resource.snapshot.deleted" : "resource.snapshot.delete_failed",
  }[task.action];
  store.writeAudit({
    customerId: task.customer_id,
    userId: null,
    actorRole: "system",
    action: snapshotAction || `resource.${task.action}.${task.exit_status === "OK" ? "completed" : "failed"}`,
    resourceId: task.resource_id,
    detail: { taskId: task.id },
  });
  try { await notifications.actionCompleted(task); }
  catch (error) { log("error", "task_notification_failed", { taskId: task.id, error: error.code || error.message }); }
}

async function blockingTask(resourceId) {
  const active = store.getActiveTask(resourceId);
  if (!active) return null;
  try {
    const result = await refreshStoredTask(active);
    if (result.transitioned) await recordTaskCompletion(result.task);
    return result.completed ? null : result.task;
  } catch (error) {
    log("error", "task_refresh_delayed", { taskId: active.id, resourceId, error: error.code || error.message });
    return active;
  }
}

async function refreshClusterTasks(clusterId) {
  for (const task of store.listActiveTasksForCluster(clusterId)) {
    try {
      const result = await refreshStoredTask(task);
      if (result.transitioned) await recordTaskCompletion(result.task);
    } catch (error) {
      log("error", "background_task_refresh_delayed", {
        clusterId,
        taskId: task.id,
        error: error.code || error.message,
      });
    }
  }
}

async function syncCluster(clusterId) {
  if (config.allowDemoData && clusterId === "demo-eu") {
    const synced = store.syncResources(clusterId, demoResources.map((resource) => {
      const current = store.getResource(`${clusterId}:${resource.type}:${resource.vmid}`);
      return current ? { ...resource, status: current.status } : resource;
    }));
    await refreshClusterTasks(clusterId);
    try { await notifications.evaluateResourceAlerts({ clusterId }); }
    catch (error) { log("error", "alert_evaluation_failed", { clusterId, error: error.code || error.message }); }
    return synced;
  }
  try {
    const resources = await proxmox.forCluster(clusterId).listVirtualMachines();
    const synced = store.syncResources(clusterId, resources);
    await refreshClusterTasks(clusterId);
    try { await notifications.evaluateResourceAlerts({ clusterId }); }
    catch (error) { log("error", "alert_evaluation_failed", { clusterId, error: error.code || error.message }); }
    return synced;
  } catch (error) {
    store.setClusterSync(clusterId, { error: error.code || "proxmox_sync_failed" });
    throw error;
  }
}

async function syncAllClusters() {
  for (const cluster of store.listClusters().filter((entry) => entry.status !== "disabled")) {
    try { await syncCluster(cluster.id); }
    catch (error) { log("error", "cluster_sync_failed", { clusterId: cluster.id, error: error.code || error.message }); }
  }
}

async function routeAuth(request, response, pathname) {
  if (pathname === "/api/auth/session" && request.method === "GET") {
    const session = requireSession(request, response);
    if (session) sendJson(response, 200, { user: session.user, csrfToken: session.csrfToken, expiresAt: session.expiresAt });
    return true;
  }
  if (pathname === "/api/auth/login" && request.method === "POST") {
    const ip = clientIp(request);
    const limit = loginLimiter.consume(ip);
    if (!limit.allowed) { sendJson(response, 429, { error: "too_many_attempts" }, { "retry-after": String(limit.retryAfter) }); return true; }
    const { email, password } = await readBody(request);
    const user = store.findUserForLogin(email);
    if (!user || user.status !== "active" || !user.password_set
      || (user.role === "customer" && user.customer_status !== "active")
      || !(await verifyPassword(String(password || ""), user.password_hash))) {
      sendJson(response, 401, { error: "invalid_credentials" }); return true;
    }
    loginLimiter.clear(ip);
    if (user.mfa_enabled) {
      const challenge = store.createMfaChallenge({ userId: user.id });
      store.writeAudit({
        customerId: user.customer_id,
        userId: user.id,
        actorRole: user.role,
        action: "auth.mfa_challenge",
        ipAddress: ip,
      });
      sendJson(response, 202, {
        mfaRequired: true,
        challengeToken: challenge.token,
        expiresAt: challenge.expiresAt,
      });
      return true;
    }
    const session = createLoginSession(request, user.id);
    store.writeAudit({ customerId: user.customer_id, userId: user.id, actorRole: user.role, action: "auth.login", ipAddress: ip });
    sendAuthenticated(response, session);
    return true;
  }
  if (pathname === "/api/auth/mfa" && request.method === "POST") {
    const ip = clientIp(request);
    const limit = mfaLimiter.consume(ip);
    if (!limit.allowed) {
      sendJson(response, 429, { error: "too_many_mfa_attempts" }, { "retry-after": String(limit.retryAfter) });
      return true;
    }
    const { challengeToken, code } = await readBody(request);
    const challenge = store.getMfaChallenge(String(challengeToken || ""));
    const user = challenge ? store.getUserForAuth(challenge.user_id) : null;
    if (!challenge || !user || user.status !== "active"
      || (user.role === "customer" && user.customer_status !== "active") || !user.mfa_enabled) {
      sendJson(response, 401, { error: "invalid_mfa_challenge" });
      return true;
    }
    const verification = verifyMfaCredential(user.id, code);
    if (!verification.valid) {
      store.failMfaChallenge(challengeToken);
      store.writeAudit({
        customerId: user.customer_id,
        userId: user.id,
        actorRole: user.role,
        action: "auth.mfa_failed",
        ipAddress: ip,
      });
      sendJson(response, 401, { error: "invalid_mfa_code" });
      return true;
    }
    if (!store.consumeMfaChallenge(challengeToken)) {
      sendJson(response, 401, { error: "invalid_mfa_challenge" });
      return true;
    }
    mfaLimiter.clear(ip);
    const session = createLoginSession(request, user.id);
    store.writeAudit({
      customerId: user.customer_id,
      userId: user.id,
      actorRole: user.role,
      action: "auth.login",
      detail: { mfa: true, recoveryCode: verification.recoveryCode },
      ipAddress: ip,
    });
    if (verification.recoveryCode) {
      queueSecurityNotice(user, {
        title: "A recovery code was used",
        message: "A one-time recovery code was used to sign in. Review your active sessions and regenerate codes if this was unexpected.",
        ipAddress: ip,
      });
    }
    sendAuthenticated(response, session);
    return true;
  }
  if (pathname === "/api/auth/password/forgot" && request.method === "POST") {
    const startedAt = Date.now();
    const ip = clientIp(request);
    const ipLimit = forgotPasswordLimiter.consume(ip);
    const { email: requestedEmail } = await readBody(request);
    const normalizedEmail = String(requestedEmail || "").trim().toLowerCase();
    const accountKey = createHash("sha256").update(normalizedEmail).digest("base64url");
    const accountLimit = forgotAccountLimiter.consume(accountKey);
    if (ipLimit.allowed && accountLimit.allowed) {
      const user = store.findUserForLogin(normalizedEmail);
      const eligible = user
        && user.status === "active"
        && user.password_set
        && (user.role !== "customer" || user.customer_status === "active");
      if (eligible) {
        try {
          accountEmailSettings();
          const accountToken = store.createAccountToken({
            userId: user.id,
            purpose: "password_reset",
            requestedIp: ip,
          });
          const job = queuePasswordResetEmail(user, accountToken);
          store.writeAudit({
            customerId: user.customer_id,
            userId: user.id,
            actorRole: "system",
            action: "auth.password_reset_requested",
            detail: { emailJobId: job.id },
            ipAddress: ip,
          });
        } catch (error) {
          log("error", "password_reset_request_suppressed", {
            userId: user.id,
            error: error.code || error.message,
          });
        }
      }
    }
    await waitForUniformResponse(startedAt);
    sendJson(response, 202, {
      accepted: true,
      message: "If the account exists, a password reset link will be sent.",
    });
    return true;
  }
  if (pathname === "/api/auth/account-token" && request.method === "POST") {
    const ip = clientIp(request);
    const limit = accountTokenLimiter.consume(ip);
    if (!limit.allowed) {
      sendJson(response, 429, { error: "too_many_account_token_attempts" }, { "retry-after": String(limit.retryAfter) });
      return true;
    }
    const { purpose, token } = await readBody(request);
    const row = store.getAccountToken(token, purpose);
    if (!row) { sendJson(response, 400, { error: "account_token_invalid" }); return true; }
    sendJson(response, 200, {
      valid: true,
      purpose,
      emailHint: maskedEmail(row.email),
      expiresAt: row.expires_at,
    });
    return true;
  }
  if (pathname === "/api/auth/account/complete" && request.method === "POST") {
    const ip = clientIp(request);
    const limit = accountTokenLimiter.consume(ip);
    if (!limit.allowed) {
      sendJson(response, 429, { error: "too_many_account_token_attempts" }, { "retry-after": String(limit.retryAfter) });
      return true;
    }
    const { token, purpose, password, confirmPassword } = await readBody(request);
    if (!["invitation", "password_reset"].includes(purpose)) {
      sendJson(response, 400, { error: "account_token_invalid" });
      return true;
    }
    if (password !== confirmPassword) {
      sendJson(response, 400, { error: "password_confirmation_mismatch" });
      return true;
    }
    const tokenRow = store.getAccountToken(token, purpose);
    if (!tokenRow) { sendJson(response, 400, { error: "account_token_invalid" }); return true; }
    const completedUser = await store.consumeAccountToken(token, purpose, String(password || ""));
    if (!completedUser) { sendJson(response, 400, { error: "account_token_invalid" }); return true; }
    accountTokenLimiter.clear(ip);
    const authUser = store.getUserForAuth(completedUser.id);
    store.writeAudit({
      customerId: completedUser.customerId,
      userId: completedUser.id,
      actorRole: "system",
      action: purpose === "invitation" ? "auth.invitation_accepted" : "auth.password_reset_completed",
      ipAddress: ip,
    });
    queueSecurityNotice(authUser, {
      title: purpose === "invitation" ? "Your Nimbus Direct account is active" : "Your password was reset",
      message: purpose === "invitation"
        ? "Your invitation was accepted and your private password was created."
        : "Your Nimbus Direct password was changed and every active session was signed out. Two-factor authentication remains enabled.",
      ipAddress: ip,
    });
    sendJson(response, 200, {
      completed: true,
      purpose,
      message: purpose === "invitation" ? "Your account is ready. Sign in to continue." : "Your password was reset. Sign in again.",
    });
    return true;
  }
  if (pathname === "/api/auth/logout" && request.method === "POST") {
    const session = requireSession(request, response);
    if (!session || !requireCsrf(request, response, session)) return true;
    store.deleteSession(parseCookies(request.headers.cookie)[cookieName]);
    audit(request, session, "auth.logout");
    sendJson(response, 204, null, { "set-cookie": sessionCookie("", { secure: config.secureCookies, maxAge: 0, name: cookieName }) });
    return true;
  }
  return false;
}

async function routeAdmin(request, response, pathname) {
  const session = requireSession(request, response);
  if (!session || !requireAdmin(response, session)) return true;
  if (request.method !== "GET" && !requireCsrf(request, response, session)) return true;

  if (pathname === "/api/admin/state" && request.method === "GET") {
    sendJson(response, 200, {
      clusters: store.listClusters(), customers: store.listCustomers(), users: store.listUsers(),
      resources: store.listResources(), isoPolicies: store.listIsoPolicies(),
      emailSettings: store.getEmailSettings(), emailJobs: store.listEmailJobs({ limit: 30 }),
      notificationEvents: store.listNotificationEvents({ limit: 50 }),
      audit: store.listAudit(null, { all: true, limit: 50 }),
    });
    return true;
  }
  if (pathname === "/api/admin/email/settings" && request.method === "PUT") {
    const settings = store.saveEmailSettings(await readBody(request), { userId: session.user.id });
    emailConnectionTestLimiter.clear(`${session.user.id}:${clientIp(request)}`);
    audit(request, session, "admin.email.settings_updated", {
      detail: {
        enabled: settings.enabled,
        host: settings.host,
        port: settings.port,
        security: settings.security,
        authenticated: Boolean(settings.username),
      },
    });
    sendJson(response, 200, { settings }); return true;
  }
  if (pathname === "/api/admin/email/test-connection" && request.method === "POST") {
    const limit = emailConnectionTestLimiter.consume(`${session.user.id}:${clientIp(request)}`);
    if (!limit.allowed) {
      sendJson(response, 429, { error: "too_many_email_connection_tests" }, { "retry-after": String(limit.retryAfter) });
      return true;
    }
    try {
      const result = await email.testConnection();
      audit(request, session, "admin.email.connection_tested", { detail: { success: true } });
      sendJson(response, 200, { result, settings: store.getEmailSettings() });
    } catch (error) {
      audit(request, session, "admin.email.connection_tested", { detail: { success: false, error: error.code || "smtp_connection_failed" } });
      throw error;
    }
    return true;
  }
  if (pathname === "/api/admin/email/test-message" && request.method === "POST") {
    const limit = emailMessageTestLimiter.consume(`${session.user.id}:${clientIp(request)}`);
    if (!limit.allowed) {
      sendJson(response, 429, { error: "too_many_test_emails" }, { "retry-after": String(limit.retryAfter) });
      return true;
    }
    const input = await readBody(request);
    try {
      const job = await email.sendTest(input.recipient, session.user.id);
      audit(request, session, "admin.email.test_delivered", { detail: { jobId: job.id, recipient: job.to } });
      sendJson(response, 200, { job });
    } catch (error) {
      audit(request, session, "admin.email.test_failed", {
        detail: { jobId: error.job?.id || null, error: error.code || "email_delivery_failed" },
      });
      throw error;
    }
    return true;
  }
  if (pathname === "/api/admin/customers" && request.method === "POST") {
    const customer = store.createCustomer(await readBody(request));
    audit(request, session, "admin.customer.created", { customerId: customer.id, detail: { name: customer.name } });
    sendJson(response, 201, { customer }); return true;
  }
  if (pathname === "/api/admin/users" && request.method === "POST") {
    const user = await store.createUser(await readBody(request));
    audit(request, session, "admin.user.created", { customerId: user.customerId, detail: { email: user.email, role: user.role } });
    sendJson(response, 201, { user }); return true;
  }
  if (pathname === "/api/admin/invitations" && request.method === "POST") {
    const limit = invitationLimiter.consume(`${session.user.id}:${clientIp(request)}`);
    if (!limit.allowed) {
      sendJson(response, 429, { error: "too_many_invitations" }, { "retry-after": String(limit.retryAfter) });
      return true;
    }
    accountEmailSettings();
    const input = await readBody(request);
    if ((input.role || "customer") === "customer" && store.getCustomer(input.customerId)?.status !== "active") {
      sendJson(response, 409, { error: "customer_disabled" });
      return true;
    }
    const user = await store.createInvitedUser(input);
    const accountToken = store.createAccountToken({
      userId: user.id,
      purpose: "invitation",
      createdBy: session.user.id,
      requestedIp: clientIp(request),
    });
    const job = queueInvitationEmail(user, accountToken, session.user.id);
    audit(request, session, "admin.user.invited", {
      customerId: user.customerId,
      detail: { targetUserId: user.id, email: user.email, role: user.role, emailJobId: job.id },
    });
    sendJson(response, 201, {
      user: store.listUsers().find((entry) => entry.id === user.id),
      invitation: { expiresAt: accountToken.expiresAt, emailJobId: job.id },
    });
    return true;
  }
  if (pathname === "/api/admin/clusters" && request.method === "POST") {
    const cluster = store.createCluster(await readBody(request));
    audit(request, session, "admin.cluster.created", { detail: { clusterId: cluster.id } });
    sendJson(response, 201, { cluster }); return true;
  }
  if (pathname === "/api/admin/iso-policies" && request.method === "POST") {
    const input = await readBody(request);
    const candidates = config.allowDemoData && input.clusterId === "demo-eu"
      ? [{ storageId: "local", nodes: ["pve-ber-01", "pve-ber-02", "pve-ber-03"] }]
      : await proxmox.forCluster(input.clusterId).listIsoStorageCandidates();
    if (!candidates.some((candidate) => candidate.storageId === input.storageId)) {
      sendJson(response, 409, { error: "iso_storage_unavailable", message: "That storage is not enabled for ISO images on this cluster." }); return true;
    }
    const policy = store.createIsoPolicy(input);
    audit(request, session, "admin.iso_policy.created", { detail: { policyId: policy.id, clusterId: policy.clusterId, storageId: policy.storageId } });
    sendJson(response, 201, { policy }); return true;
  }
  if (pathname === "/api/admin/assignments" && request.method === "POST") {
    const input = await readBody(request);
    const resource = store.assignResource(input);
    audit(request, session, "admin.resource.assigned", {
      customerId: input.customerId,
      resourceId: input.resourceId,
      detail: { permissions: resource.permissions, snapshotLimit: resource.snapshotLimit, alertPolicy: resource.alertPolicy },
    });
    sendJson(response, 201, { resource }); return true;
  }

  let match = pathname.match(/^\/api\/admin\/customers\/([^/]+)$/);
  if (match && request.method === "PATCH") {
    const customer = store.updateCustomer(decodeURIComponent(match[1]), await readBody(request));
    audit(request, session, "admin.customer.updated", { customerId: customer.id });
    sendJson(response, 200, { customer }); return true;
  }
  if (match && request.method === "DELETE") {
    const id = decodeURIComponent(match[1]);
    audit(request, session, "admin.customer.deleted", { customerId: id });
    store.deleteCustomer(id);
    sendJson(response, 204, null); return true;
  }
  match = pathname.match(/^\/api\/admin\/users\/([^/]+)$/);
  if (match && request.method === "PATCH") {
    const user = store.updateUser(decodeURIComponent(match[1]), await readBody(request));
    audit(request, session, "admin.user.updated", { customerId: user.customerId, detail: { targetUserId: user.id } });
    sendJson(response, 200, { user }); return true;
  }
  if (match && request.method === "DELETE") {
    const id = decodeURIComponent(match[1]);
    store.deleteUser(id);
    audit(request, session, "admin.user.deleted", { detail: { targetUserId: id } });
    sendJson(response, 204, null); return true;
  }
  match = pathname.match(/^\/api\/admin\/users\/([^/]+)\/password$/);
  if (match && request.method === "POST") {
    await store.updatePassword(decodeURIComponent(match[1]), (await readBody(request)).password);
    audit(request, session, "admin.user.password_reset", { detail: { targetUserId: decodeURIComponent(match[1]) } });
    sendJson(response, 204, null); return true;
  }
  match = pathname.match(/^\/api\/admin\/users\/([^/]+)\/mfa\/reset$/);
  if (match && request.method === "POST") {
    if (!requireSecurityActionRate(request, response, session.user.id)) return true;
    const targetUserId = decodeURIComponent(match[1]);
    if (targetUserId === session.user.id) {
      sendJson(response, 409, { error: "mfa_self_reset_forbidden" });
      return true;
    }
    const { currentPassword } = await readBody(request);
    if (!(await requireCurrentPassword(response, session.user.id, currentPassword))) return true;
    const target = store.getUserForAuth(targetUserId);
    if (!target) { sendJson(response, 404, { error: "user_not_found" }); return true; }
    if (!target.mfa_enabled) { sendJson(response, 409, { error: "mfa_not_enabled" }); return true; }
    store.disableMfa(targetUserId);
    const revokedSessions = store.revokeUserSessions(targetUserId);
    audit(request, session, "admin.user.mfa_reset", {
      customerId: target.customer_id,
      detail: { targetUserId, revokedSessions },
    });
    queueSecurityNotice(target, {
      title: "Two-factor authentication reset",
      message: "An administrator reset two-factor authentication for your account. Your active sessions were signed out.",
      ipAddress: clientIp(request),
    });
    sendJson(response, 200, { reset: true });
    return true;
  }
  match = pathname.match(/^\/api\/admin\/users\/([^/]+)\/invitation\/(resend|revoke)$/);
  if (match && request.method === "POST") {
    const targetUserId = decodeURIComponent(match[1]);
    const operation = match[2];
    const target = store.getUserForAuth(targetUserId);
    if (!target) { sendJson(response, 404, { error: "user_not_found" }); return true; }
    if (target.password_set) { sendJson(response, 409, { error: "invitation_not_pending" }); return true; }
    if (operation === "revoke") {
      const revoked = store.revokeAccountTokens(targetUserId, "invitation");
      audit(request, session, "admin.user.invitation_revoked", {
        customerId: target.customer_id,
        detail: { targetUserId, revoked },
      });
      sendJson(response, 200, { revoked });
      return true;
    }
    const limit = invitationLimiter.consume(`${session.user.id}:${clientIp(request)}`);
    if (!limit.allowed) {
      sendJson(response, 429, { error: "too_many_invitations" }, { "retry-after": String(limit.retryAfter) });
      return true;
    }
    accountEmailSettings();
    const accountToken = store.createAccountToken({
      userId: targetUserId,
      purpose: "invitation",
      createdBy: session.user.id,
      requestedIp: clientIp(request),
    });
    const publicTarget = store.listUsers().find((entry) => entry.id === targetUserId);
    const job = queueInvitationEmail(publicTarget, accountToken, session.user.id);
    audit(request, session, "admin.user.invitation_resent", {
      customerId: target.customer_id,
      detail: { targetUserId, emailJobId: job.id },
    });
    sendJson(response, 200, {
      user: store.listUsers().find((entry) => entry.id === targetUserId),
      invitation: { expiresAt: accountToken.expiresAt, emailJobId: job.id },
    });
    return true;
  }
  match = pathname.match(/^\/api\/admin\/clusters\/([^/]+)\/iso-storage-candidates$/);
  if (match && request.method === "GET") {
    const clusterId = decodeURIComponent(match[1]);
    const candidates = config.allowDemoData && clusterId === "demo-eu"
      ? [{ storageId: "local", type: "dir", shared: true, nodes: ["pve-ber-01", "pve-ber-02", "pve-ber-03"], totalBytes: 536870912000, availableBytes: 322122547200 }]
      : await proxmox.forCluster(clusterId).listIsoStorageCandidates();
    sendJson(response, 200, { candidates }); return true;
  }
  match = pathname.match(/^\/api\/admin\/clusters\/([^/]+)$/);
  if (match && request.method === "PATCH") {
    const cluster = store.updateCluster(decodeURIComponent(match[1]), await readBody(request));
    audit(request, session, "admin.cluster.updated", { detail: { clusterId: cluster.id } });
    sendJson(response, 200, { cluster }); return true;
  }
  match = pathname.match(/^\/api\/admin\/clusters\/([^/]+)\/(test|sync)$/);
  if (match && request.method === "POST") {
    const clusterId = decodeURIComponent(match[1]);
    const operation = match[2];
    const result = operation === "sync"
      ? await syncCluster(clusterId)
      : (config.allowDemoData && clusterId === "demo-eu" ? { version: "9.0", nodes: [{ name: "pve-ber-01", status: "online" }] } : await proxmox.forCluster(clusterId).testConnection());
    audit(request, session, `admin.cluster.${operation}ed`, { detail: { clusterId } });
    sendJson(response, 200, operation === "sync" ? { resources: result.length } : { result }); return true;
  }
  match = pathname.match(/^\/api\/admin\/iso-policies\/([^/]+)$/);
  if (match && request.method === "PATCH") {
    const policy = store.updateIsoPolicy(decodeURIComponent(match[1]), await readBody(request));
    audit(request, session, "admin.iso_policy.updated", { detail: { policyId: policy.id, status: policy.status } });
    sendJson(response, 200, { policy }); return true;
  }
  if (match && request.method === "DELETE") {
    const policyId = decodeURIComponent(match[1]);
    store.deleteIsoPolicy(policyId);
    audit(request, session, "admin.iso_policy.deleted", { detail: { policyId } });
    sendJson(response, 204, null); return true;
  }
  match = pathname.match(/^\/api\/admin\/resources\/(.+)\/assignment$/);
  if (match && request.method === "PATCH") {
    const resourceId = decodeURIComponent(match[1]);
    const resource = store.updateAssignment(resourceId, await readBody(request));
    audit(request, session, "admin.assignment.updated", {
      customerId: resource.customerId,
      resourceId,
      detail: { permissions: resource.permissions, snapshotLimit: resource.snapshotLimit, alertPolicy: resource.alertPolicy },
    });
    sendJson(response, 200, { resource }); return true;
  }
  if (match && request.method === "DELETE") {
    const resourceId = decodeURIComponent(match[1]);
    const existing = store.getResource(resourceId);
    store.unassignResource(resourceId);
    audit(request, session, "admin.resource.unassigned", { customerId: existing?.customerId, resourceId });
    sendJson(response, 204, null); return true;
  }
  match = pathname.match(/^\/api\/admin\/email\/jobs\/([^/]+)\/retry$/);
  if (match && request.method === "POST") {
    const job = store.retryEmailJob(decodeURIComponent(match[1]));
    audit(request, session, "admin.email.delivery_retried", { detail: { jobId: job.id } });
    void email.processDue();
    sendJson(response, 202, { job }); return true;
  }

  sendJson(response, 404, { error: "not_found" });
  return true;
}

async function routeCustomer(request, response, pathname) {
  const session = requireSession(request, response);
  if (!session) return true;
  const user = session.user;

  if (pathname === "/api/v1/dashboard" && request.method === "GET") {
    const resources = user.role === "admin"
      ? store.listResources()
      : store.listResources({ customerId: user.customerId }).filter((resource) => resource.permissions.includes("view_status"));
    sendJson(response, 200, {
      mode: config.allowDemoData ? "demo" : "live", user, summary: summarize(resources), resources,
      activity: store.listAudit(user.customerId, { limit: 10 }),
      tasks: store.listTasks(user, { limit: 12 }),
      notifications: store.listNotifications(user.id, { limit: 8 }),
      notificationPreferences: store.getNotificationPreferences(user.id),
      emailDeliveryAvailable: store.getEmailSettings().enabled,
      security: {
        mfa: store.getMfaStatus(user.id),
        sessions: store.listSessions(user.id, { currentIdHash: session.idHash }),
      },
      capabilities: {
        directAssignments: true,
        proxmoxPools: false,
        consoleTickets: true,
        customerIsoMedia: true,
        notificationCenter: true,
        twoFactorAuthentication: true,
        customerInvitations: true,
        passwordRecovery: true,
      },
    });
    return true;
  }

  if (pathname === "/api/v1/notifications" && request.method === "GET") {
    const search = new URL(request.url, `http://${request.headers.host || "localhost"}`).searchParams;
    sendJson(response, 200, {
      notifications: store.listNotifications(user.id, {
        limit: search.get("limit") || 50,
        offset: search.get("offset") || 0,
      }),
      preferences: store.getNotificationPreferences(user.id),
      emailDeliveryAvailable: store.getEmailSettings().enabled,
    });
    return true;
  }
  if (pathname === "/api/v1/notifications/preferences" && request.method === "PATCH") {
    if (!requireCsrf(request, response, session)) return true;
    const preferences = store.updateNotificationPreferences(user.id, await readBody(request));
    audit(request, session, "notifications.preferences_updated", {
      detail: {
        inAppEnabled: preferences.inAppEnabled,
        emailEnabled: preferences.emailEnabled,
      },
    });
    sendJson(response, 200, { preferences }); return true;
  }
  if (pathname === "/api/v1/notifications/read-all" && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    const changed = store.markAllNotificationsRead(user.id);
    sendJson(response, 200, { changed }); return true;
  }
  let notificationMatch = pathname.match(/^\/api\/v1\/notifications\/([^/]+)\/read$/);
  if (notificationMatch && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    store.markNotificationRead(decodeURIComponent(notificationMatch[1]), user.id);
    sendJson(response, 204, null); return true;
  }

  let match = pathname.match(/^\/api\/v1\/console\/session\/([^/]+)$/);
  if (match && request.method === "GET") {
    const token = decodeURIComponent(match[1]);
    const consoleSession = store.getConsoleSession(token, user.id);
    if (!consoleSession || !resourceFor(user, consoleSession.resourceId, "console")) {
      sendJson(response, 404, { error: "console_session_not_found" }); return true;
    }
    sendJson(response, 200, {
      resource: { name: consoleSession.name, node: consoleSession.node, type: consoleSession.type, vmid: consoleSession.vmid },
      expiresAt: consoleSession.expiresAt,
      demo: config.allowDemoData && consoleSession.clusterId === "demo-eu",
      websocketUrl: `/api/v1/console/ws/${encodeURIComponent(token)}`,
      credentials: { password: consoleSession.password },
    });
    return true;
  }

  match = pathname.match(/^\/api\/v1\/resources\/(.+)\/media$/);
  if (match && request.method === "GET") {
    const resourceId = decodeURIComponent(match[1]);
    const resource = requireResource(response, user, resourceId, "iso_view");
    if (!resource) return true;
    requireQemu(resource);
    const owner = isoCustomer(resource, user);
    const pending = store.listIsoImages(owner.scope, { clusterId: resource.clusterId })
      .filter((image) => ["processing", "deleting"].includes(image.status));
    if (!isDemo(resource) && pending.length) {
      await Promise.allSettled(pending.map(async (image) => {
        const row = store.getIsoImageRow(image.id, owner.scope);
        try { await refreshIsoOperation(row); }
        catch (error) { log("error", "iso_task_refresh_delayed", { imageId: image.id, error: error.code || error.message }); }
      }));
    }
    const policies = store.listIsoPolicies({ clusterId: resource.clusterId, activeOnly: true }).map((policy) => {
      const usedBytes = store.getIsoUsage(owner.id, policy.id);
      return { ...policy, usedBytes, remainingBytes: Math.max(0, policy.customerQuotaBytes - usedBytes) };
    });
    let mountedRow = store.getActiveIsoMountForResource(resourceId);
    let bootRow = store.getActiveIsoBootOverrideForResource(resourceId);
    if (mountedRow && mountedRow.customer_id !== owner.id) mountedRow = null;
    if (mountedRow && !isDemo(resource)) {
      try {
        const cdroms = await clientFor(resource).getQemuCdroms(resource);
        if (!cdroms.some((drive) => drive.slot === mountedRow.drive_slot && drive.volumeId === mountedRow.volume_id)) {
          if (bootRow) {
            try {
              await restoreIsoBootOverride(resourceId, { finalStatus: "cancelled" });
              store.writeAudit({
                customerId: owner.id,
                userId: null,
                actorRole: "system",
                action: "resource.iso_boot.cancelled",
                resourceId,
                detail: { bootOverrideId: bootRow.id, reason: "cdrom_changed_outside_nimbus" },
              });
            } catch (error) {
              log("error", "iso_boot_restore_delayed", { resourceId, error: error.code || error.message });
            }
          }
          store.ejectIsoMount(mountedRow.id);
          mountedRow = null;
          bootRow = store.getActiveIsoBootOverrideForResource(resourceId);
        }
      } catch (error) {
        log("error", "iso_mount_state_refresh_delayed", { resourceId, error: error.code || error.message });
      }
    }
    const mounted = mountedRow ? {
      id: mountedRow.id,
      isoImageId: mountedRow.iso_image_id,
      resourceId: mountedRow.resource_id,
      driveSlot: mountedRow.drive_slot,
      status: mountedRow.status,
      fileName: mountedRow.file_name,
      originalName: mountedRow.original_name,
      mountedAt: mountedRow.mounted_at,
    } : null;
    sendJson(response, 200, {
      policies,
      images: store.listIsoImages(owner.scope, { clusterId: resource.clusterId }),
      mounted,
      boot: store.publicIsoBootOverride(bootRow) || null,
    });
    return true;
  }

  match = pathname.match(/^\/api\/v1\/resources\/(.+)\/media\/upload$/);
  if (match && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    if (!String(request.headers["content-type"] || "").toLowerCase().startsWith("application/octet-stream")) {
      sendJson(response, 415, { error: "invalid_content_type", message: "ISO uploads must use application/octet-stream." }); return true;
    }
    const limit = uploadLimiter.consume(user.id);
    if (!limit.allowed) { sendJson(response, 429, { error: "too_many_uploads" }, { "retry-after": String(limit.retryAfter) }); return true; }
    const resourceId = decodeURIComponent(match[1]);
    const resource = requireResource(response, user, resourceId, "iso_upload");
    if (!resource) return true;
    requireQemu(resource);
    const owner = isoCustomer(resource, user);
    const upload = isoUploadMetadata(request);
    if (request.headers["content-length"] && Number(request.headers["content-length"]) !== upload.sizeBytes) {
      sendJson(response, 400, { error: "iso_upload_size_mismatch", message: "The upload size did not match the selected file." }); return true;
    }
    const search = new URL(request.url, `http://${request.headers.host || "localhost"}`).searchParams;
    const policy = store.getIsoPolicy(search.get("policyId"));
    if (!policy || policy.status !== "active" || policy.clusterId !== resource.clusterId) {
      sendJson(response, 404, { error: "iso_policy_not_found" }); return true;
    }
    if (upload.sizeBytes > policy.maxUploadBytes) {
      sendJson(response, 413, { error: "iso_too_large", message: "The ISO is larger than this storage policy allows." }); return true;
    }
    if (!isDemo(resource)) await clientFor(resource).requireIsoStorage(resource.node, policy.storageId);
    const usedBytes = store.getIsoUsage(owner.id, policy.id);
    if (usedBytes + upload.sizeBytes > policy.customerQuotaBytes) {
      sendJson(response, 409, { error: "iso_quota_exceeded", message: "This upload would exceed the customer ISO quota." }); return true;
    }
    const volumeId = `${policy.storageId}:iso/${upload.fileName}`;
    const image = store.createIsoImage({
      customerId: owner.id,
      clusterId: resource.clusterId,
      storagePolicyId: policy.id,
      storageId: policy.storageId,
      node: resource.node,
      volumeId,
      fileName: upload.fileName,
      originalName: upload.originalName,
      sizeBytes: upload.sizeBytes,
      createdBy: user.id,
    });
    try {
      const result = isDemo(resource)
        ? await consumeDemoUpload(request, upload.sizeBytes)
        : await clientFor(resource).uploadIso({
          node: resource.node,
          storageId: policy.storageId,
          fileName: upload.fileName,
          source: request,
          expectedBytes: upload.sizeBytes,
          signal: AbortSignal.timeout(config.isoUploadTimeoutMs),
        });
      const upid = typeof result.result === "string" && result.result.startsWith("UPID:") ? result.result : null;
      const updated = store.updateIsoImage(image.id, {
        status: upid ? "processing" : "ready",
        sha256: result.sha256,
        sizeBytes: result.bytes,
        operationUpid: upid,
        errorCode: null,
      });
      audit(request, session, "resource.iso.uploaded", {
        customerId: owner.id,
        resourceId,
        detail: { imageId: image.id, storageId: policy.storageId, fileName: upload.originalName, sizeBytes: upload.sizeBytes },
      });
      sendJson(response, upid ? 202 : 201, { image: updated }); return true;
    } catch (error) {
      store.updateIsoImage(image.id, { status: "error", operationUpid: null, errorCode: error.code || "iso_upload_failed" });
      audit(request, session, "resource.iso.upload_failed", {
        customerId: owner.id,
        resourceId,
        detail: { imageId: image.id, storageId: policy.storageId, error: error.code || "iso_upload_failed" },
      });
      throw error;
    }
  }

  match = pathname.match(/^\/api\/v1\/resources\/(.+)\/media\/mount$/);
  if (match && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    const resourceId = decodeURIComponent(match[1]);
    const resource = requireResource(response, user, resourceId, "iso_mount");
    if (!resource) return true;
    requireQemu(resource);
    const owner = isoCustomer(resource, user);
    if (store.getActiveIsoMountForResource(resourceId)) {
      sendJson(response, 409, { error: "cdrom_in_use", message: "Eject the currently mounted ISO first." }); return true;
    }
    const { isoImageId } = await readBody(request);
    const imageRow = store.getIsoImageRow(String(isoImageId || ""), owner.scope);
    if (!imageRow) { sendJson(response, 404, { error: "iso_not_found" }); return true; }
    if (imageRow.status !== "ready" || imageRow.cluster_id !== resource.clusterId) {
      sendJson(response, 409, { error: "iso_not_ready" }); return true;
    }
    const policy = store.getIsoPolicy(imageRow.storage_policy_id);
    if (!policy || policy.status !== "active") { sendJson(response, 409, { error: "iso_policy_disabled" }); return true; }
    let mounted;
    if (isDemo(resource)) {
      mounted = { slot: "ide2", volumeId: imageRow.volume_id };
    } else {
      const storage = await clientFor(resource).requireIsoStorage(resource.node, imageRow.storage_id);
      if (!storage.shared && imageRow.node !== resource.node) {
        sendJson(response, 409, { error: "iso_not_on_node", message: "This ISO was uploaded to node-local storage on another node." }); return true;
      }
      mounted = await clientFor(resource).mountIso(resource, imageRow.volume_id);
    }
    const mount = store.createIsoMount({ isoImageId: imageRow.id, resourceId, driveSlot: mounted.slot, createdBy: user.id });
    audit(request, session, "resource.iso.mounted", {
      customerId: owner.id,
      resourceId,
      detail: { imageId: imageRow.id, driveSlot: mounted.slot },
    });
    sendJson(response, 201, { mount }); return true;
  }

  match = pathname.match(/^\/api\/v1\/resources\/(.+)\/media\/eject$/);
  if (match && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    const resourceId = decodeURIComponent(match[1]);
    const resource = requireResource(response, user, resourceId, "iso_mount");
    if (!resource) return true;
    requireQemu(resource);
    const owner = isoCustomer(resource, user);
    const mounted = store.getActiveIsoMountForResource(resourceId);
    if (!mounted || mounted.customer_id !== owner.id) { sendJson(response, 404, { error: "iso_mount_not_found" }); return true; }
    const activeBoot = store.getActiveIsoBootOverrideForResource(resourceId);
    if (activeBoot) {
      const restored = await restoreIsoBootOverride(resourceId, { finalStatus: "cancelled" });
      audit(request, session, "resource.iso_boot.cancelled", {
        customerId: owner.id,
        resourceId,
        detail: { bootOverrideId: restored.id, reason: "iso_ejected" },
      });
    }
    if (!isDemo(resource)) {
      await clientFor(resource).ejectIso(resource, { slot: mounted.drive_slot, volumeId: mounted.volume_id });
    }
    const mount = store.ejectIsoMount(mounted.id);
    audit(request, session, "resource.iso.ejected", {
      customerId: owner.id,
      resourceId,
      detail: { imageId: mounted.iso_image_id, driveSlot: mounted.drive_slot },
    });
    sendJson(response, 200, { mount }); return true;
  }

  match = pathname.match(/^\/api\/v1\/resources\/(.+)\/media\/boot-once$/);
  if (match && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    const resourceId = decodeURIComponent(match[1]);
    const resource = requireResource(response, user, resourceId, "iso_boot");
    if (!resource) return true;
    requireQemu(resource);
    const owner = isoCustomer(resource, user);
    const mounted = store.getActiveIsoMountForResource(resourceId);
    if (!mounted || mounted.customer_id !== owner.id) {
      sendJson(response, 409, { error: "iso_mount_not_found", message: "Mount a customer-owned ISO before scheduling an ISO boot." }); return true;
    }
    if (store.getActiveIsoBootOverrideForResource(resourceId)) {
      sendJson(response, 409, { error: "iso_boot_already_armed" }); return true;
    }
    const prepared = isDemo(resource)
      ? { slot: mounted.drive_slot, originalBoot: "order=scsi0", armedBoot: `order=${mounted.drive_slot};scsi0` }
      : await clientFor(resource).prepareIsoBootOnce(resource, { slot: mounted.drive_slot, volumeId: mounted.volume_id });
    const pending = store.createIsoBootOverride({
      resourceId,
      isoMountId: mounted.id,
      driveSlot: prepared.slot,
      originalBoot: prepared.originalBoot,
      armedBoot: prepared.armedBoot,
      createdBy: user.id,
    });
    try {
      if (!isDemo(resource)) await clientFor(resource).applyIsoBootOnce(resource, prepared.armedBoot);
      const armed = store.updateIsoBootOverride(pending.id, { status: "armed", errorCode: null, armedAt: Date.now() });
      audit(request, session, "resource.iso_boot.armed", {
        customerId: owner.id,
        resourceId,
        detail: { bootOverrideId: armed.id, isoMountId: mounted.id, driveSlot: mounted.drive_slot },
      });
      sendJson(response, 201, { boot: store.publicIsoBootOverride(armed) }); return true;
    } catch (error) {
      store.updateIsoBootOverride(pending.id, { status: "error", errorCode: error.code || "iso_boot_arm_failed" });
      audit(request, session, "resource.iso_boot.arm_failed", {
        customerId: owner.id,
        resourceId,
        detail: { bootOverrideId: pending.id, error: error.code || "iso_boot_arm_failed" },
      });
      throw error;
    }
  }

  match = pathname.match(/^\/api\/v1\/resources\/(.+)\/media\/boot-once\/cancel$/);
  if (match && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    const resourceId = decodeURIComponent(match[1]);
    const resource = requireResource(response, user, resourceId, "iso_boot");
    if (!resource) return true;
    requireQemu(resource);
    const owner = isoCustomer(resource, user);
    const active = store.getActiveIsoBootOverrideForResource(resourceId);
    if (!active) { sendJson(response, 404, { error: "iso_boot_not_found" }); return true; }
    const restored = await restoreIsoBootOverride(resourceId, { finalStatus: "cancelled" });
    audit(request, session, "resource.iso_boot.cancelled", {
      customerId: owner.id,
      resourceId,
      detail: { bootOverrideId: restored.id, reason: "user_cancelled" },
    });
    sendJson(response, 200, { boot: store.publicIsoBootOverride(restored) }); return true;
  }

  match = pathname.match(/^\/api\/v1\/resources\/(.+)\/media\/([^/]+)$/);
  if (match && request.method === "DELETE") {
    if (!requireCsrf(request, response, session)) return true;
    const resourceId = decodeURIComponent(match[1]);
    const deleteAuthorized = resourceFor(user, resourceId, "iso_delete");
    const uploadAuthorized = resourceFor(user, resourceId, "iso_upload");
    const resource = deleteAuthorized || uploadAuthorized;
    if (!resource) { sendJson(response, 404, { error: "resource_not_found" }); return true; }
    requireQemu(resource);
    const owner = isoCustomer(resource, user);
    const imageRow = store.getIsoImageRow(decodeURIComponent(match[2]), owner.scope);
    if (!imageRow) { sendJson(response, 404, { error: "iso_not_found" }); return true; }
    if (imageRow.status !== "error" && !deleteAuthorized) { sendJson(response, 404, { error: "resource_not_found" }); return true; }
    const policy = store.getIsoPolicy(imageRow.storage_policy_id);
    if (imageRow.status !== "error" && !policy?.allowDelete) { sendJson(response, 403, { error: "iso_delete_disabled" }); return true; }
    if (store.hasActiveIsoMount(imageRow.id)) { sendJson(response, 409, { error: "iso_mounted" }); return true; }
    if (["uploading", "processing", "deleting"].includes(imageRow.status)) {
      sendJson(response, 409, { error: "iso_operation_in_progress" }); return true;
    }
    let upid = null;
    if (imageRow.status !== "error" && !isDemo(resource)) {
      const result = await clientFor(resource).deleteIso({
        node: imageRow.node,
        storageId: imageRow.storage_id,
        volumeId: imageRow.volume_id,
      });
      upid = typeof result === "string" && result.startsWith("UPID:") ? result : null;
    }
    const image = store.updateIsoImage(imageRow.id, {
      status: upid ? "deleting" : "deleted",
      operationUpid: upid,
      errorCode: null,
    });
    audit(request, session, "resource.iso.deleted", {
      customerId: owner.id,
      resourceId,
      detail: { imageId: imageRow.id, storageId: imageRow.storage_id },
    });
    sendJson(response, upid ? 202 : 200, { image }); return true;
  }

  match = pathname.match(/^\/api\/v1\/resources\/(.+)\/actions$/);
  if (match && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    const limit = actionLimiter.consume(user.id);
    if (!limit.allowed) { sendJson(response, 429, { error: "too_many_actions" }, { "retry-after": String(limit.retryAfter) }); return true; }
    const { action } = await readBody(request);
    const permission = String(action || "");
    if (!new Set(["start", "stop", "shutdown", "reboot", "reset", "suspend", "resume"]).has(permission)) {
      sendJson(response, 400, { error: "invalid_action" }); return true;
    }
    const resourceId = decodeURIComponent(match[1]);
    const resource = requireResource(response, user, resourceId, permission);
    if (!resource) return true;
    const idempotencyKey = String(request.headers["idempotency-key"] || "").slice(0, 120) || null;
    const existing = store.getTaskByIdempotency(user.id, idempotencyKey);
    if (existing) { sendJson(response, 202, { task: store.publicTask(existing), duplicate: true }); return true; }
    const active = await blockingTask(resourceId);
    if (active) {
      sendJson(response, 409, { error: "resource_task_in_progress", task: store.publicTask(active) });
      return true;
    }
    audit(request, session, `resource.${permission}.requested`, { customerId: resource.customerId || user.customerId, resourceId, detail: { clusterId: resource.clusterId, node: resource.node, vmid: resource.vmid } });
    if (isDemo(resource)) {
      const nextStatus = ["stop", "shutdown"].includes(permission) ? "stopped" : permission === "suspend" ? "suspended" : "running";
      const updatedResource = store.setResourceStatus(resourceId, nextStatus);
      if (["start", "reboot", "reset"].includes(permission)) {
        const activeBoot = store.getActiveIsoBootOverrideForResource(resourceId);
        if (activeBoot) {
          const restored = await restoreIsoBootOverride(resourceId);
          store.writeAudit({
            customerId: resource.customerId || user.customerId,
            userId: null,
            actorRole: "system",
            action: "resource.iso_boot.restored",
            resourceId,
            detail: { bootOverrideId: restored.id, reason: `demo_${permission}` },
          });
        }
      }
      await notifications.actionCompleted({
        id: `demo-${randomUUID()}`,
        customerId: resource.customerId || user.customerId,
        resourceId,
        action: permission,
        exitStatus: "OK",
      });
      sendJson(response, 200, { completed: true, resource: updatedResource }); return true;
    }
    const upid = await clientFor(resource).performAction(resource, permission);
    const task = store.createTask({ customerId: resource.customerId || user.customerId, userId: user.id, clusterId: resource.clusterId, node: resource.node, upid, resourceId, action: permission, idempotencyKey });
    sendJson(response, 202, { completed: false, task }); return true;
  }

  match = pathname.match(/^\/api\/v1\/resources\/(.+)\/console$/);
  if (match && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    const resourceId = decodeURIComponent(match[1]);
    const resource = requireResource(response, user, resourceId, "console");
    if (!resource) return true;
    let consoleSession;
    if (isDemo(resource)) {
      consoleSession = store.createConsoleSession({ userId: user.id, resourceId, ticket: "demo-console-ticket", port: 5900 });
    } else {
      const ticket = await clientFor(resource).createConsoleTicket(resource);
      consoleSession = store.createConsoleSession({ userId: user.id, resourceId, ticket: ticket.ticket, port: ticket.port });
    }
    audit(request, session, "resource.console.ticket_created", { customerId: resource.customerId || user.customerId, resourceId });
    sendJson(response, 201, { launchUrl: `/console.html?token=${encodeURIComponent(consoleSession.token)}`, expiresAt: consoleSession.expiresAt }); return true;
  }

  match = pathname.match(/^\/api\/v1\/resources\/(.+)\/snapshots$/);
  if (match && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    const rate = actionLimiter.consume(user.id);
    if (!rate.allowed) { sendJson(response, 429, { error: "too_many_actions" }, { "retry-after": String(rate.retryAfter) }); return true; }
    const resourceId = decodeURIComponent(match[1]);
    const resource = requireResource(response, user, resourceId, "snapshot_create");
    if (!resource) return true;
    const input = await readBody(request);
    const name = snapshotName(input.name);
    const description = String(input.description || "").trim().slice(0, 500);
    const includeMemory = input.includeMemory === true;
    if (includeMemory && resource.type !== "qemu") {
      sendJson(response, 400, { error: "snapshot_memory_qemu_only" }); return true;
    }
    if (includeMemory && resource.status !== "running") {
      sendJson(response, 409, { error: "snapshot_memory_requires_running" }); return true;
    }
    requireSnapshotMediaClear(resourceId);
    const idempotencyKey = String(request.headers["idempotency-key"] || "").slice(0, 120) || null;
    const existing = store.getTaskByIdempotency(user.id, idempotencyKey);
    if (existing) { sendJson(response, 202, { completed: false, task: store.publicTask(existing), duplicate: true }); return true; }
    const active = await blockingTask(resourceId);
    if (active) {
      sendJson(response, 409, { error: "resource_task_in_progress", task: store.publicTask(active) });
      return true;
    }
    const snapshots = isDemo(resource) ? demoSnapshotsFor(resource) : await clientFor(resource).listSnapshots(resource);
    if (snapshots.some((snapshot) => snapshot.name === name)) {
      sendJson(response, 409, { error: "snapshot_exists" }); return true;
    }
    if (snapshots.length >= resource.snapshotLimit) {
      sendJson(response, 409, { error: "snapshot_limit_reached", limit: resource.snapshotLimit }); return true;
    }
    audit(request, session, "resource.snapshot.create_requested", {
      customerId: resource.customerId || user.customerId,
      resourceId,
      detail: { name, includeMemory },
    });
    if (isDemo(resource)) {
      snapshots.unshift({ name, description, parent: snapshots[0]?.name || null, createdAt: Date.now(), includesMemory: includeMemory });
      audit(request, session, "resource.snapshot.created", { customerId: resource.customerId || user.customerId, resourceId, detail: { name, demo: true } });
      await notifications.actionCompleted({
        id: `demo-${randomUUID()}`,
        customerId: resource.customerId || user.customerId,
        resourceId,
        action: "snapshot_create",
        exitStatus: "OK",
      });
      sendJson(response, 200, { completed: true }); return true;
    }
    const upid = await clientFor(resource).createSnapshot(resource, { name, description, includeMemory });
    const task = store.createTask({
      customerId: resource.customerId || user.customerId,
      userId: user.id,
      clusterId: resource.clusterId,
      node: resource.node,
      upid,
      resourceId,
      action: "snapshot_create",
      idempotencyKey,
    });
    sendJson(response, 202, { completed: false, task }); return true;
  }
  match = pathname.match(/^\/api\/v1\/resources\/(.+)\/snapshots\/([^/]+)\/(restore|delete)$/);
  if (match && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    const rate = actionLimiter.consume(user.id);
    if (!rate.allowed) { sendJson(response, 429, { error: "too_many_actions" }, { "retry-after": String(rate.retryAfter) }); return true; }
    const resourceId = decodeURIComponent(match[1]);
    const selectedSnapshot = snapshotName(decodeURIComponent(match[2]));
    const operation = match[3];
    const resource = requireResource(response, user, resourceId, operation === "restore" ? "snapshot_restore" : "snapshot_delete");
    if (!resource) return true;
    const input = await readBody(request);
    if (String(input.confirmName || "") !== selectedSnapshot) {
      sendJson(response, 400, { error: "snapshot_confirmation_mismatch" }); return true;
    }
    if (operation === "restore") requireSnapshotMediaClear(resourceId);
    const idempotencyKey = String(request.headers["idempotency-key"] || "").slice(0, 120) || null;
    const existing = store.getTaskByIdempotency(user.id, idempotencyKey);
    if (existing) { sendJson(response, 202, { completed: false, task: store.publicTask(existing), duplicate: true }); return true; }
    const active = await blockingTask(resourceId);
    if (active) {
      sendJson(response, 409, { error: "resource_task_in_progress", task: store.publicTask(active) });
      return true;
    }
    const snapshots = isDemo(resource) ? demoSnapshotsFor(resource) : await clientFor(resource).listSnapshots(resource);
    const snapshotIndex = snapshots.findIndex((snapshot) => snapshot.name === selectedSnapshot);
    if (snapshotIndex < 0) {
      sendJson(response, 404, { error: "snapshot_not_found" }); return true;
    }
    audit(request, session, `resource.snapshot.${operation}_requested`, {
      customerId: resource.customerId || user.customerId,
      resourceId,
      detail: { name: selectedSnapshot },
    });
    if (isDemo(resource)) {
      if (operation === "delete") snapshots.splice(snapshotIndex, 1);
      audit(request, session, `resource.snapshot.${operation === "restore" ? "restored" : "deleted"}`, {
        customerId: resource.customerId || user.customerId,
        resourceId,
        detail: { name: selectedSnapshot, demo: true },
      });
      await notifications.actionCompleted({
        id: `demo-${randomUUID()}`,
        customerId: resource.customerId || user.customerId,
        resourceId,
        action: `snapshot_${operation}`,
        exitStatus: "OK",
      });
      sendJson(response, 200, { completed: true }); return true;
    }
    const upid = operation === "restore"
      ? await clientFor(resource).restoreSnapshot(resource, selectedSnapshot)
      : await clientFor(resource).deleteSnapshot(resource, selectedSnapshot);
    const task = store.createTask({
      customerId: resource.customerId || user.customerId,
      userId: user.id,
      clusterId: resource.clusterId,
      node: resource.node,
      upid,
      resourceId,
      action: `snapshot_${operation}`,
      idempotencyKey,
    });
    sendJson(response, 202, { completed: false, task }); return true;
  }

  match = pathname.match(/^\/api\/v1\/resources\/(.+)\/config$/);
  if (match && request.method === "PUT") {
    if (!requireCsrf(request, response, session)) return true;
    const resourceId = decodeURIComponent(match[1]);
    const resource = requireResource(response, user, resourceId, "config_change");
    if (!resource) return true;
    const input = await readBody(request);
    if (!isDemo(resource)) await clientFor(resource).updateConfig(resource, input);
    audit(request, session, "resource.config.updated", { customerId: resource.customerId || user.customerId, resourceId, detail: { fields: Object.keys(input) } });
    sendJson(response, 202, { accepted: true }); return true;
  }

  match = pathname.match(/^\/api\/v1\/resources\/(.+)\/history$/);
  if (match && request.method === "GET") {
    const resourceId = decodeURIComponent(match[1]);
    const resource = requireResource(response, user, resourceId, "view_usage");
    if (!resource) return true;
    const timeframe = new URL(request.url, `http://${request.headers.host || "localhost"}`).searchParams.get("timeframe") || "day";
    const history = isDemo(resource)
      ? demoInstanceHistory(resource, timeframe)
      : await clientFor(resource).getHistory([resource], timeframe);
    sendJson(response, 200, { history }); return true;
  }

  match = pathname.match(/^\/api\/v1\/resources\/(.+)$/);
  if (match && request.method === "GET") {
    const resourceId = decodeURIComponent(match[1]);
    const resource = requireResource(response, user, resourceId, "view_status");
    if (!resource) return true;
    if (isDemo(resource)) {
      const snapshots = canViewSnapshots(resource, user) ? demoSnapshotsFor(resource) : [];
      sendJson(response, 200, {
        instance: resource,
        config: { cores: resource.vcpu, memory: resource.memory * 1024, onboot: 1 },
        network: { status: "available", primaryIp: resource.ip, addresses: resource.ip ? [{ address: resource.ip, family: "ipv4", interface: "eth0" }] : [] },
        snapshots,
        snapshotPolicy: snapshotPolicy(resource, snapshots),
        tasks: store.listTasks(user, { resourceId, limit: 12 }),
      });
      return true;
    }
    const details = await clientFor(resource).getInstanceDetails(resource);
    if (!resource.permissions.includes("view_config") && user.role !== "admin") details.config = {};
    if (!canViewSnapshots(resource, user)) details.snapshots = [];
    details.snapshotPolicy = snapshotPolicy(resource, details.snapshots);
    details.tasks = store.listTasks(user, { resourceId, limit: 12 });
    sendJson(response, 200, details); return true;
  }

  if (pathname === "/api/v1/tasks" && request.method === "GET") {
    const search = new URL(request.url, `http://${request.headers.host || "localhost"}`).searchParams;
    const resourceId = search.get("resourceId");
    if (resourceId && !resourceFor(user, resourceId, "view_status")) {
      sendJson(response, 404, { error: "resource_not_found" }); return true;
    }
    sendJson(response, 200, { tasks: store.listTasks(user, { resourceId, limit: search.get("limit") || 20 }) });
    return true;
  }

  match = pathname.match(/^\/api\/v1\/tasks\/([^/]+)$/);
  if (match && request.method === "GET") {
    const task = store.getTask(decodeURIComponent(match[1]), user);
    if (!task) { sendJson(response, 404, { error: "task_not_found" }); return true; }
    try {
      const result = await refreshStoredTask(task);
      if (result.transitioned) await recordTaskCompletion(result.task);
      sendJson(response, 200, { task: store.publicTask(result.task), completed: result.completed });
    } catch (error) {
      log("error", "task_poll_failed", { taskId: task.id, error: error.code || error.message });
      sendJson(response, 200, { task: store.publicTask(task), completed: false, pollingDelayed: true });
    }
    return true;
  }

  if (pathname === "/api/v1/security/mfa/setup" && request.method === "POST") {
    if (!requireCsrf(request, response, session) || !requireSecurityActionRate(request, response, user.id)) return true;
    const { currentPassword } = await readBody(request);
    const authUser = await requireCurrentPassword(response, user.id, currentPassword);
    if (!authUser) return true;
    const enrollment = createTotpEnrollment(authUser.email);
    const setup = store.saveMfaSetup(user.id, enrollment.secret);
    const qrCode = await QRCode.toDataURL(enrollment.uri, {
      errorCorrectionLevel: "M",
      margin: 2,
      width: 240,
      color: { dark: "#11182aff", light: "#ffffffff" },
    });
    audit(request, session, "security.mfa_setup_started");
    sendJson(response, 200, {
      enrollment: {
        secret: enrollment.secret,
        uri: enrollment.uri,
        qrCode,
        expiresAt: setup.expiresAt,
      },
    });
    return true;
  }
  if (pathname === "/api/v1/security/mfa/confirm" && request.method === "POST") {
    if (!requireCsrf(request, response, session) || !requireSecurityActionRate(request, response, user.id)) return true;
    const { code } = await readBody(request);
    const secret = store.getMfaSecret(user.id, { pending: true });
    if (!secret) { sendJson(response, 409, { error: "mfa_setup_expired" }); return true; }
    if (!verifyTotp(secret, code)) { sendJson(response, 400, { error: "invalid_mfa_code" }); return true; }
    const recoveryCodes = generateRecoveryCodes();
    const mfa = store.enableMfa(user.id, recoveryCodes);
    const revokedSessions = store.deleteOtherSessions(user.id, session.idHash);
    const authUser = store.getUserForAuth(user.id);
    audit(request, session, "security.mfa_enabled", { detail: { revokedSessions } });
    queueSecurityNotice(authUser, {
      title: "Two-factor authentication enabled",
      message: "Authenticator-based two-factor authentication is now protecting your Nimbus Direct account.",
      ipAddress: clientIp(request),
    });
    sendJson(response, 200, { mfa, recoveryCodes });
    return true;
  }
  if (pathname === "/api/v1/security/mfa/disable" && request.method === "POST") {
    if (!requireCsrf(request, response, session) || !requireSecurityActionRate(request, response, user.id)) return true;
    const { currentPassword, code } = await readBody(request);
    const authUser = await requireCurrentPassword(response, user.id, currentPassword);
    if (!authUser) return true;
    const verification = verifyMfaCredential(user.id, code);
    if (!verification.valid) { sendJson(response, 400, { error: "invalid_mfa_code" }); return true; }
    const mfa = store.disableMfa(user.id);
    const revokedSessions = store.deleteOtherSessions(user.id, session.idHash);
    audit(request, session, "security.mfa_disabled", { detail: { revokedSessions, recoveryCode: verification.recoveryCode } });
    queueSecurityNotice(authUser, {
      title: "Two-factor authentication disabled",
      message: "Two-factor authentication was removed from your Nimbus Direct account.",
      ipAddress: clientIp(request),
    });
    sendJson(response, 200, { mfa });
    return true;
  }
  if (pathname === "/api/v1/security/mfa/recovery-codes" && request.method === "POST") {
    if (!requireCsrf(request, response, session) || !requireSecurityActionRate(request, response, user.id)) return true;
    const { currentPassword, code } = await readBody(request);
    const authUser = await requireCurrentPassword(response, user.id, currentPassword);
    if (!authUser) return true;
    const secret = store.getMfaSecret(user.id);
    if (!secret) { sendJson(response, 409, { error: "mfa_not_enabled" }); return true; }
    if (!verifyTotp(secret, code)) { sendJson(response, 400, { error: "invalid_mfa_code" }); return true; }
    const recoveryCodes = generateRecoveryCodes();
    const mfa = store.replaceRecoveryCodes(user.id, recoveryCodes);
    audit(request, session, "security.mfa_recovery_codes_regenerated");
    queueSecurityNotice(authUser, {
      title: "New recovery codes generated",
      message: "Your previous recovery codes are no longer valid. Store the new set somewhere safe.",
      ipAddress: clientIp(request),
    });
    sendJson(response, 200, { mfa, recoveryCodes });
    return true;
  }
  if (pathname === "/api/v1/security/sessions/revoke-others" && request.method === "POST") {
    if (!requireCsrf(request, response, session) || !requireSecurityActionRate(request, response, user.id)) return true;
    const { currentPassword } = await readBody(request);
    if (!(await requireCurrentPassword(response, user.id, currentPassword))) return true;
    const revoked = store.deleteOtherSessions(user.id, session.idHash);
    audit(request, session, "security.sessions_revoked", { detail: { revoked } });
    sendJson(response, 200, {
      revoked,
      sessions: store.listSessions(user.id, { currentIdHash: session.idHash }),
    });
    return true;
  }
  match = pathname.match(/^\/api\/v1\/security\/sessions\/([^/]+)$/);
  if (match && request.method === "DELETE") {
    if (!requireCsrf(request, response, session) || !requireSecurityActionRate(request, response, user.id)) return true;
    const idHash = decodeURIComponent(match[1]);
    const current = idHash === session.idHash;
    if (!store.deleteUserSession(user.id, idHash)) {
      sendJson(response, 404, { error: "session_not_found" });
      return true;
    }
    audit(request, session, "security.session_revoked", { detail: { current } });
    sendJson(response, 204, null, current
      ? { "set-cookie": sessionCookie("", { secure: config.secureCookies, maxAge: 0, name: cookieName }) }
      : {});
    return true;
  }

  if (pathname === "/api/v1/profile" && request.method === "PATCH") {
    if (!requireCsrf(request, response, session)) return true;
    const user = store.updateProfile(session.user.id, (await readBody(request)).displayName);
    audit(request, session, "profile.updated");
    sendJson(response, 200, { user }); return true;
  }
  if (pathname === "/api/v1/password" && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    const { currentPassword, password } = await readBody(request);
    const authUser = store.getUserForAuth(session.user.id);
    if (!(await verifyPassword(String(currentPassword || ""), authUser.password_hash))) {
      sendJson(response, 400, { error: "current_password_invalid" }); return true;
    }
    await store.updatePassword(session.user.id, password);
    audit(request, session, "password.updated");
    sendJson(response, 204, null, { "set-cookie": sessionCookie("", { secure: config.secureCookies, maxAge: 0, name: cookieName }) }); return true;
  }

  sendJson(response, 404, { error: "not_found" });
  return true;
}

async function routeApi(request, response, pathname) {
  if (pathname === "/api/health" && request.method === "GET") { sendJson(response, 200, { ok: true }); return; }
  if (pathname === "/api/ready" && request.method === "GET") { sendJson(response, store.hasUsers() ? 200 : 503, { ready: store.hasUsers() }); return; }
  if (pathname.startsWith("/api/auth/") && await routeAuth(request, response, pathname)) return;
  if (pathname.startsWith("/api/admin/")) { await routeAdmin(request, response, pathname); return; }
  await routeCustomer(request, response, pathname);
}

const mime = {
  ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml", ".webmanifest": "application/manifest+json", ".txt": "text/plain; charset=utf-8",
};

const server = createServer(async (request, response) => {
  const requestId = randomUUID();
  response.setHeader("x-request-id", requestId);
  try {
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    const startedAt = Date.now();
    if (url.pathname.startsWith("/api/")) {
      log("info", "api_request_started", { requestId, method: request.method, path: url.pathname });
      response.once("finish", () => log("info", "api_request", {
        requestId,
        method: request.method,
        path: url.pathname,
        status: response.statusCode,
        durationMs: Date.now() - startedAt,
      }));
    }
    if (url.pathname.startsWith("/api/")) return await routeApi(request, response, url.pathname);
    const vendorPrefix = "/vendor/novnc/";
    const isNoVnc = url.pathname.startsWith(vendorPrefix);
    const requested = url.pathname === "/" ? "index.html" : (isNoVnc ? url.pathname.slice(vendorPrefix.length) : url.pathname.slice(1));
    const staticRoot = isNoVnc ? noVncRoot : root;
    const file = resolve(staticRoot, requested);
    if (file !== staticRoot && !file.startsWith(`${staticRoot}${sep}`)) return sendJson(response, 403, { error: "forbidden" });
    const contents = await readFile(file);
    response.writeHead(200, { ...headers, "content-type": mime[extname(file)] || "application/octet-stream", "cache-control": "no-store" });
    if (request.method === "HEAD") response.end(); else response.end(contents);
  } catch (error) {
    const status = error.status || (error.code === "ENOENT" ? 404 : 500);
    if (status >= 500) {
      let safePath = "unknown";
      try { safePath = new URL(request.url, `http://${request.headers.host || "localhost"}`).pathname; } catch { /* omit malformed URLs */ }
      log("error", "request_failed", { requestId, method: request.method, path: safePath, error: error.message, code: error.code });
    }
    if (!response.headersSent) sendJson(response, status, { error: error.code || (status === 404 ? "not_found" : "request_failed"), message: status < 500 ? error.message : undefined, requestId });
    else response.end();
  }
});

function rejectUpgrade(socket, status = "401 Unauthorized") {
  if (!socket.destroyed) socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
}

server.on("upgrade", (request, socket, head) => {
  void (async () => {
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    const match = url.pathname.match(/^\/api\/v1\/console\/ws\/([^/]+)$/);
    if (!match) return rejectUpgrade(socket, "404 Not Found");
    const session = currentSession(request);
    if (!session) return rejectUpgrade(socket);
    const token = decodeURIComponent(match[1]);
    const pending = store.getConsoleSession(token, session.user.id);
    if (!pending || !resourceFor(session.user, pending.resourceId, "console")) return rejectUpgrade(socket, "404 Not Found");
    if (config.allowDemoData && pending.clusterId === "demo-eu") return rejectUpgrade(socket, "409 Conflict");
    const consoleSession = store.consumeConsoleSession(token, session.user.id);
    if (!consoleSession) return rejectUpgrade(socket, "404 Not Found");
    const resource = store.getResource(consoleSession.resource_id);
    const connection = store.getClusterConnection(resource.clusterId);
    if (!connection) return rejectUpgrade(socket, "503 Service Unavailable");

    const target = new URL(connection.baseUrl);
    const remote = connectTls({
      host: target.hostname,
      port: Number(target.port || 443),
      servername: target.hostname,
      rejectUnauthorized: true,
    });
    const remotePath = `/api2/json/nodes/${encodeURIComponent(resource.node)}/${resource.type}/${resource.vmid}/vncwebsocket?port=${consoleSession.port}&vncticket=${encodeURIComponent(consoleSession.ticket)}`;
    remote.once("secureConnect", () => {
      remote.write([
        `GET ${remotePath} HTTP/1.1`,
        `Host: ${target.host}`,
        "Connection: Upgrade",
        "Upgrade: websocket",
        `Sec-WebSocket-Key: ${request.headers["sec-websocket-key"] || ""}`,
        `Sec-WebSocket-Version: ${request.headers["sec-websocket-version"] || "13"}`,
        `Sec-WebSocket-Protocol: ${request.headers["sec-websocket-protocol"] || "binary"}`,
        `Origin: ${target.origin}`,
        `Authorization: PVEAPIToken=${connection.tokenId}=${connection.tokenSecret}`,
        "\r\n",
      ].join("\r\n"));
    });

    let responseBuffer = Buffer.alloc(0);
    const onHandshake = (chunk) => {
      responseBuffer = Buffer.concat([responseBuffer, chunk]);
      if (responseBuffer.length > 64 * 1024) {
        remote.destroy(); rejectUpgrade(socket, "502 Bad Gateway"); return;
      }
      const boundary = responseBuffer.indexOf("\r\n\r\n");
      if (boundary < 0) return;
      remote.off("data", onHandshake);
      const header = responseBuffer.subarray(0, boundary + 4);
      if (!/^HTTP\/1\.[01] 101\b/.test(header.toString("latin1"))) {
        remote.destroy(); rejectUpgrade(socket, "502 Bad Gateway"); return;
      }
      socket.write(header);
      const remainder = responseBuffer.subarray(boundary + 4);
      if (remainder.length) socket.write(remainder);
      if (head?.length) remote.write(head);
      remote.pipe(socket);
      socket.pipe(remote);
    };
    remote.on("data", onHandshake);
    remote.once("error", () => rejectUpgrade(socket, "502 Bad Gateway"));
    socket.once("error", () => remote.destroy());
    socket.once("close", () => remote.destroy());
  })().catch(() => rejectUpgrade(socket, "500 Internal Server Error"));
});

server.listen(config.port, config.host, () => {
  log("info", "server_started", { host: config.host, port: config.port, production: config.production, bootstrapped, demo: config.allowDemoData });
});

email.start();
const syncTimer = setInterval(syncAllClusters, config.syncIntervalMs);
syncTimer.unref();

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => { email.stop(); clearInterval(syncTimer); store.close(); process.exit(0); }));
}
