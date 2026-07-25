import { mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import {
  decryptSecret,
  encryptSecret,
  hashPassword,
  hashToken,
  normalizeEmail,
  randomToken,
  safeEqual,
} from "./security.mjs";
import { normalizeMfaCode } from "./mfa.mjs";

export const ASSIGNMENT_PERMISSIONS = [
  "view_status", "start", "stop", "shutdown", "reboot", "reset", "suspend", "resume",
  "console", "view_config", "view_usage", "snapshot_create", "snapshot_restore", "snapshot_delete",
  "config_change", "iso_view", "iso_upload", "iso_mount", "iso_boot", "iso_delete",
];

export const DEFAULT_PERMISSIONS = [
  "view_status", "start", "stop", "shutdown", "reboot", "suspend", "resume", "console",
  "view_config", "view_usage",
];

export const DEFAULT_SNAPSHOT_LIMIT = 3;
export const DEFAULT_ALERT_POLICY = Object.freeze({
  enabled: false,
  offline: true,
  cpu: true,
  memory: true,
  storage: true,
  cpuThreshold: 90,
  memoryThreshold: 90,
  storageThreshold: 90,
  sustainMinutes: 5,
  cooldownMinutes: 60,
});

function problem(message, code = "invalid_input", status = 400) {
  return Object.assign(new Error(message), { status, code });
}

function parseJson(value, fallback = {}) {
  try { return JSON.parse(value || "") ?? fallback; } catch { return fallback; }
}

function publicCustomer(row) {
  return row && {
    id: row.id,
    name: row.name,
    status: row.status,
    supportEmail: row.support_email || "",
    planName: row.plan_name || "Managed infrastructure",
    resourceCount: Number(row.resource_count || 0),
    userCount: Number(row.user_count || 0),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function publicUser(row) {
  return row && {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    role: row.role,
    status: row.status,
    customerId: row.customer_id || null,
    customerName: row.customer_name || null,
    supportEmail: row.support_email || "",
    planName: row.plan_name || "Managed infrastructure",
    mfaEnabled: Boolean(row.mfa_enabled),
    passwordSet: row.password_set === undefined ? true : Boolean(row.password_set),
    invitationExpiresAt: row.invitation_expires_at || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function publicSession(row, currentIdHash = null) {
  return row && {
    id: row.id_hash,
    current: row.id_hash === currentIdHash,
    ipAddress: row.ip_address || "Unknown",
    userAgent: row.user_agent || "Unknown device",
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
    expiresAt: row.expires_at,
  };
}

function publicCluster(row) {
  return row && {
    id: row.id,
    name: row.name,
    apiUrl: row.api_url,
    status: row.status,
    verifyTls: Boolean(row.verify_tls),
    credentialConfigured: Boolean(row.token_id),
    tokenIdHint: row.token_id ? String(row.token_id).replace(/[^!@]{3,}(?=[!@]|$)/g, "•••") : null,
    resourceCount: Number(row.resource_count || 0),
    nodeCount: Number(row.node_count || 0),
    lastSyncAt: row.last_sync_at || null,
    lastError: row.last_error || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function publicResource(row) {
  if (!row) return null;
  const permissions = Array.isArray(row.permissions)
    ? row.permissions
    : String(row.permissions || "").split(",").filter(Boolean);
  const metadata = parseJson(row.metadata, {});
  return {
    id: row.id,
    clusterId: row.cluster_id,
    clusterName: row.cluster_name || row.cluster_id,
    node: row.node,
    type: row.type,
    vmid: row.vmid,
    name: row.name || `${row.type}-${row.vmid}`,
    status: row.status || "unknown",
    vcpu: Number(row.vcpu || 0),
    memory: Number(row.memory || 0),
    memoryUsed: Number(row.memory_used || 0),
    storage: Number(row.storage || 0),
    storageUsed: Number(row.storage_used || 0),
    cpu: Number(row.cpu || 0),
    uptime: Number(row.uptime || 0),
    ip: row.ip || null,
    lastSeenAt: row.last_seen_at || null,
    stale: Boolean(row.stale),
    customerId: row.customer_id || null,
    customerName: row.customer_name || null,
    assignmentId: row.assignment_id || null,
    assignmentStatus: row.assignment_status || null,
    displayName: row.display_name || null,
    snapshotLimit: Number(row.snapshot_limit ?? DEFAULT_SNAPSHOT_LIMIT),
    alertPolicy: {
      enabled: Boolean(row.alert_policy_enabled),
      offline: row.alert_offline === null || row.alert_offline === undefined ? DEFAULT_ALERT_POLICY.offline : Boolean(row.alert_offline),
      cpu: row.alert_cpu === null || row.alert_cpu === undefined ? DEFAULT_ALERT_POLICY.cpu : Boolean(row.alert_cpu),
      memory: row.alert_memory === null || row.alert_memory === undefined ? DEFAULT_ALERT_POLICY.memory : Boolean(row.alert_memory),
      storage: row.alert_storage === null || row.alert_storage === undefined ? DEFAULT_ALERT_POLICY.storage : Boolean(row.alert_storage),
      cpuThreshold: Number(row.cpu_threshold ?? DEFAULT_ALERT_POLICY.cpuThreshold),
      memoryThreshold: Number(row.memory_threshold ?? DEFAULT_ALERT_POLICY.memoryThreshold),
      storageThreshold: Number(row.storage_threshold ?? DEFAULT_ALERT_POLICY.storageThreshold),
      sustainMinutes: Math.round(Number(row.sustain_seconds ?? DEFAULT_ALERT_POLICY.sustainMinutes * 60) / 60),
      cooldownMinutes: Math.round(Number(row.cooldown_seconds ?? DEFAULT_ALERT_POLICY.cooldownMinutes * 60) / 60),
    },
    permissions,
    metadata,
  };
}

function publicNotificationPreferences(row, userId = null) {
  return {
    userId: row?.user_id || userId,
    inAppEnabled: row ? Boolean(row.in_app_enabled) : true,
    emailEnabled: row ? Boolean(row.email_enabled) : false,
    actionSuccess: row ? Boolean(row.action_success) : true,
    actionFailure: row ? Boolean(row.action_failure) : true,
    infrastructureAlerts: row ? Boolean(row.infrastructure_alerts) : true,
    resolutionAlerts: row ? Boolean(row.resolution_alerts) : true,
    updatedAt: row?.updated_at || null,
  };
}

function publicNotification(row) {
  return row && {
    id: row.notification_id || row.id,
    eventId: row.event_id || row.id,
    customerId: row.customer_id,
    resourceId: row.resource_id || null,
    resourceName: row.resource_name || null,
    resourceType: row.resource_type || null,
    vmid: row.vmid === null || row.vmid === undefined ? null : Number(row.vmid),
    category: row.category,
    type: row.event_type,
    severity: row.severity,
    title: row.title,
    message: row.message,
    readAt: row.read_at || null,
    emailJobId: row.email_job_id || null,
    createdAt: row.created_at,
  };
}

function publicTask(row) {
  if (!row) return null;
  const completed = Boolean(row.completed_at) || row.status === "stopped";
  const success = completed ? row.exit_status === "OK" : null;
  const messages = {
    snapshot_create: {
      running: "Proxmox is creating the snapshot.",
      success: "Snapshot created successfully.",
      failed: "Proxmox reported that snapshot creation failed.",
    },
    snapshot_restore: {
      running: "Proxmox is restoring the snapshot.",
      success: "Snapshot restored successfully.",
      failed: "Proxmox reported that snapshot restoration failed.",
    },
    snapshot_delete: {
      running: "Proxmox is deleting the snapshot.",
      success: "Snapshot deleted successfully.",
      failed: "Proxmox reported that snapshot deletion failed.",
    },
  };
  const taskMessages = messages[row.action];
  return {
    id: row.id,
    resourceId: row.resource_id,
    node: row.node,
    action: row.action,
    status: row.status,
    state: completed ? (success ? "success" : "failed") : "running",
    completed,
    success,
    message: taskMessages
      ? taskMessages[completed ? (success ? "success" : "failed") : "running"]
      : (completed
          ? (success ? "Completed successfully." : "Proxmox reported that the task failed.")
          : "Proxmox is processing this action."),
    createdAt: row.created_at,
    completedAt: row.completed_at || null,
    lastCheckedAt: row.last_checked_at || null,
  };
}

function publicIsoPolicy(row) {
  return row && {
    id: row.id,
    clusterId: row.cluster_id,
    clusterName: row.cluster_name || row.cluster_id,
    storageId: row.storage_id,
    displayName: row.display_name,
    status: row.status,
    maxUploadBytes: Number(row.max_upload_bytes),
    customerQuotaBytes: Number(row.customer_quota_bytes),
    allowDelete: Boolean(row.allow_delete),
    imageCount: Number(row.image_count || 0),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function publicIsoImage(row) {
  return row && {
    id: row.id,
    customerId: row.customer_id || null,
    clusterId: row.cluster_id,
    storagePolicyId: row.storage_policy_id || null,
    storageId: row.storage_id,
    node: row.node,
    fileName: row.file_name,
    originalName: row.original_name,
    sizeBytes: Number(row.size_bytes || 0),
    sha256: row.sha256 || null,
    status: row.status,
    error: row.status === "error" ? "Proxmox could not finish this ISO operation." : null,
    allowDelete: Boolean(row.allow_delete),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function publicIsoMount(row) {
  return row && {
    id: row.id,
    isoImageId: row.iso_image_id,
    resourceId: row.resource_id,
    driveSlot: row.drive_slot,
    status: row.status,
    fileName: row.file_name || null,
    originalName: row.original_name || null,
    mountedAt: row.mounted_at,
    ejectedAt: row.ejected_at || null,
  };
}

function publicIsoBootOverride(row) {
  return row && {
    id: row.id,
    resourceId: row.resource_id,
    isoMountId: row.iso_mount_id,
    driveSlot: row.drive_slot,
    status: row.status,
    error: row.error_code ? "Nimbus could not safely restore the original boot order." : null,
    armedAt: row.armed_at || null,
    restoredAt: row.restored_at || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function publicEmailSettings(row) {
  if (!row) {
    return {
      configured: false,
      enabled: false,
      host: "",
      port: 587,
      security: "starttls",
      username: "",
      passwordConfigured: false,
      fromName: "Nimbus Direct",
      fromEmail: "",
      replyTo: "",
      appUrl: "",
      lastTestAt: null,
      lastTestStatus: null,
      lastTestErrorCode: null,
      updatedAt: null,
    };
  }
  return {
    configured: true,
    enabled: Boolean(row.enabled),
    host: row.host,
    port: Number(row.port),
    security: row.security,
    username: row.username || "",
    passwordConfigured: Boolean(row.password_encrypted),
    fromName: row.from_name,
    fromEmail: row.from_email,
    replyTo: row.reply_to || "",
    appUrl: row.app_url || "",
    lastTestAt: row.last_test_at || null,
    lastTestStatus: row.last_test_status || null,
    lastTestErrorCode: row.last_test_error_code || null,
    updatedAt: row.updated_at,
  };
}

function publicEmailJob(row) {
  return row && {
    id: row.id,
    to: row.to_email,
    subject: row.subject,
    category: row.category,
    status: row.status,
    attempts: Number(row.attempts),
    maxAttempts: Number(row.max_attempts),
    nextAttemptAt: row.next_attempt_at,
    lastErrorCode: row.last_error_code || null,
    providerMessageId: row.provider_message_id || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    sentAt: row.sent_at || null,
  };
}

function normalizeId(value, label) {
  const id = String(value || "").trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]{1,63}$/.test(id)) throw problem(`${label} ID must be 2-64 lowercase characters`);
  return id;
}

function normalizePermissions(values) {
  const requested = new Set(Array.isArray(values) ? values : DEFAULT_PERMISSIONS);
  return ASSIGNMENT_PERMISSIONS.filter((permission) => requested.has(permission));
}

function normalizeStorageId(value) {
  const storageId = String(value || "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(storageId)) throw problem("Storage ID is invalid", "invalid_storage_id");
  return storageId;
}

function normalizeByteLimit(value, label) {
  const bytes = Number(value);
  if (!Number.isSafeInteger(bytes) || bytes < 1024 * 1024) throw problem(`${label} must be at least 1 MB`);
  return bytes;
}

function normalizeSnapshotLimit(value) {
  const limit = Number(value);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50) {
    throw problem("Snapshot limit must be a whole number between 1 and 50", "invalid_snapshot_limit");
  }
  return limit;
}

function normalizeAlertPolicy(input = {}, existing = null) {
  const current = existing ? {
    enabled: Boolean(existing.enabled),
    offline: Boolean(existing.alert_offline),
    cpu: Boolean(existing.alert_cpu),
    memory: Boolean(existing.alert_memory),
    storage: Boolean(existing.alert_storage),
    cpuThreshold: Number(existing.cpu_threshold),
    memoryThreshold: Number(existing.memory_threshold),
    storageThreshold: Number(existing.storage_threshold),
    sustainMinutes: Number(existing.sustain_seconds) / 60,
    cooldownMinutes: Number(existing.cooldown_seconds) / 60,
  } : DEFAULT_ALERT_POLICY;
  const integer = (value, fallback, minimum, maximum, label) => {
    const result = value === undefined ? fallback : Number(value);
    if (!Number.isSafeInteger(result) || result < minimum || result > maximum) {
      throw problem(`${label} must be a whole number between ${minimum} and ${maximum}`, "invalid_alert_policy");
    }
    return result;
  };
  return {
    enabled: input.enabled === undefined ? current.enabled : Boolean(input.enabled),
    offline: input.offline === undefined ? current.offline : Boolean(input.offline),
    cpu: input.cpu === undefined ? current.cpu : Boolean(input.cpu),
    memory: input.memory === undefined ? current.memory : Boolean(input.memory),
    storage: input.storage === undefined ? current.storage : Boolean(input.storage),
    cpuThreshold: integer(input.cpuThreshold, current.cpuThreshold, 50, 100, "CPU threshold"),
    memoryThreshold: integer(input.memoryThreshold, current.memoryThreshold, 50, 100, "Memory threshold"),
    storageThreshold: integer(input.storageThreshold, current.storageThreshold, 50, 100, "Storage threshold"),
    sustainMinutes: integer(input.sustainMinutes, current.sustainMinutes, 1, 1440, "Alert duration"),
    cooldownMinutes: integer(input.cooldownMinutes, current.cooldownMinutes, 5, 10080, "Alert cooldown"),
  };
}

function normalizeMailbox(value, label, { optional = false } = {}) {
  const email = normalizeEmail(value);
  if (optional && !email) return "";
  if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email) || email.length > 254 || /[\r\n]/.test(email)) {
    throw problem(`${label} is invalid`, "invalid_email_address");
  }
  return email;
}

function normalizeEmailSettings(input, existing = null) {
  const host = String(input.host ?? existing?.host ?? "").trim().toLowerCase();
  if (!host || host.length > 253 || /[\s/@]/.test(host) || !/^[A-Za-z0-9._:[\]-]+$/.test(host)) {
    throw problem("SMTP hostname is invalid", "invalid_smtp_host");
  }
  const port = Number(input.port ?? existing?.port ?? 587);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw problem("SMTP port must be between 1 and 65535", "invalid_smtp_port");
  const security = String(input.security ?? existing?.security ?? "starttls").toLowerCase();
  if (!["tls", "starttls"].includes(security)) throw problem("Choose TLS or STARTTLS encryption", "invalid_smtp_security");
  const username = String(input.username ?? existing?.username ?? "").trim();
  if (username.length > 255 || /[\r\n]/.test(username)) throw problem("SMTP username is invalid", "invalid_smtp_username");
  const fromName = String(input.fromName ?? existing?.from_name ?? "Nimbus Direct").trim();
  if (!fromName || fromName.length > 100 || /[\r\n]/.test(fromName)) throw problem("Sender name must contain 1-100 characters", "invalid_sender_name");
  const fromEmail = normalizeMailbox(input.fromEmail ?? existing?.from_email, "Sender address");
  const replyTo = normalizeMailbox(input.replyTo ?? existing?.reply_to, "Reply-to address", { optional: true });
  const appUrlValue = String(input.appUrl ?? existing?.app_url ?? "").trim();
  let appUrl = "";
  if (appUrlValue) {
    let parsed;
    try { parsed = new URL(appUrlValue); } catch { throw problem("Panel URL is invalid", "invalid_app_url"); }
    const localHttp = parsed.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(parsed.hostname);
    if (parsed.protocol !== "https:" && !localHttp) throw problem("Panel URL must use HTTPS", "invalid_app_url");
    if (parsed.username || parsed.password || parsed.search || parsed.hash) throw problem("Panel URL must not contain credentials, a query, or a fragment", "invalid_app_url");
    appUrl = parsed.toString().replace(/\/$/, "");
  }
  return {
    enabled: input.enabled === undefined ? Boolean(existing?.enabled) : Boolean(input.enabled),
    host,
    port,
    security,
    username,
    fromName,
    fromEmail,
    replyTo,
    appUrl,
  };
}

function customerSelect(where = "") {
  return `SELECT c.*,
    (SELECT COUNT(*) FROM customer_resource_assignments a WHERE a.customer_id=c.id AND a.status='active') AS resource_count,
    (SELECT COUNT(*) FROM users u WHERE u.customer_id=c.id) AS user_count
    FROM customers c ${where}`;
}

function userSelect(where = "") {
  return `SELECT u.*,c.name AS customer_name,c.status AS customer_status,c.support_email,c.plan_name,
    CASE WHEN m.enabled=1 THEN 1 ELSE 0 END AS mfa_enabled,
    (SELECT MAX(t.expires_at) FROM account_tokens t
      WHERE t.user_id=u.id AND t.purpose='invitation' AND t.used_at IS NULL
    ) AS invitation_expires_at
    FROM users u
    LEFT JOIN customers c ON c.id=u.customer_id
    LEFT JOIN user_mfa m ON m.user_id=u.id ${where}`;
}

function clusterSelect(where = "") {
  return `SELECT c.*,pc.token_id,
    (SELECT COUNT(*) FROM resources r WHERE r.cluster_id=c.id) AS resource_count,
    (SELECT COUNT(*) FROM proxmox_nodes n WHERE n.cluster_id=c.id) AS node_count
    FROM proxmox_clusters c LEFT JOIN proxmox_credentials pc ON pc.cluster_id=c.id ${where}`;
}

function resourceSelect(where = "") {
  return `SELECT r.*,pc.name AS cluster_name,a.id AS assignment_id,a.customer_id,a.status AS assignment_status,
    a.display_name,a.snapshot_limit,c.name AS customer_name,GROUP_CONCAT(ap.permission) AS permissions,
    rap.enabled AS alert_policy_enabled,rap.alert_offline,rap.alert_cpu,rap.alert_memory,rap.alert_storage,
    rap.cpu_threshold,rap.memory_threshold,rap.storage_threshold,rap.sustain_seconds,rap.cooldown_seconds
    FROM resources r
    JOIN proxmox_clusters pc ON pc.id=r.cluster_id
    LEFT JOIN customer_resource_assignments a ON a.resource_id=r.id AND a.status='active'
    LEFT JOIN customers c ON c.id=a.customer_id
    LEFT JOIN assignment_permissions ap ON ap.assignment_id=a.id AND ap.allowed=1
    LEFT JOIN resource_alert_policies rap ON rap.assignment_id=a.id
    ${where}
    GROUP BY r.id`;
}

function isoPolicySelect(where = "") {
  return `SELECT p.*,c.name AS cluster_name,
    (SELECT COUNT(*) FROM iso_images i WHERE i.storage_policy_id=p.id AND i.status!='deleted') AS image_count
    FROM iso_storage_policies p JOIN proxmox_clusters c ON c.id=p.cluster_id ${where}`;
}

function isoImageSelect(where = "") {
  return `SELECT i.*,p.allow_delete FROM iso_images i
    LEFT JOIN iso_storage_policies p ON p.id=i.storage_policy_id ${where}`;
}

export async function openStore(dataDir, { appSecret = "" } = {}) {
  const directory = dataDir instanceof URL ? fileURLToPath(dataDir) : resolve(String(dataDir));
  await mkdir(directory, { recursive: true });
  const database = new DatabaseSync(join(directory, "nimbus-direct.sqlite"));
  database.exec(`
    PRAGMA journal_mode=WAL;
    PRAGMA foreign_keys=ON;
    PRAGMA busy_timeout=5000;

    CREATE TABLE IF NOT EXISTS customers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
      support_email TEXT NOT NULL DEFAULT '',
      plan_name TEXT NOT NULL DEFAULT 'Managed infrastructure',
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      customer_id TEXT REFERENCES customers(id) ON DELETE CASCADE,
      email TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      password_set INTEGER NOT NULL DEFAULT 1,
      role TEXT NOT NULL CHECK(role IN ('admin','customer')),
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS user_mfa (
      user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      totp_secret_encrypted TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 0,
      recovery_code_hashes TEXT NOT NULL DEFAULT '[]',
      setup_expires_at INTEGER,
      confirmed_at INTEGER,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS proxmox_clusters (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      api_url TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','error')),
      verify_tls INTEGER NOT NULL DEFAULT 1,
      last_sync_at INTEGER,
      last_error TEXT,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS proxmox_credentials (
      id TEXT PRIMARY KEY,
      cluster_id TEXT NOT NULL UNIQUE REFERENCES proxmox_clusters(id) ON DELETE CASCADE,
      token_id TEXT NOT NULL,
      token_secret_encrypted TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS proxmox_nodes (
      cluster_id TEXT NOT NULL REFERENCES proxmox_clusters(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'unknown',
      last_seen_at INTEGER,
      PRIMARY KEY(cluster_id,name)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS resources (
      id TEXT PRIMARY KEY,
      cluster_id TEXT NOT NULL REFERENCES proxmox_clusters(id) ON DELETE CASCADE,
      node TEXT NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('qemu','lxc')),
      vmid INTEGER NOT NULL,
      name TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'unknown',
      vcpu REAL NOT NULL DEFAULT 0,
      memory REAL NOT NULL DEFAULT 0,
      memory_used REAL NOT NULL DEFAULT 0,
      storage REAL NOT NULL DEFAULT 0,
      storage_used REAL NOT NULL DEFAULT 0,
      cpu REAL NOT NULL DEFAULT 0,
      uptime INTEGER NOT NULL DEFAULT 0,
      ip TEXT,
      metadata TEXT NOT NULL DEFAULT '{}',
      stale INTEGER NOT NULL DEFAULT 0,
      last_seen_at INTEGER,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      UNIQUE(cluster_id,type,vmid)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS customer_resource_assignments (
      id TEXT PRIMARY KEY,
      customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
      resource_id TEXT NOT NULL UNIQUE REFERENCES resources(id) ON DELETE CASCADE,
      display_name TEXT,
      snapshot_limit INTEGER NOT NULL DEFAULT 3 CHECK(snapshot_limit BETWEEN 1 AND 50),
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','unassigned')),
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS assignment_permissions (
      assignment_id TEXT NOT NULL REFERENCES customer_resource_assignments(id) ON DELETE CASCADE,
      permission TEXT NOT NULL,
      allowed INTEGER NOT NULL DEFAULT 1,
      PRIMARY KEY(assignment_id,permission)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS sessions (
      id_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      csrf_token TEXT NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      last_seen_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS mfa_login_challenges (
      id_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      attempts INTEGER NOT NULL DEFAULT 0,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS account_tokens (
      id_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      purpose TEXT NOT NULL CHECK(purpose IN ('invitation','password_reset')),
      created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      requested_ip TEXT,
      expires_at INTEGER NOT NULL,
      used_at INTEGER,
      created_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_id TEXT REFERENCES customers(id) ON DELETE SET NULL,
      actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      actor_role TEXT NOT NULL,
      action TEXT NOT NULL,
      resource_id TEXT,
      detail TEXT NOT NULL DEFAULT '{}',
      ip_address TEXT,
      created_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS api_tasks (
      id TEXT PRIMARY KEY,
      customer_id TEXT REFERENCES customers(id) ON DELETE SET NULL,
      user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      cluster_id TEXT NOT NULL REFERENCES proxmox_clusters(id) ON DELETE CASCADE,
      resource_id TEXT NOT NULL,
      node TEXT NOT NULL,
      upid TEXT NOT NULL,
      action TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      exit_status TEXT,
      idempotency_key TEXT,
      completed_at INTEGER,
      last_checked_at INTEGER,
      created_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS iso_storage_policies (
      id TEXT PRIMARY KEY,
      cluster_id TEXT NOT NULL REFERENCES proxmox_clusters(id) ON DELETE CASCADE,
      storage_id TEXT NOT NULL,
      display_name TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
      max_upload_bytes INTEGER NOT NULL,
      customer_quota_bytes INTEGER NOT NULL,
      allow_delete INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      UNIQUE(cluster_id,storage_id)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS iso_images (
      id TEXT PRIMARY KEY,
      customer_id TEXT REFERENCES customers(id) ON DELETE SET NULL,
      cluster_id TEXT NOT NULL REFERENCES proxmox_clusters(id) ON DELETE CASCADE,
      storage_policy_id TEXT REFERENCES iso_storage_policies(id) ON DELETE SET NULL,
      storage_id TEXT NOT NULL,
      node TEXT NOT NULL,
      volume_id TEXT NOT NULL,
      file_name TEXT NOT NULL,
      original_name TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      sha256 TEXT,
      status TEXT NOT NULL CHECK(status IN ('uploading','processing','ready','error','deleting','deleted')),
      operation_upid TEXT,
      error_code TEXT,
      created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS iso_mounts (
      id TEXT PRIMARY KEY,
      iso_image_id TEXT NOT NULL REFERENCES iso_images(id) ON DELETE CASCADE,
      resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
      drive_slot TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('active','ejected')),
      created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      mounted_at INTEGER NOT NULL,
      ejected_at INTEGER,
      created_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS iso_boot_overrides (
      id TEXT PRIMARY KEY,
      resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
      iso_mount_id TEXT NOT NULL REFERENCES iso_mounts(id) ON DELETE CASCADE,
      drive_slot TEXT NOT NULL,
      original_boot TEXT,
      armed_boot TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('arming','armed','restoring','restored','cancelled','error')),
      error_code TEXT,
      created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      armed_at INTEGER,
      restored_at INTEGER,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS email_settings (
      id TEXT PRIMARY KEY CHECK(id='default'),
      enabled INTEGER NOT NULL DEFAULT 0,
      host TEXT NOT NULL,
      port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
      security TEXT NOT NULL CHECK(security IN ('tls','starttls')),
      username TEXT NOT NULL DEFAULT '',
      password_encrypted TEXT,
      from_name TEXT NOT NULL,
      from_email TEXT NOT NULL,
      reply_to TEXT NOT NULL DEFAULT '',
      app_url TEXT NOT NULL DEFAULT '',
      last_test_at INTEGER,
      last_test_status TEXT CHECK(last_test_status IS NULL OR last_test_status IN ('success','failed')),
      last_test_error_code TEXT,
      updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS email_jobs (
      id TEXT PRIMARY KEY,
      to_email TEXT NOT NULL,
      subject TEXT NOT NULL,
      payload_encrypted TEXT NOT NULL,
      category TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('pending','processing','sent','failed')),
      attempts INTEGER NOT NULL DEFAULT 0,
      max_attempts INTEGER NOT NULL DEFAULT 4 CHECK(max_attempts BETWEEN 1 AND 10),
      next_attempt_at INTEGER NOT NULL,
      locked_at INTEGER,
      last_error_code TEXT,
      provider_message_id TEXT,
      created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      sent_at INTEGER
    ) STRICT;

    CREATE TABLE IF NOT EXISTS resource_alert_policies (
      assignment_id TEXT PRIMARY KEY REFERENCES customer_resource_assignments(id) ON DELETE CASCADE,
      enabled INTEGER NOT NULL DEFAULT 0,
      alert_offline INTEGER NOT NULL DEFAULT 1,
      alert_cpu INTEGER NOT NULL DEFAULT 1,
      alert_memory INTEGER NOT NULL DEFAULT 1,
      alert_storage INTEGER NOT NULL DEFAULT 1,
      cpu_threshold INTEGER NOT NULL DEFAULT 90 CHECK(cpu_threshold BETWEEN 50 AND 100),
      memory_threshold INTEGER NOT NULL DEFAULT 90 CHECK(memory_threshold BETWEEN 50 AND 100),
      storage_threshold INTEGER NOT NULL DEFAULT 90 CHECK(storage_threshold BETWEEN 50 AND 100),
      sustain_seconds INTEGER NOT NULL DEFAULT 300 CHECK(sustain_seconds BETWEEN 60 AND 86400),
      cooldown_seconds INTEGER NOT NULL DEFAULT 3600 CHECK(cooldown_seconds BETWEEN 300 AND 604800),
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS alert_states (
      assignment_id TEXT NOT NULL REFERENCES customer_resource_assignments(id) ON DELETE CASCADE,
      alert_type TEXT NOT NULL CHECK(alert_type IN ('offline','cpu','memory','storage')),
      status TEXT NOT NULL DEFAULT 'healthy' CHECK(status IN ('healthy','pending','firing')),
      condition_active INTEGER NOT NULL DEFAULT 0,
      first_observed_at INTEGER,
      last_value REAL,
      last_notified_at INTEGER,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY(assignment_id,alert_type)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS notification_preferences (
      user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      in_app_enabled INTEGER NOT NULL DEFAULT 1,
      email_enabled INTEGER NOT NULL DEFAULT 0,
      action_success INTEGER NOT NULL DEFAULT 1,
      action_failure INTEGER NOT NULL DEFAULT 1,
      infrastructure_alerts INTEGER NOT NULL DEFAULT 1,
      resolution_alerts INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS notification_events (
      id TEXT PRIMARY KEY,
      customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
      resource_id TEXT REFERENCES resources(id) ON DELETE SET NULL,
      category TEXT NOT NULL CHECK(category IN ('action_success','action_failure','infrastructure_alert','resolution')),
      event_type TEXT NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('info','success','warning','critical')),
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      dedup_key TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      event_id TEXT NOT NULL REFERENCES notification_events(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      in_app_visible INTEGER NOT NULL DEFAULT 1,
      email_job_id TEXT REFERENCES email_jobs(id) ON DELETE SET NULL,
      read_at INTEGER,
      created_at INTEGER NOT NULL,
      UNIQUE(event_id,user_id)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS console_sessions (
      id_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
      ticket_encrypted TEXT NOT NULL,
      port INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      used_at INTEGER,
      created_at INTEGER NOT NULL
    ) STRICT;

    CREATE INDEX IF NOT EXISTS users_customer_idx ON users(customer_id);
    CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions(expires_at);
    CREATE INDEX IF NOT EXISTS sessions_user_created_idx ON sessions(user_id,created_at DESC);
    CREATE INDEX IF NOT EXISTS mfa_challenges_expires_idx ON mfa_login_challenges(expires_at);
    CREATE INDEX IF NOT EXISTS account_tokens_user_purpose_idx ON account_tokens(user_id,purpose,created_at DESC);
    CREATE INDEX IF NOT EXISTS account_tokens_expires_idx ON account_tokens(expires_at);
    CREATE INDEX IF NOT EXISTS resources_cluster_idx ON resources(cluster_id,node,type,vmid);
    CREATE INDEX IF NOT EXISTS assignments_customer_idx ON customer_resource_assignments(customer_id,status);
    CREATE INDEX IF NOT EXISTS audit_customer_created_idx ON audit_logs(customer_id,created_at DESC);
    CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_logs(created_at DESC);
    CREATE INDEX IF NOT EXISTS tasks_customer_created_idx ON api_tasks(customer_id,created_at DESC);
    CREATE INDEX IF NOT EXISTS tasks_resource_created_idx ON api_tasks(resource_id,created_at DESC);
    CREATE INDEX IF NOT EXISTS iso_images_customer_created_idx ON iso_images(customer_id,created_at DESC);
    CREATE INDEX IF NOT EXISTS iso_images_policy_status_idx ON iso_images(storage_policy_id,status);
    CREATE INDEX IF NOT EXISTS iso_mounts_resource_status_idx ON iso_mounts(resource_id,status);
    CREATE INDEX IF NOT EXISTS iso_mounts_image_status_idx ON iso_mounts(iso_image_id,status);
    CREATE INDEX IF NOT EXISTS iso_boot_overrides_resource_created_idx ON iso_boot_overrides(resource_id,created_at DESC);
    CREATE UNIQUE INDEX IF NOT EXISTS iso_boot_overrides_active_idx ON iso_boot_overrides(resource_id)
      WHERE status IN ('arming','armed','restoring','error');
    CREATE INDEX IF NOT EXISTS email_jobs_due_idx ON email_jobs(status,next_attempt_at,created_at);
    CREATE INDEX IF NOT EXISTS email_jobs_created_idx ON email_jobs(created_at DESC);
    CREATE INDEX IF NOT EXISTS alert_states_status_idx ON alert_states(status,updated_at);
    CREATE INDEX IF NOT EXISTS notification_events_customer_created_idx ON notification_events(customer_id,created_at DESC);
    CREATE INDEX IF NOT EXISTS notification_events_resource_created_idx ON notification_events(resource_id,created_at DESC);
    CREATE INDEX IF NOT EXISTS notifications_user_created_idx ON notifications(user_id,created_at DESC);
    CREATE UNIQUE INDEX IF NOT EXISTS tasks_idempotency_idx ON api_tasks(user_id,idempotency_key) WHERE idempotency_key IS NOT NULL;
  `);

  const assignmentColumns = new Set(database.prepare("PRAGMA table_info(customer_resource_assignments)").all().map((column) => column.name));
  if (!assignmentColumns.has("snapshot_limit")) {
    database.exec("ALTER TABLE customer_resource_assignments ADD COLUMN snapshot_limit INTEGER NOT NULL DEFAULT 3 CHECK(snapshot_limit BETWEEN 1 AND 50)");
  }
  const sessionColumns = new Set(database.prepare("PRAGMA table_info(sessions)").all().map((column) => column.name));
  if (!sessionColumns.has("ip_address")) database.exec("ALTER TABLE sessions ADD COLUMN ip_address TEXT");
  if (!sessionColumns.has("user_agent")) database.exec("ALTER TABLE sessions ADD COLUMN user_agent TEXT");
  const userColumns = new Set(database.prepare("PRAGMA table_info(users)").all().map((column) => column.name));
  if (!userColumns.has("password_set")) database.exec("ALTER TABLE users ADD COLUMN password_set INTEGER NOT NULL DEFAULT 1");
  const emailSettingsColumns = new Set(database.prepare("PRAGMA table_info(email_settings)").all().map((column) => column.name));
  if (!emailSettingsColumns.has("app_url")) database.exec("ALTER TABLE email_settings ADD COLUMN app_url TEXT NOT NULL DEFAULT ''");

  const getCustomerRow = database.prepare(customerSelect("WHERE c.id=?"));
  const getUserRow = database.prepare(userSelect("WHERE u.id=?"));
  const getUserByEmailRow = database.prepare(userSelect("WHERE u.email=?"));
  const getClusterRow = database.prepare(clusterSelect("WHERE c.id=?"));
  const getResourceRow = database.prepare(resourceSelect("WHERE r.id=?"));

  function replacePermissions(assignmentId, permissions) {
    database.prepare("DELETE FROM assignment_permissions WHERE assignment_id=?").run(assignmentId);
    const insert = database.prepare("INSERT INTO assignment_permissions (assignment_id,permission,allowed) VALUES (?,?,1)");
    for (const permission of normalizePermissions(permissions)) insert.run(assignmentId, permission);
  }

  function replaceAlertPolicy(assignmentId, input = {}, { reset = false } = {}) {
    const existing = reset ? null : database.prepare("SELECT * FROM resource_alert_policies WHERE assignment_id=?").get(assignmentId);
    const policy = normalizeAlertPolicy(input, existing);
    const now = Date.now();
    database.prepare(`INSERT INTO resource_alert_policies
      (assignment_id,enabled,alert_offline,alert_cpu,alert_memory,alert_storage,cpu_threshold,memory_threshold,
       storage_threshold,sustain_seconds,cooldown_seconds,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(assignment_id) DO UPDATE SET
        enabled=excluded.enabled,alert_offline=excluded.alert_offline,alert_cpu=excluded.alert_cpu,
        alert_memory=excluded.alert_memory,alert_storage=excluded.alert_storage,cpu_threshold=excluded.cpu_threshold,
        memory_threshold=excluded.memory_threshold,storage_threshold=excluded.storage_threshold,
        sustain_seconds=excluded.sustain_seconds,cooldown_seconds=excluded.cooldown_seconds,updated_at=excluded.updated_at`)
      .run(
        assignmentId,
        policy.enabled ? 1 : 0,
        policy.offline ? 1 : 0,
        policy.cpu ? 1 : 0,
        policy.memory ? 1 : 0,
        policy.storage ? 1 : 0,
        policy.cpuThreshold,
        policy.memoryThreshold,
        policy.storageThreshold,
        policy.sustainMinutes * 60,
        policy.cooldownMinutes * 60,
        existing?.created_at || now,
        now,
      );
    return policy;
  }

  return {
    database,
    hasUsers: () => database.prepare("SELECT COUNT(*) AS count FROM users").get().count > 0,

    createCustomer(input) {
      const id = normalizeId(input.id, "Customer");
      const name = String(input.name || "").trim();
      if (!name || name.length > 100) throw problem("Customer name must contain 1-100 characters");
      const supportEmail = normalizeEmail(input.supportEmail);
      if (supportEmail && !/^\S+@\S+\.\S+$/.test(supportEmail)) throw problem("Support email is invalid");
      const planName = String(input.planName || "Managed infrastructure").trim();
      const now = Date.now();
      database.prepare("INSERT INTO customers (id,name,status,support_email,plan_name,created_at,updated_at) VALUES (?,?,?,?,?,?,?)")
        .run(id, name, input.status || "active", supportEmail, planName, now, now);
      return publicCustomer(getCustomerRow.get(id));
    },
    getCustomer: (id) => publicCustomer(getCustomerRow.get(id)),
    listCustomers: () => database.prepare(customerSelect("ORDER BY c.name")).all().map(publicCustomer),
    updateCustomer(id, input) {
      const row = database.prepare("SELECT * FROM customers WHERE id=?").get(id);
      if (!row) throw problem("Customer does not exist", "customer_not_found", 404);
      const name = input.name === undefined ? row.name : String(input.name).trim();
      const status = input.status ?? row.status;
      const supportEmail = input.supportEmail === undefined ? row.support_email : normalizeEmail(input.supportEmail);
      const planName = input.planName === undefined ? row.plan_name : String(input.planName).trim();
      if (!name || !["active", "disabled"].includes(status)) throw problem("Invalid customer update");
      if (supportEmail && !/^\S+@\S+\.\S+$/.test(supportEmail)) throw problem("Support email is invalid");
      database.prepare("UPDATE customers SET name=?,status=?,support_email=?,plan_name=?,updated_at=? WHERE id=?")
        .run(name, status, supportEmail, planName, Date.now(), id);
      if (status === "disabled") {
        database.prepare("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE customer_id=?)").run(id);
      }
      return publicCustomer(getCustomerRow.get(id));
    },
    deleteCustomer(id) {
      const images = database.prepare("SELECT COUNT(*) AS count FROM iso_images WHERE customer_id=? AND status!='deleted'").get(id).count;
      if (images) throw problem("Delete the customer's ISO images before deleting the customer account", "customer_iso_images_exist", 409);
      const result = database.prepare("DELETE FROM customers WHERE id=?").run(id);
      if (!result.changes) throw problem("Customer does not exist", "customer_not_found", 404);
    },

    async createUser({ email, displayName, password, role = "customer", customerId = null }) {
      const normalized = normalizeEmail(email);
      if (!/^\S+@\S+\.\S+$/.test(normalized)) throw problem("A valid email address is required");
      if (getUserByEmailRow.get(normalized)) throw problem("A user with this email address already exists", "email_in_use", 409);
      if (!["admin", "customer"].includes(role)) throw problem("Invalid role");
      if (role === "customer" && !customerId) throw problem("Customer users must belong to a customer account");
      if (customerId && !getCustomerRow.get(customerId)) throw problem("Customer does not exist", "customer_not_found");
      const name = String(displayName || normalized).trim();
      const now = Date.now();
      const id = randomToken(18);
      database.prepare("INSERT INTO users (id,customer_id,email,display_name,password_hash,role,status,created_at,updated_at) VALUES (?,?,?,?,?,?, 'active',?,?)")
        .run(id, customerId, normalized, name, await hashPassword(password), role, now, now);
      return publicUser(getUserRow.get(id));
    },
    async createInvitedUser({ email, displayName, role = "customer", customerId = null }) {
      const normalized = normalizeEmail(email);
      if (!/^\S+@\S+\.\S+$/.test(normalized)) throw problem("A valid email address is required");
      if (getUserByEmailRow.get(normalized)) throw problem("A user with this email address already exists", "email_in_use", 409);
      if (!["admin", "customer"].includes(role)) throw problem("Invalid role");
      if (role === "customer" && !customerId) throw problem("Customer users must belong to a customer account");
      if (customerId && !getCustomerRow.get(customerId)) throw problem("Customer does not exist", "customer_not_found");
      const name = String(displayName || normalized).trim();
      if (!name || name.length > 100) throw problem("Display name must contain 1-100 characters");
      const now = Date.now();
      const id = randomToken(18);
      database.prepare(`INSERT INTO users
        (id,customer_id,email,display_name,password_hash,password_set,role,status,created_at,updated_at)
        VALUES (?,?,?,?,?,0,?,'active',?,?)`)
        .run(id, customerId, normalized, name, await hashPassword(randomToken(32)), role, now, now);
      return publicUser(getUserRow.get(id));
    },
    findUserForLogin: (email) => getUserByEmailRow.get(normalizeEmail(email)),
    getUserForAuth: (id) => getUserRow.get(id),
    listUsers: () => database.prepare(userSelect("ORDER BY u.email")).all().map(publicUser),
    listCustomerUsers: (customerId) => database.prepare(userSelect("WHERE u.customer_id=? ORDER BY u.display_name")).all(customerId).map(publicUser),
    listActiveCustomerUsers: (customerId) => database.prepare(userSelect("WHERE u.customer_id=? AND u.role='customer' AND u.status='active' ORDER BY u.display_name"))
      .all(customerId).map(publicUser),
    updateUser(id, input) {
      const row = database.prepare("SELECT * FROM users WHERE id=?").get(id);
      if (!row) throw problem("User does not exist", "user_not_found", 404);
      const role = input.role ?? row.role;
      const status = input.status ?? row.status;
      const customerId = input.customerId === undefined ? row.customer_id : (input.customerId || null);
      const displayName = input.displayName === undefined ? row.display_name : String(input.displayName).trim();
      if (!["admin", "customer"].includes(role) || !["active", "disabled"].includes(status)) throw problem("Invalid user update");
      if (!displayName || displayName.length > 100) throw problem("Display name must contain 1-100 characters");
      if (role === "customer" && !customerId) throw problem("Customer users must belong to a customer account");
      if (customerId && !getCustomerRow.get(customerId)) throw problem("Customer does not exist", "customer_not_found");
      const activeAdmins = database.prepare("SELECT COUNT(*) AS count FROM users WHERE role='admin' AND status='active'").get().count;
      if (row.role === "admin" && row.status === "active" && (role !== "admin" || status !== "active") && activeAdmins <= 1) {
        throw problem("The last active administrator cannot be disabled or demoted", "last_admin");
      }
      database.prepare("UPDATE users SET customer_id=?,display_name=?,role=?,status=?,updated_at=? WHERE id=?")
        .run(customerId, displayName, role, status, Date.now(), id);
      if (status === "disabled") database.prepare("DELETE FROM sessions WHERE user_id=?").run(id);
      return publicUser(getUserRow.get(id));
    },
    deleteUser(id) {
      const row = database.prepare("SELECT * FROM users WHERE id=?").get(id);
      if (!row) throw problem("User does not exist", "user_not_found", 404);
      if (row.role === "admin" && row.status === "active" && database.prepare("SELECT COUNT(*) AS count FROM users WHERE role='admin' AND status='active'").get().count <= 1) {
        throw problem("The last active administrator cannot be deleted", "last_admin");
      }
      database.prepare("DELETE FROM users WHERE id=?").run(id);
    },
    updateProfile(id, displayName) {
      const name = String(displayName || "").trim();
      if (!name || name.length > 100) throw problem("Display name must contain 1-100 characters");
      database.prepare("UPDATE users SET display_name=?,updated_at=? WHERE id=?").run(name, Date.now(), id);
      return publicUser(getUserRow.get(id));
    },
    async updatePassword(id, password, { revokeSessions = true } = {}) {
      database.prepare("UPDATE users SET password_hash=?,password_set=1,updated_at=? WHERE id=?").run(await hashPassword(password), Date.now(), id);
      if (revokeSessions) database.prepare("DELETE FROM sessions WHERE user_id=?").run(id);
      database.prepare("UPDATE account_tokens SET used_at=? WHERE user_id=? AND used_at IS NULL").run(Date.now(), id);
    },

    createCluster(input) {
      const id = normalizeId(input.id, "Cluster");
      const name = String(input.name || "").trim();
      let apiUrl;
      try { apiUrl = new URL(String(input.apiUrl || "")); } catch { throw problem("A valid Proxmox API URL is required"); }
      if (apiUrl.protocol !== "https:") throw problem("The Proxmox API URL must use HTTPS");
      const tokenId = String(input.tokenId || "").trim();
      const tokenSecret = String(input.tokenSecret || "").trim();
      if (!name || !tokenId || !tokenSecret) throw problem("Cluster name and API token credentials are required");
      const now = Date.now();
      database.exec("BEGIN IMMEDIATE");
      try {
        database.prepare("INSERT INTO proxmox_clusters (id,name,api_url,status,verify_tls,created_at,updated_at) VALUES (?,?,?,'active',1,?,?)")
          .run(id, name, apiUrl.toString().replace(/\/$/, ""), now, now);
        database.prepare("INSERT INTO proxmox_credentials (id,cluster_id,token_id,token_secret_encrypted,created_at,updated_at) VALUES (?,?,?,?,?,?)")
          .run(randomToken(18), id, tokenId, encryptSecret(tokenSecret, appSecret), now, now);
        database.exec("COMMIT");
      } catch (error) { database.exec("ROLLBACK"); throw error; }
      return publicCluster(getClusterRow.get(id));
    },
    listClusters: () => database.prepare(clusterSelect("ORDER BY c.name")).all().map(publicCluster),
    getCluster: (id) => publicCluster(getClusterRow.get(id)),
    getClusterConnection(id) {
      const row = database.prepare(`SELECT c.id,c.name,c.api_url,c.status,pc.token_id,pc.token_secret_encrypted
        FROM proxmox_clusters c JOIN proxmox_credentials pc ON pc.cluster_id=c.id WHERE c.id=?`).get(id);
      if (!row || row.status === "disabled") return null;
      return {
        id: row.id,
        name: row.name,
        baseUrl: row.api_url,
        tokenId: row.token_id,
        tokenSecret: decryptSecret(row.token_secret_encrypted, appSecret),
      };
    },
    updateCluster(id, input) {
      const row = database.prepare("SELECT * FROM proxmox_clusters WHERE id=?").get(id);
      if (!row) throw problem("Cluster does not exist", "cluster_not_found", 404);
      const name = input.name === undefined ? row.name : String(input.name).trim();
      let apiUrl = row.api_url;
      if (input.apiUrl !== undefined) {
        let parsed;
        try { parsed = new URL(String(input.apiUrl)); } catch { throw problem("A valid Proxmox API URL is required"); }
        if (parsed.protocol !== "https:") throw problem("The Proxmox API URL must use HTTPS");
        apiUrl = parsed.toString().replace(/\/$/, "");
      }
      const status = input.status ?? row.status;
      if (!name || !["active", "disabled", "error"].includes(status)) throw problem("Invalid cluster update");
      database.prepare("UPDATE proxmox_clusters SET name=?,api_url=?,status=?,updated_at=? WHERE id=?")
        .run(name, apiUrl, status, Date.now(), id);
      if (input.tokenId || input.tokenSecret) {
        const credential = database.prepare("SELECT * FROM proxmox_credentials WHERE cluster_id=?").get(id);
        const tokenId = input.tokenId || credential.token_id;
        const encrypted = input.tokenSecret ? encryptSecret(input.tokenSecret, appSecret) : credential.token_secret_encrypted;
        database.prepare("UPDATE proxmox_credentials SET token_id=?,token_secret_encrypted=?,updated_at=? WHERE cluster_id=?")
          .run(tokenId, encrypted, Date.now(), id);
      }
      return publicCluster(getClusterRow.get(id));
    },
    setClusterSync(id, { error = null } = {}) {
      database.prepare("UPDATE proxmox_clusters SET status=?,last_sync_at=?,last_error=?,updated_at=? WHERE id=?")
        .run(error ? "error" : "active", Date.now(), error, Date.now(), id);
    },
    syncResources(clusterId, resources) {
      const now = Date.now();
      database.prepare("UPDATE resources SET stale=1,updated_at=? WHERE cluster_id=?").run(now, clusterId);
      const upsertNode = database.prepare(`INSERT INTO proxmox_nodes (cluster_id,name,status,last_seen_at) VALUES (?,?,'online',?)
        ON CONFLICT(cluster_id,name) DO UPDATE SET status='online',last_seen_at=excluded.last_seen_at`);
      const upsert = database.prepare(`INSERT INTO resources
        (id,cluster_id,node,type,vmid,name,status,vcpu,memory,memory_used,storage,storage_used,cpu,uptime,ip,metadata,stale,last_seen_at,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?)
        ON CONFLICT(cluster_id,type,vmid) DO UPDATE SET
          node=excluded.node,name=excluded.name,status=excluded.status,vcpu=excluded.vcpu,memory=excluded.memory,
          memory_used=excluded.memory_used,storage=excluded.storage,storage_used=excluded.storage_used,cpu=excluded.cpu,
          uptime=excluded.uptime,ip=COALESCE(excluded.ip,resources.ip),metadata=excluded.metadata,stale=0,
          last_seen_at=excluded.last_seen_at,updated_at=excluded.updated_at`);
      database.exec("BEGIN IMMEDIATE");
      try {
        for (const resource of resources) {
          if (!["qemu", "lxc"].includes(resource.type) || !Number.isInteger(Number(resource.vmid)) || !resource.node) continue;
          const id = `${clusterId}:${resource.type}:${resource.vmid}`;
          upsertNode.run(clusterId, resource.node, now);
          upsert.run(
            id, clusterId, resource.node, resource.type, Number(resource.vmid), resource.name || `${resource.type}-${resource.vmid}`,
            resource.status || "unknown", Number(resource.vcpu || 0), Number(resource.memory || 0), Number(resource.memoryUsed || 0),
            Number(resource.storage || 0), Number(resource.storageUsed || 0), Number(resource.cpu || 0), Number(resource.uptime || 0),
            resource.ip || null, JSON.stringify(resource.metadata || {}), now, now, now,
          );
        }
        database.prepare("UPDATE proxmox_clusters SET status='active',last_sync_at=?,last_error=NULL,updated_at=? WHERE id=?").run(now, now, clusterId);
        database.exec("COMMIT");
      } catch (error) { database.exec("ROLLBACK"); throw error; }
      return this.listResources({ clusterId });
    },

    listResources({ clusterId = null, customerId = null } = {}) {
      if (customerId) return database.prepare(resourceSelect("WHERE a.customer_id=? AND a.status='active'")).all(customerId).map(publicResource);
      if (clusterId) return database.prepare(resourceSelect("WHERE r.cluster_id=?")).all(clusterId).map(publicResource);
      return database.prepare(resourceSelect()).all().map(publicResource).sort((left, right) =>
        left.clusterName.localeCompare(right.clusterName) || left.node.localeCompare(right.node) || left.vmid - right.vmid);
    },
    getResource: (id) => publicResource(getResourceRow.get(id)),
    setResourceStatus(id, status) {
      database.prepare("UPDATE resources SET status=?,updated_at=? WHERE id=?").run(status, Date.now(), id);
      return publicResource(getResourceRow.get(id));
    },
    assignResource({ customerId, resourceId, displayName = null, permissions = DEFAULT_PERMISSIONS, snapshotLimit, alertPolicy }) {
      if (!getCustomerRow.get(customerId)) throw problem("Customer does not exist", "customer_not_found", 404);
      if (!getResourceRow.get(resourceId)) throw problem("Resource does not exist", "resource_not_found", 404);
      const existing = database.prepare("SELECT * FROM customer_resource_assignments WHERE resource_id=?").get(resourceId);
      if (existing?.customer_id !== customerId && database.prepare("SELECT 1 FROM iso_mounts WHERE resource_id=? AND status='active' LIMIT 1").get(resourceId)) {
        throw problem("Eject the mounted customer ISO before reassigning this resource", "resource_iso_mounted", 409);
      }
      if (existing?.customer_id !== customerId && database.prepare(`SELECT 1 FROM iso_boot_overrides WHERE resource_id=?
        AND status IN ('arming','armed','restoring','error') LIMIT 1`).get(resourceId)) {
        throw problem("Restore the VM boot order before reassigning this resource", "resource_iso_boot_active", 409);
      }
      const now = Date.now();
      const assignmentId = existing?.id || randomToken(18);
      const reassigned = Boolean(existing && (existing.customer_id !== customerId || existing.status !== "active"));
      const nextSnapshotLimit = normalizeSnapshotLimit(snapshotLimit === undefined
        ? (existing?.customer_id === customerId ? existing.snapshot_limit : DEFAULT_SNAPSHOT_LIMIT)
        : snapshotLimit);
      database.exec("BEGIN IMMEDIATE");
      try {
        if (existing) {
          database.prepare("UPDATE customer_resource_assignments SET customer_id=?,display_name=?,snapshot_limit=?,status='active',updated_at=? WHERE id=?")
            .run(customerId, displayName || null, nextSnapshotLimit, now, assignmentId);
        } else {
          database.prepare("INSERT INTO customer_resource_assignments (id,customer_id,resource_id,display_name,snapshot_limit,status,created_at,updated_at) VALUES (?,?,?,?,?,'active',?,?)")
            .run(assignmentId, customerId, resourceId, displayName || null, nextSnapshotLimit, now, now);
        }
        replacePermissions(assignmentId, permissions);
        if (reassigned) {
          database.prepare("DELETE FROM alert_states WHERE assignment_id=?").run(assignmentId);
          database.prepare("DELETE FROM resource_alert_policies WHERE assignment_id=?").run(assignmentId);
        }
        replaceAlertPolicy(assignmentId, alertPolicy || {}, { reset: reassigned });
        database.exec("COMMIT");
      } catch (error) { database.exec("ROLLBACK"); throw error; }
      return this.getResource(resourceId);
    },
    updateAssignment(resourceId, { displayName, permissions, status, snapshotLimit, alertPolicy }) {
      const existing = database.prepare("SELECT * FROM customer_resource_assignments WHERE resource_id=?").get(resourceId);
      if (!existing) throw problem("Assignment does not exist", "assignment_not_found", 404);
      if (status && status !== "active" && database.prepare(`SELECT 1 FROM iso_boot_overrides WHERE resource_id=?
        AND status IN ('arming','armed','restoring','error') LIMIT 1`).get(resourceId)) {
        throw problem("Restore the VM boot order before disabling this assignment", "resource_iso_boot_active", 409);
      }
      const nextSnapshotLimit = snapshotLimit === undefined ? existing.snapshot_limit : normalizeSnapshotLimit(snapshotLimit);
      database.prepare("UPDATE customer_resource_assignments SET display_name=?,snapshot_limit=?,status=?,updated_at=? WHERE id=?")
        .run(displayName === undefined ? existing.display_name : (displayName || null), nextSnapshotLimit, status || existing.status, Date.now(), existing.id);
      if (permissions !== undefined) replacePermissions(existing.id, permissions);
      if (alertPolicy !== undefined) replaceAlertPolicy(existing.id, alertPolicy);
      else if (!database.prepare("SELECT 1 FROM resource_alert_policies WHERE assignment_id=?").get(existing.id)) replaceAlertPolicy(existing.id);
      return this.getResource(resourceId);
    },
    unassignResource(resourceId) {
      if (database.prepare("SELECT 1 FROM iso_mounts WHERE resource_id=? AND status='active' LIMIT 1").get(resourceId)) {
        throw problem("Eject the mounted customer ISO before removing this assignment", "resource_iso_mounted", 409);
      }
      if (database.prepare(`SELECT 1 FROM iso_boot_overrides WHERE resource_id=?
        AND status IN ('arming','armed','restoring','error') LIMIT 1`).get(resourceId)) {
        throw problem("Restore the VM boot order before removing this assignment", "resource_iso_boot_active", 409);
      }
      const result = database.prepare("UPDATE customer_resource_assignments SET status='unassigned',updated_at=? WHERE resource_id=? AND status='active'")
        .run(Date.now(), resourceId);
      if (!result.changes) throw problem("Assignment does not exist", "assignment_not_found", 404);
    },
    authorizeResource(customerId, resourceId, permission) {
      if (!ASSIGNMENT_PERMISSIONS.includes(permission)) return null;
      const row = database.prepare(`${resourceSelect(`WHERE r.id=? AND a.customer_id=? AND a.status='active'
        AND EXISTS (SELECT 1 FROM assignment_permissions p WHERE p.assignment_id=a.id AND p.permission=? AND p.allowed=1)`)}`).get(resourceId, customerId, permission);
      return publicResource(row);
    },
    listAlertAssignments({ clusterId = null } = {}) {
      const clusterClause = clusterId ? " AND r.cluster_id=?" : "";
      return database.prepare(resourceSelect(`WHERE a.status='active' AND c.status='active' AND pc.status='active'
        AND r.stale=0 AND rap.enabled=1${clusterClause}`)).all(...(clusterId ? [clusterId] : [])).map(publicResource);
    },
    getAlertState(assignmentId, alertType) {
      return database.prepare("SELECT * FROM alert_states WHERE assignment_id=? AND alert_type=?").get(assignmentId, alertType) || null;
    },
    upsertAlertState(assignmentId, alertType, input = {}) {
      if (!["offline", "cpu", "memory", "storage"].includes(alertType)) throw problem("Alert type is invalid", "invalid_alert_type");
      const existing = this.getAlertState(assignmentId, alertType);
      const status = input.status ?? existing?.status ?? "healthy";
      if (!["healthy", "pending", "firing"].includes(status)) throw problem("Alert state is invalid", "invalid_alert_state");
      const now = Date.now();
      database.prepare(`INSERT INTO alert_states
        (assignment_id,alert_type,status,condition_active,first_observed_at,last_value,last_notified_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(assignment_id,alert_type) DO UPDATE SET
          status=excluded.status,condition_active=excluded.condition_active,first_observed_at=excluded.first_observed_at,
          last_value=excluded.last_value,last_notified_at=excluded.last_notified_at,updated_at=excluded.updated_at`)
        .run(
          assignmentId,
          alertType,
          status,
          (input.conditionActive ?? Boolean(existing?.condition_active)) ? 1 : 0,
          input.firstObservedAt === undefined ? (existing?.first_observed_at || null) : input.firstObservedAt,
          input.lastValue === undefined ? (existing?.last_value ?? null) : input.lastValue,
          input.lastNotifiedAt === undefined ? (existing?.last_notified_at || null) : input.lastNotifiedAt,
          now,
        );
      return this.getAlertState(assignmentId, alertType);
    },
    resetAlertStates(assignmentId) {
      database.prepare("DELETE FROM alert_states WHERE assignment_id=?").run(assignmentId);
    },

    createIsoPolicy({ clusterId, storageId, displayName, maxUploadBytes, customerQuotaBytes, allowDelete = false, status = "active" }) {
      if (!getClusterRow.get(clusterId)) throw problem("Cluster does not exist", "cluster_not_found", 404);
      const normalizedStorageId = normalizeStorageId(storageId);
      const name = String(displayName || normalizedStorageId).trim();
      if (!name || name.length > 100) throw problem("ISO storage display name must contain 1-100 characters");
      if (!["active", "disabled"].includes(status)) throw problem("ISO storage policy status is invalid");
      if (database.prepare("SELECT 1 FROM iso_storage_policies WHERE cluster_id=? AND storage_id=?").get(clusterId, normalizedStorageId)) {
        throw problem("That Proxmox storage already has an ISO policy", "iso_policy_exists", 409);
      }
      const maxBytes = normalizeByteLimit(maxUploadBytes, "Maximum upload size");
      const quotaBytes = normalizeByteLimit(customerQuotaBytes, "Customer quota");
      if (quotaBytes < maxBytes) throw problem("Customer quota cannot be smaller than the per-file upload limit");
      const id = randomToken(18);
      const now = Date.now();
      database.prepare(`INSERT INTO iso_storage_policies
        (id,cluster_id,storage_id,display_name,status,max_upload_bytes,customer_quota_bytes,allow_delete,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)`)
        .run(id, clusterId, normalizedStorageId, name, status, maxBytes, quotaBytes, allowDelete ? 1 : 0, now, now);
      return publicIsoPolicy(database.prepare(isoPolicySelect("WHERE p.id=?")).get(id));
    },
    getIsoPolicy: (id) => publicIsoPolicy(database.prepare(isoPolicySelect("WHERE p.id=?")).get(id)),
    listIsoPolicies({ clusterId = null, activeOnly = false } = {}) {
      const clauses = [];
      const params = [];
      if (clusterId) { clauses.push("p.cluster_id=?"); params.push(clusterId); }
      if (activeOnly) clauses.push("p.status='active'");
      const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
      return database.prepare(`${isoPolicySelect(where)} ORDER BY c.name,p.display_name`).all(...params).map(publicIsoPolicy);
    },
    updateIsoPolicy(id, input) {
      const row = database.prepare("SELECT * FROM iso_storage_policies WHERE id=?").get(id);
      if (!row) throw problem("ISO storage policy does not exist", "iso_policy_not_found", 404);
      const displayName = input.displayName === undefined ? row.display_name : String(input.displayName).trim();
      const status = input.status ?? row.status;
      const maxUploadBytes = input.maxUploadBytes === undefined ? row.max_upload_bytes : normalizeByteLimit(input.maxUploadBytes, "Maximum upload size");
      const customerQuotaBytes = input.customerQuotaBytes === undefined ? row.customer_quota_bytes : normalizeByteLimit(input.customerQuotaBytes, "Customer quota");
      const allowDelete = input.allowDelete === undefined ? row.allow_delete : (input.allowDelete ? 1 : 0);
      if (!displayName || displayName.length > 100 || !["active", "disabled"].includes(status)) throw problem("Invalid ISO storage policy update");
      if (customerQuotaBytes < maxUploadBytes) throw problem("Customer quota cannot be smaller than the per-file upload limit");
      database.prepare("UPDATE iso_storage_policies SET display_name=?,status=?,max_upload_bytes=?,customer_quota_bytes=?,allow_delete=?,updated_at=? WHERE id=?")
        .run(displayName, status, maxUploadBytes, customerQuotaBytes, allowDelete, Date.now(), id);
      return publicIsoPolicy(database.prepare(isoPolicySelect("WHERE p.id=?")).get(id));
    },
    deleteIsoPolicy(id) {
      const policy = database.prepare("SELECT * FROM iso_storage_policies WHERE id=?").get(id);
      if (!policy) throw problem("ISO storage policy does not exist", "iso_policy_not_found", 404);
      const images = database.prepare("SELECT COUNT(*) AS count FROM iso_images WHERE storage_policy_id=? AND status!='deleted'").get(id).count;
      if (images) throw problem("Disable this policy instead; customer ISO records still use it", "iso_policy_in_use", 409);
      database.prepare("DELETE FROM iso_storage_policies WHERE id=?").run(id);
    },
    getIsoUsage(customerId, storagePolicyId) {
      return Number(database.prepare(`SELECT COALESCE(SUM(size_bytes),0) AS bytes FROM iso_images
        WHERE customer_id=? AND storage_policy_id=? AND status IN ('uploading','processing','ready','deleting')`)
        .get(customerId, storagePolicyId).bytes || 0);
    },
    createIsoImage({ customerId, clusterId, storagePolicyId, storageId, node, volumeId, fileName, originalName, sizeBytes, createdBy }) {
      if (!getCustomerRow.get(customerId)) throw problem("Customer does not exist", "customer_not_found", 404);
      const policy = database.prepare("SELECT * FROM iso_storage_policies WHERE id=? AND status='active'").get(storagePolicyId);
      if (!policy || policy.cluster_id !== clusterId || policy.storage_id !== storageId) throw problem("ISO storage policy is unavailable", "iso_policy_not_found", 404);
      const id = randomToken(18);
      const now = Date.now();
      database.prepare(`INSERT INTO iso_images
        (id,customer_id,cluster_id,storage_policy_id,storage_id,node,volume_id,file_name,original_name,size_bytes,status,created_by,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,'uploading',?,?,?)`)
        .run(id, customerId, clusterId, storagePolicyId, storageId, node, volumeId, fileName, originalName, Number(sizeBytes), createdBy, now, now);
      return publicIsoImage(database.prepare(isoImageSelect("WHERE i.id=?")).get(id));
    },
    getIsoImageRow(id, user = null) {
      if (!user || user.role === "admin") return database.prepare(isoImageSelect("WHERE i.id=?")).get(id);
      return database.prepare(isoImageSelect("WHERE i.id=? AND i.customer_id=?")).get(id, user.customerId);
    },
    getIsoImage(id, user = null) { return publicIsoImage(this.getIsoImageRow(id, user)); },
    listIsoImages(user, { clusterId = null, includeDeleted = false } = {}) {
      const clauses = [];
      const params = [];
      if (user.role !== "admin") { clauses.push("i.customer_id=?"); params.push(user.customerId); }
      if (clusterId) { clauses.push("i.cluster_id=?"); params.push(clusterId); }
      if (!includeDeleted) clauses.push("i.status!='deleted'");
      const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
      return database.prepare(`${isoImageSelect(where)} ORDER BY i.created_at DESC`).all(...params).map(publicIsoImage);
    },
    updateIsoImage(id, { status, sha256, operationUpid, errorCode, sizeBytes } = {}) {
      const row = database.prepare("SELECT * FROM iso_images WHERE id=?").get(id);
      if (!row) throw problem("ISO image does not exist", "iso_not_found", 404);
      const nextStatus = status ?? row.status;
      if (!["uploading", "processing", "ready", "error", "deleting", "deleted"].includes(nextStatus)) throw problem("ISO image status is invalid");
      database.prepare(`UPDATE iso_images SET status=?,sha256=?,operation_upid=?,error_code=?,size_bytes=?,updated_at=? WHERE id=?`)
        .run(nextStatus, sha256 === undefined ? row.sha256 : sha256, operationUpid === undefined ? row.operation_upid : operationUpid,
          errorCode === undefined ? row.error_code : errorCode, sizeBytes === undefined ? row.size_bytes : Number(sizeBytes), Date.now(), id);
      return publicIsoImage(database.prepare(isoImageSelect("WHERE i.id=?")).get(id));
    },
    createIsoMount({ isoImageId, resourceId, driveSlot, createdBy }) {
      const image = database.prepare("SELECT * FROM iso_images WHERE id=? AND status='ready'").get(isoImageId);
      if (!image) throw problem("ISO image is not ready", "iso_not_ready", 409);
      const now = Date.now();
      const id = randomToken(18);
      database.exec("BEGIN IMMEDIATE");
      try {
        database.prepare("UPDATE iso_mounts SET status='ejected',ejected_at=? WHERE resource_id=? AND status='active'").run(now, resourceId);
        database.prepare(`INSERT INTO iso_mounts
          (id,iso_image_id,resource_id,drive_slot,status,created_by,mounted_at,created_at)
          VALUES (?,?,?,?,'active',?,?,?)`).run(id, isoImageId, resourceId, driveSlot, createdBy, now, now);
        database.exec("COMMIT");
      } catch (error) { database.exec("ROLLBACK"); throw error; }
      return publicIsoMount(database.prepare(`SELECT m.*,i.file_name,i.original_name FROM iso_mounts m
        JOIN iso_images i ON i.id=m.iso_image_id WHERE m.id=?`).get(id));
    },
    getActiveIsoMountForResource(resourceId) {
      return database.prepare(`SELECT m.*,i.customer_id,i.cluster_id,i.storage_id,i.volume_id,i.file_name,i.original_name
        FROM iso_mounts m JOIN iso_images i ON i.id=m.iso_image_id
        WHERE m.resource_id=? AND m.status='active' ORDER BY m.mounted_at DESC LIMIT 1`).get(resourceId);
    },
    listIsoMountsForResource(resourceId) {
      return database.prepare(`SELECT m.*,i.file_name,i.original_name FROM iso_mounts m
        JOIN iso_images i ON i.id=m.iso_image_id WHERE m.resource_id=? ORDER BY m.mounted_at DESC`)
        .all(resourceId).map(publicIsoMount);
    },
    hasActiveIsoMount(isoImageId) {
      return Boolean(database.prepare("SELECT 1 FROM iso_mounts WHERE iso_image_id=? AND status='active' LIMIT 1").get(isoImageId));
    },
    ejectIsoMount(id) {
      database.prepare("UPDATE iso_mounts SET status='ejected',ejected_at=? WHERE id=? AND status='active'").run(Date.now(), id);
      return publicIsoMount(database.prepare(`SELECT m.*,i.file_name,i.original_name FROM iso_mounts m
        JOIN iso_images i ON i.id=m.iso_image_id WHERE m.id=?`).get(id));
    },
    createIsoBootOverride({ resourceId, isoMountId, driveSlot, originalBoot = null, armedBoot, createdBy }) {
      const slot = String(driveSlot || "");
      if (!/^(ide|sata|scsi)\d+$/.test(slot)) throw problem("The virtual CD/DVD slot is invalid", "cdrom_slot_invalid", 409);
      const mount = database.prepare("SELECT * FROM iso_mounts WHERE id=? AND resource_id=? AND status='active'").get(isoMountId, resourceId);
      if (!mount || mount.drive_slot !== slot) throw problem("The mounted ISO is no longer active", "iso_mount_not_found", 409);
      if (database.prepare(`SELECT 1 FROM iso_boot_overrides WHERE resource_id=?
        AND status IN ('arming','armed','restoring','error')`).get(resourceId)) {
        throw problem("A one-time ISO boot is already configured", "iso_boot_already_armed", 409);
      }
      const desiredBoot = String(armedBoot || "");
      if (!desiredBoot.startsWith("order=") || desiredBoot.length > 2048) throw problem("The generated boot order is invalid", "invalid_boot_order", 409);
      const savedBoot = originalBoot === null || originalBoot === undefined ? null : String(originalBoot).slice(0, 2048);
      const id = randomToken(18);
      const now = Date.now();
      database.prepare(`INSERT INTO iso_boot_overrides
        (id,resource_id,iso_mount_id,drive_slot,original_boot,armed_boot,status,created_by,created_at,updated_at)
        VALUES (?,?,?,?,?,?,'arming',?,?,?)`)
        .run(id, resourceId, isoMountId, slot, savedBoot, desiredBoot, createdBy, now, now);
      return database.prepare("SELECT * FROM iso_boot_overrides WHERE id=?").get(id);
    },
    getIsoBootOverride(id) {
      return database.prepare("SELECT * FROM iso_boot_overrides WHERE id=?").get(id);
    },
    getActiveIsoBootOverrideForResource(resourceId) {
      return database.prepare(`SELECT * FROM iso_boot_overrides WHERE resource_id=?
        AND status IN ('arming','armed','restoring','error') ORDER BY created_at DESC LIMIT 1`).get(resourceId);
    },
    publicIsoBootOverride,
    updateIsoBootOverride(id, { status, errorCode, armedAt, restoredAt } = {}) {
      const row = database.prepare("SELECT * FROM iso_boot_overrides WHERE id=?").get(id);
      if (!row) throw problem("The one-time ISO boot record does not exist", "iso_boot_not_found", 404);
      const nextStatus = status ?? row.status;
      if (!["arming", "armed", "restoring", "restored", "cancelled", "error"].includes(nextStatus)) {
        throw problem("The one-time ISO boot status is invalid", "invalid_iso_boot_status");
      }
      database.prepare(`UPDATE iso_boot_overrides
        SET status=?,error_code=?,armed_at=?,restored_at=?,updated_at=? WHERE id=?`)
        .run(
          nextStatus,
          errorCode === undefined ? row.error_code : errorCode,
          armedAt === undefined ? row.armed_at : armedAt,
          restoredAt === undefined ? row.restored_at : restoredAt,
          Date.now(),
          id,
        );
      return database.prepare("SELECT * FROM iso_boot_overrides WHERE id=?").get(id);
    },

    getNotificationPreferences(userId) {
      if (!getUserRow.get(userId)) throw problem("User does not exist", "user_not_found", 404);
      return publicNotificationPreferences(database.prepare("SELECT * FROM notification_preferences WHERE user_id=?").get(userId), userId);
    },
    updateNotificationPreferences(userId, input = {}) {
      if (!getUserRow.get(userId)) throw problem("User does not exist", "user_not_found", 404);
      const existing = database.prepare("SELECT * FROM notification_preferences WHERE user_id=?").get(userId);
      const current = publicNotificationPreferences(existing, userId);
      const next = {
        inAppEnabled: input.inAppEnabled === undefined ? current.inAppEnabled : Boolean(input.inAppEnabled),
        emailEnabled: input.emailEnabled === undefined ? current.emailEnabled : Boolean(input.emailEnabled),
        actionSuccess: input.actionSuccess === undefined ? current.actionSuccess : Boolean(input.actionSuccess),
        actionFailure: input.actionFailure === undefined ? current.actionFailure : Boolean(input.actionFailure),
        infrastructureAlerts: input.infrastructureAlerts === undefined ? current.infrastructureAlerts : Boolean(input.infrastructureAlerts),
        resolutionAlerts: input.resolutionAlerts === undefined ? current.resolutionAlerts : Boolean(input.resolutionAlerts),
      };
      const now = Date.now();
      database.prepare(`INSERT INTO notification_preferences
        (user_id,in_app_enabled,email_enabled,action_success,action_failure,infrastructure_alerts,resolution_alerts,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?)
        ON CONFLICT(user_id) DO UPDATE SET
          in_app_enabled=excluded.in_app_enabled,email_enabled=excluded.email_enabled,
          action_success=excluded.action_success,action_failure=excluded.action_failure,
          infrastructure_alerts=excluded.infrastructure_alerts,resolution_alerts=excluded.resolution_alerts,
          updated_at=excluded.updated_at`)
        .run(
          userId,
          next.inAppEnabled ? 1 : 0,
          next.emailEnabled ? 1 : 0,
          next.actionSuccess ? 1 : 0,
          next.actionFailure ? 1 : 0,
          next.infrastructureAlerts ? 1 : 0,
          next.resolutionAlerts ? 1 : 0,
          existing?.created_at || now,
          now,
        );
      return this.getNotificationPreferences(userId);
    },
    createNotificationEvent({ customerId, resourceId = null, category, type, severity, title, message, dedupKey }) {
      const categories = ["action_success", "action_failure", "infrastructure_alert", "resolution"];
      const severities = ["info", "success", "warning", "critical"];
      if (!getCustomerRow.get(customerId)) throw problem("Customer does not exist", "customer_not_found", 404);
      if (resourceId && !getResourceRow.get(resourceId)) throw problem("Resource does not exist", "resource_not_found", 404);
      if (!categories.includes(category) || !severities.includes(severity)) throw problem("Notification classification is invalid", "invalid_notification");
      const eventType = String(type || "").trim().slice(0, 80);
      const cleanTitle = String(title || "").trim().slice(0, 160);
      const cleanMessage = String(message || "").trim().slice(0, 1000);
      const key = String(dedupKey || "").trim().slice(0, 240);
      if (!eventType || !cleanTitle || !cleanMessage || !key) throw problem("Notification content is incomplete", "invalid_notification");
      const id = randomToken(18);
      const now = Date.now();
      const result = database.prepare(`INSERT OR IGNORE INTO notification_events
        (id,customer_id,resource_id,category,event_type,severity,title,message,dedup_key,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)`)
        .run(id, customerId, resourceId, category, eventType, severity, cleanTitle, cleanMessage, key, now);
      const row = result.changes
        ? database.prepare("SELECT * FROM notification_events WHERE id=?").get(id)
        : database.prepare("SELECT * FROM notification_events WHERE dedup_key=?").get(key);
      return { event: publicNotification(row), created: Boolean(result.changes) };
    },
    createNotificationDelivery({ eventId, userId, inAppVisible = true, emailJobId = null }) {
      const event = database.prepare("SELECT * FROM notification_events WHERE id=?").get(eventId);
      const user = database.prepare("SELECT * FROM users WHERE id=? AND role='customer' AND status='active'").get(userId);
      if (!event || !user || user.customer_id !== event.customer_id) throw problem("Notification recipient is invalid", "invalid_notification_recipient");
      const id = randomToken(18);
      const result = database.prepare(`INSERT OR IGNORE INTO notifications
        (id,event_id,user_id,in_app_visible,email_job_id,created_at) VALUES (?,?,?,?,?,?)`)
        .run(id, eventId, userId, inAppVisible ? 1 : 0, emailJobId, Date.now());
      const row = result.changes
        ? database.prepare("SELECT * FROM notifications WHERE id=?").get(id)
        : database.prepare("SELECT * FROM notifications WHERE event_id=? AND user_id=?").get(eventId, userId);
      return { id: row.id, eventId: row.event_id, userId: row.user_id, emailJobId: row.email_job_id || null, created: Boolean(result.changes) };
    },
    setNotificationEmailJob(notificationId, emailJobId) {
      database.prepare("UPDATE notifications SET email_job_id=? WHERE id=?").run(emailJobId, notificationId);
    },
    listNotifications(userId, { limit = 30, offset = 0 } = {}) {
      const safeLimit = Math.min(100, Math.max(1, Number(limit) || 30));
      const safeOffset = Math.max(0, Number(offset) || 0);
      const select = `SELECT n.id AS notification_id,n.event_id,n.read_at,n.email_job_id,
        e.customer_id,e.resource_id,e.category,e.event_type,e.severity,e.title,e.message,e.created_at,
        r.name AS resource_name,r.type AS resource_type,r.vmid
        FROM notifications n JOIN notification_events e ON e.id=n.event_id
        LEFT JOIN resources r ON r.id=e.resource_id
        WHERE n.user_id=? AND n.in_app_visible=1`;
      const items = database.prepare(`${select} ORDER BY e.created_at DESC LIMIT ? OFFSET ?`)
        .all(userId, safeLimit, safeOffset).map(publicNotification);
      const total = Number(database.prepare("SELECT COUNT(*) AS count FROM notifications WHERE user_id=? AND in_app_visible=1").get(userId).count);
      const unread = Number(database.prepare("SELECT COUNT(*) AS count FROM notifications WHERE user_id=? AND in_app_visible=1 AND read_at IS NULL").get(userId).count);
      return { items, total, unread, limit: safeLimit, offset: safeOffset };
    },
    listNotificationEvents({ limit = 50, offset = 0 } = {}) {
      const safeLimit = Math.min(100, Math.max(1, Number(limit) || 50));
      const safeOffset = Math.max(0, Number(offset) || 0);
      const items = database.prepare(`SELECT e.*,r.name AS resource_name,r.type AS resource_type,r.vmid,c.name AS customer_name
        FROM notification_events e JOIN customers c ON c.id=e.customer_id
        LEFT JOIN resources r ON r.id=e.resource_id
        ORDER BY e.created_at DESC LIMIT ? OFFSET ?`).all(safeLimit, safeOffset).map((row) => ({
          ...publicNotification(row),
          customerName: row.customer_name,
        }));
      const total = Number(database.prepare("SELECT COUNT(*) AS count FROM notification_events").get().count);
      return { items, total, limit: safeLimit, offset: safeOffset };
    },
    markNotificationRead(notificationId, userId) {
      const result = database.prepare("UPDATE notifications SET read_at=COALESCE(read_at,?) WHERE id=? AND user_id=? AND in_app_visible=1")
        .run(Date.now(), notificationId, userId);
      if (!result.changes) throw problem("Notification does not exist", "notification_not_found", 404);
    },
    markAllNotificationsRead(userId) {
      return database.prepare("UPDATE notifications SET read_at=? WHERE user_id=? AND in_app_visible=1 AND read_at IS NULL")
        .run(Date.now(), userId).changes;
    },

    getEmailSettings() {
      return publicEmailSettings(database.prepare("SELECT * FROM email_settings WHERE id='default'").get());
    },
    getEmailConnection() {
      const row = database.prepare("SELECT * FROM email_settings WHERE id='default'").get();
      if (!row) return null;
      return {
        enabled: Boolean(row.enabled),
        host: row.host,
        port: Number(row.port),
        security: row.security,
        username: row.username || "",
        password: row.password_encrypted ? decryptSecret(row.password_encrypted, appSecret) : "",
        fromName: row.from_name,
        fromEmail: row.from_email,
        replyTo: row.reply_to || "",
      };
    },
    saveEmailSettings(input, { userId = null } = {}) {
      const existing = database.prepare("SELECT * FROM email_settings WHERE id='default'").get();
      const normalized = normalizeEmailSettings(input, existing);
      let passwordEncrypted = existing?.password_encrypted || null;
      if (!normalized.username) {
        passwordEncrypted = null;
      } else if (input.password) {
        const password = String(input.password);
        if (password.length > 1024 || /[\r\n]/.test(password)) throw problem("SMTP password is invalid", "invalid_smtp_password");
        passwordEncrypted = encryptSecret(password, appSecret);
      } else if (!passwordEncrypted) {
        throw problem("Enter the SMTP password for this authenticated account", "smtp_password_required");
      }
      const now = Date.now();
      database.prepare(`INSERT INTO email_settings
        (id,enabled,host,port,security,username,password_encrypted,from_name,from_email,reply_to,app_url,updated_by,created_at,updated_at)
        VALUES ('default',?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
          enabled=excluded.enabled,host=excluded.host,port=excluded.port,security=excluded.security,
          username=excluded.username,password_encrypted=excluded.password_encrypted,from_name=excluded.from_name,
          from_email=excluded.from_email,reply_to=excluded.reply_to,app_url=excluded.app_url,updated_by=excluded.updated_by,
          last_test_at=NULL,last_test_status=NULL,last_test_error_code=NULL,updated_at=excluded.updated_at`)
        .run(
          normalized.enabled ? 1 : 0,
          normalized.host,
          normalized.port,
          normalized.security,
          normalized.username,
          passwordEncrypted,
          normalized.fromName,
          normalized.fromEmail,
          normalized.replyTo,
          normalized.appUrl,
          userId,
          existing?.created_at || now,
          now,
        );
      return this.getEmailSettings();
    },
    setEmailTestResult({ status, errorCode = null }) {
      if (!["success", "failed"].includes(status)) throw problem("Email test status is invalid");
      database.prepare(`UPDATE email_settings SET last_test_at=?,last_test_status=?,last_test_error_code=?,updated_at=?
        WHERE id='default'`).run(Date.now(), status, errorCode, Date.now());
      return this.getEmailSettings();
    },
    queueEmail({ to, subject, text = "", html = "", category = "transactional", createdBy = null, maxAttempts = 4 }) {
      const toEmail = normalizeMailbox(to, "Recipient");
      const cleanSubject = String(subject || "").trim();
      const cleanCategory = String(category || "").trim().toLowerCase();
      const attemptLimit = Number(maxAttempts);
      if (!cleanSubject || cleanSubject.length > 240 || /[\r\n]/.test(cleanSubject)) throw problem("Email subject is invalid", "invalid_email_message");
      if (!/^[a-z0-9][a-z0-9_.-]{1,63}$/.test(cleanCategory)) throw problem("Email category is invalid", "invalid_email_message");
      if (!Number.isSafeInteger(attemptLimit) || attemptLimit < 1 || attemptLimit > 10) throw problem("Email retry limit is invalid");
      const payload = JSON.stringify({ text: String(text || ""), html: String(html || "") });
      if (Buffer.byteLength(payload) > 512 * 1024) throw problem("Email content is too large", "email_too_large", 413);
      const id = randomToken(18);
      const now = Date.now();
      database.prepare(`INSERT INTO email_jobs
        (id,to_email,subject,payload_encrypted,category,status,attempts,max_attempts,next_attempt_at,created_by,created_at,updated_at)
        VALUES (?,?,?,?,?,'pending',0,?,?,?,?,?)`)
        .run(id, toEmail, cleanSubject, encryptSecret(payload, appSecret), cleanCategory, attemptLimit, now, createdBy, now, now);
      return publicEmailJob(database.prepare("SELECT * FROM email_jobs WHERE id=?").get(id));
    },
    getEmailJob(id) {
      return publicEmailJob(database.prepare("SELECT * FROM email_jobs WHERE id=?").get(id));
    },
    listEmailJobs({ limit = 30, offset = 0 } = {}) {
      const safeLimit = Math.min(100, Math.max(1, Number(limit) || 30));
      const safeOffset = Math.max(0, Number(offset) || 0);
      const items = database.prepare("SELECT * FROM email_jobs ORDER BY created_at DESC LIMIT ? OFFSET ?")
        .all(safeLimit, safeOffset).map(publicEmailJob);
      const total = Number(database.prepare("SELECT COUNT(*) AS count FROM email_jobs").get().count);
      return { items, total, limit: safeLimit, offset: safeOffset };
    },
    claimEmailJob(id = null) {
      const now = Date.now();
      database.exec("BEGIN IMMEDIATE");
      try {
        const row = id
          ? database.prepare("SELECT * FROM email_jobs WHERE id=? AND status='pending' AND next_attempt_at<=?").get(id, now)
          : database.prepare("SELECT * FROM email_jobs WHERE status='pending' AND next_attempt_at<=? ORDER BY created_at LIMIT 1").get(now);
        if (!row) {
          database.exec("COMMIT");
          return null;
        }
        database.prepare("UPDATE email_jobs SET status='processing',attempts=attempts+1,locked_at=?,updated_at=? WHERE id=?")
          .run(now, now, row.id);
        database.exec("COMMIT");
        return database.prepare("SELECT * FROM email_jobs WHERE id=?").get(row.id);
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
    },
    getEmailJobPayload(id) {
      const row = database.prepare("SELECT payload_encrypted FROM email_jobs WHERE id=?").get(id);
      if (!row?.payload_encrypted) return null;
      return parseJson(decryptSecret(row.payload_encrypted, appSecret), null);
    },
    completeEmailJob(id, { providerMessageId = null } = {}) {
      const now = Date.now();
      database.prepare(`UPDATE email_jobs SET status='sent',payload_encrypted='',provider_message_id=?,
        last_error_code=NULL,locked_at=NULL,sent_at=?,updated_at=? WHERE id=? AND status='processing'`)
        .run(providerMessageId, now, now, id);
      return this.getEmailJob(id);
    },
    failEmailJob(id, { errorCode = "email_delivery_failed", retryable = true } = {}) {
      const row = database.prepare("SELECT * FROM email_jobs WHERE id=?").get(id);
      if (!row) throw problem("Email job does not exist", "email_job_not_found", 404);
      const shouldRetry = Boolean(retryable) && Number(row.attempts) < Number(row.max_attempts);
      const delays = [60_000, 5 * 60_000, 30 * 60_000, 2 * 60 * 60_000];
      const nextAttemptAt = shouldRetry ? Date.now() + delays[Math.min(delays.length - 1, Math.max(0, Number(row.attempts) - 1))] : row.next_attempt_at;
      database.prepare(`UPDATE email_jobs SET status=?,next_attempt_at=?,locked_at=NULL,last_error_code=?,updated_at=? WHERE id=?`)
        .run(shouldRetry ? "pending" : "failed", nextAttemptAt, String(errorCode).slice(0, 80), Date.now(), id);
      return this.getEmailJob(id);
    },
    retryEmailJob(id) {
      const row = database.prepare("SELECT * FROM email_jobs WHERE id=?").get(id);
      if (!row) throw problem("Email job does not exist", "email_job_not_found", 404);
      if (row.status !== "failed" || !row.payload_encrypted) throw problem("Only failed email jobs with retained content can be retried", "email_job_not_retryable", 409);
      database.prepare(`UPDATE email_jobs SET status='pending',attempts=0,next_attempt_at=?,locked_at=NULL,
        last_error_code=NULL,updated_at=? WHERE id=?`).run(Date.now(), Date.now(), id);
      return this.getEmailJob(id);
    },
    recoverEmailJobs({ staleAfterMs = 10 * 60_000 } = {}) {
      return database.prepare(`UPDATE email_jobs SET status='pending',locked_at=NULL,next_attempt_at=?,updated_at=?
        WHERE status='processing' AND (locked_at IS NULL OR locked_at<?)`)
        .run(Date.now(), Date.now(), Date.now() - staleAfterMs).changes;
    },

    createAccountToken({
      userId,
      purpose,
      ttlMs = 30 * 60_000,
      createdBy = null,
      requestedIp = null,
    }) {
      if (!["invitation", "password_reset"].includes(purpose)) throw problem("Account token purpose is invalid");
      const user = getUserRow.get(userId);
      if (!user || user.status !== "active" || (user.role === "customer" && user.customer_status !== "active")) {
        throw problem("User does not exist", "user_not_found", 404);
      }
      if (purpose === "invitation" && user.password_set) throw problem("This user has already completed onboarding", "invitation_not_pending", 409);
      if (purpose === "password_reset" && !user.password_set) throw problem("This user has not completed onboarding", "password_not_set", 409);
      const token = randomToken(32);
      const now = Date.now();
      database.exec("BEGIN IMMEDIATE");
      try {
        database.prepare("UPDATE account_tokens SET used_at=? WHERE user_id=? AND purpose=? AND used_at IS NULL")
          .run(now, userId, purpose);
        database.prepare(`DELETE FROM account_tokens
          WHERE (used_at IS NOT NULL AND used_at<?) OR (used_at IS NULL AND expires_at<?)`)
          .run(now - 7 * 86400_000, now - 7 * 86400_000);
        database.prepare(`INSERT INTO account_tokens
          (id_hash,user_id,purpose,created_by,requested_ip,expires_at,used_at,created_at)
          VALUES (?,?,?,?,?,?,NULL,?)`)
          .run(
            hashToken(token, appSecret),
            userId,
            purpose,
            createdBy,
            String(requestedIp || "").slice(0, 80) || null,
            now + ttlMs,
            now,
          );
        database.exec("COMMIT");
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
      return { token, purpose, expiresAt: now + ttlMs, user: publicUser(getUserRow.get(userId)) };
    },
    getAccountToken(token, purpose) {
      if (!token || !["invitation", "password_reset"].includes(purpose)) return null;
      const row = database.prepare(`SELECT t.*,u.email,u.display_name,u.role,u.status AS user_status,
        u.password_set,u.customer_id,c.status AS customer_status,c.name AS customer_name
        FROM account_tokens t
        JOIN users u ON u.id=t.user_id
        LEFT JOIN customers c ON c.id=u.customer_id
        WHERE t.id_hash=? AND t.purpose=? AND t.used_at IS NULL AND t.expires_at>?`)
        .get(hashToken(String(token), appSecret), purpose, Date.now());
      if (!row || row.user_status !== "active" || (row.role === "customer" && row.customer_status !== "active")) return null;
      if (purpose === "invitation" && row.password_set) return null;
      if (purpose === "password_reset" && !row.password_set) return null;
      return row;
    },
    async consumeAccountToken(token, purpose, password) {
      const passwordHash = await hashPassword(password);
      const idHash = hashToken(String(token || ""), appSecret);
      let userId = null;
      database.exec("BEGIN IMMEDIATE");
      try {
        const row = database.prepare(`SELECT t.user_id,u.role,u.status,u.password_set,c.status AS customer_status
          FROM account_tokens t
          JOIN users u ON u.id=t.user_id
          LEFT JOIN customers c ON c.id=u.customer_id
          WHERE t.id_hash=? AND t.purpose=? AND t.used_at IS NULL AND t.expires_at>?`)
          .get(idHash, purpose, Date.now());
        const valid = row
          && row.status === "active"
          && (row.role !== "customer" || row.customer_status === "active")
          && (purpose === "invitation" ? !row.password_set : Boolean(row.password_set));
        if (!valid) {
          database.exec("ROLLBACK");
          return null;
        }
        userId = row.user_id;
        const now = Date.now();
        database.prepare("UPDATE users SET password_hash=?,password_set=1,updated_at=? WHERE id=?")
          .run(passwordHash, now, userId);
        database.prepare("UPDATE account_tokens SET used_at=? WHERE user_id=? AND used_at IS NULL").run(now, userId);
        database.prepare("DELETE FROM sessions WHERE user_id=?").run(userId);
        database.exec("COMMIT");
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
      return publicUser(getUserRow.get(userId));
    },
    revokeAccountTokens(userId, purpose = "invitation") {
      if (!["invitation", "password_reset"].includes(purpose)) throw problem("Account token purpose is invalid");
      return database.prepare("UPDATE account_tokens SET used_at=? WHERE user_id=? AND purpose=? AND used_at IS NULL")
        .run(Date.now(), userId, purpose).changes;
    },

    getMfaStatus(userId) {
      const row = database.prepare("SELECT enabled,recovery_code_hashes,confirmed_at,setup_expires_at FROM user_mfa WHERE user_id=?").get(userId);
      return {
        enabled: Boolean(row?.enabled),
        pending: Boolean(row && !row.enabled && Number(row.setup_expires_at) > Date.now()),
        recoveryCodesRemaining: row?.enabled ? parseJson(row.recovery_code_hashes, []).length : 0,
        confirmedAt: row?.confirmed_at || null,
      };
    },
    saveMfaSetup(userId, secret, { ttlMs = 10 * 60_000 } = {}) {
      if (!getUserRow.get(userId)) throw problem("User does not exist", "user_not_found", 404);
      const existing = database.prepare("SELECT enabled,created_at FROM user_mfa WHERE user_id=?").get(userId);
      if (existing?.enabled) throw problem("Two-factor authentication is already enabled", "mfa_already_enabled", 409);
      const now = Date.now();
      database.prepare(`INSERT INTO user_mfa
        (user_id,totp_secret_encrypted,enabled,recovery_code_hashes,setup_expires_at,confirmed_at,created_at,updated_at)
        VALUES (?,?,0,'[]',?,NULL,?,?)
        ON CONFLICT(user_id) DO UPDATE SET
          totp_secret_encrypted=excluded.totp_secret_encrypted,enabled=0,recovery_code_hashes='[]',
          setup_expires_at=excluded.setup_expires_at,confirmed_at=NULL,updated_at=excluded.updated_at`)
        .run(userId, encryptSecret(secret, appSecret), now + ttlMs, existing?.created_at || now, now);
      return { expiresAt: now + ttlMs };
    },
    getMfaSecret(userId, { pending = false } = {}) {
      const row = database.prepare("SELECT * FROM user_mfa WHERE user_id=?").get(userId);
      if (!row) return null;
      if (pending) {
        if (row.enabled || Number(row.setup_expires_at) <= Date.now()) return null;
      } else if (!row.enabled) return null;
      return decryptSecret(row.totp_secret_encrypted, appSecret);
    },
    enableMfa(userId, recoveryCodes) {
      const row = database.prepare("SELECT enabled,setup_expires_at FROM user_mfa WHERE user_id=?").get(userId);
      if (!row || row.enabled || Number(row.setup_expires_at) <= Date.now()) {
        throw problem("Start two-factor setup again", "mfa_setup_expired", 409);
      }
      const hashes = recoveryCodes.map((code) => hashToken(normalizeMfaCode(code), appSecret));
      const now = Date.now();
      database.prepare(`UPDATE user_mfa SET enabled=1,recovery_code_hashes=?,setup_expires_at=NULL,
        confirmed_at=?,updated_at=? WHERE user_id=?`).run(JSON.stringify(hashes), now, now, userId);
      return this.getMfaStatus(userId);
    },
    disableMfa(userId) {
      database.prepare("DELETE FROM user_mfa WHERE user_id=?").run(userId);
      database.prepare("DELETE FROM mfa_login_challenges WHERE user_id=?").run(userId);
      return this.getMfaStatus(userId);
    },
    replaceRecoveryCodes(userId, recoveryCodes) {
      const row = database.prepare("SELECT enabled FROM user_mfa WHERE user_id=?").get(userId);
      if (!row?.enabled) throw problem("Two-factor authentication is not enabled", "mfa_not_enabled", 409);
      const hashes = recoveryCodes.map((code) => hashToken(normalizeMfaCode(code), appSecret));
      database.prepare("UPDATE user_mfa SET recovery_code_hashes=?,updated_at=? WHERE user_id=?")
        .run(JSON.stringify(hashes), Date.now(), userId);
      return this.getMfaStatus(userId);
    },
    consumeRecoveryCode(userId, code) {
      const normalized = normalizeMfaCode(code);
      if (!/^[A-Z2-9]{10}$/.test(normalized)) return false;
      const target = hashToken(normalized, appSecret);
      database.exec("BEGIN IMMEDIATE");
      try {
        const row = database.prepare("SELECT enabled,recovery_code_hashes FROM user_mfa WHERE user_id=?").get(userId);
        const hashes = row?.enabled ? parseJson(row.recovery_code_hashes, []) : [];
        const index = hashes.findIndex((value) => safeEqual(value, target));
        if (index < 0) {
          database.exec("ROLLBACK");
          return false;
        }
        hashes.splice(index, 1);
        database.prepare("UPDATE user_mfa SET recovery_code_hashes=?,updated_at=? WHERE user_id=?")
          .run(JSON.stringify(hashes), Date.now(), userId);
        database.exec("COMMIT");
        return true;
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
    },
    createMfaChallenge({ userId, ttlMs = 5 * 60_000 }) {
      const token = randomToken();
      const now = Date.now();
      database.prepare("DELETE FROM mfa_login_challenges WHERE expires_at<=?").run(now);
      database.prepare("DELETE FROM mfa_login_challenges WHERE user_id=?").run(userId);
      database.prepare("INSERT INTO mfa_login_challenges (id_hash,user_id,attempts,expires_at,created_at) VALUES (?,?,0,?,?)")
        .run(hashToken(token, appSecret), userId, now + ttlMs, now);
      return { token, expiresAt: now + ttlMs };
    },
    getMfaChallenge(token) {
      if (!token) return null;
      return database.prepare("SELECT * FROM mfa_login_challenges WHERE id_hash=? AND expires_at>?")
        .get(hashToken(token, appSecret), Date.now()) || null;
    },
    failMfaChallenge(token, { maxAttempts = 8 } = {}) {
      const idHash = hashToken(token, appSecret);
      database.prepare("UPDATE mfa_login_challenges SET attempts=attempts+1 WHERE id_hash=?").run(idHash);
      const row = database.prepare("SELECT attempts FROM mfa_login_challenges WHERE id_hash=?").get(idHash);
      if (Number(row?.attempts || 0) >= maxAttempts) database.prepare("DELETE FROM mfa_login_challenges WHERE id_hash=?").run(idHash);
      return Number(row?.attempts || 0);
    },
    consumeMfaChallenge(token) {
      const idHash = hashToken(token, appSecret);
      const row = database.prepare("SELECT * FROM mfa_login_challenges WHERE id_hash=? AND expires_at>?").get(idHash, Date.now());
      if (!row) return null;
      database.prepare("DELETE FROM mfa_login_challenges WHERE id_hash=?").run(idHash);
      return row;
    },

    createSession({ userId, ttlMs, ipAddress = null, userAgent = null }) {
      const token = randomToken();
      const csrfToken = randomToken(24);
      const now = Date.now();
      database.prepare("DELETE FROM sessions WHERE expires_at<=?").run(now);
      database.prepare(`INSERT INTO sessions
        (id_hash,user_id,csrf_token,ip_address,user_agent,expires_at,created_at,last_seen_at)
        VALUES (?,?,?,?,?,?,?,?)`)
        .run(
          hashToken(token, appSecret),
          userId,
          csrfToken,
          String(ipAddress || "").slice(0, 80) || null,
          String(userAgent || "").slice(0, 300) || null,
          now + ttlMs,
          now,
          now,
        );
      return { token, csrfToken, expiresAt: now + ttlMs };
    },
    getSession(token) {
      if (!token) return null;
      const row = database.prepare(`SELECT s.*,u.*,c.name AS customer_name,c.status AS customer_status,c.support_email,c.plan_name,
        CASE WHEN m.enabled=1 THEN 1 ELSE 0 END AS mfa_enabled
        FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN customers c ON c.id=u.customer_id
        LEFT JOIN user_mfa m ON m.user_id=u.id
        WHERE s.id_hash=? AND s.expires_at>?`).get(hashToken(token, appSecret), Date.now());
      if (!row || row.status !== "active" || (row.role === "customer" && row.customer_status !== "active")) return null;
      if (Date.now() - row.last_seen_at > 300000) database.prepare("UPDATE sessions SET last_seen_at=? WHERE id_hash=?").run(Date.now(), row.id_hash);
      return { idHash: row.id_hash, csrfToken: row.csrf_token, expiresAt: row.expires_at, user: publicUser(row) };
    },
    deleteSession(token) { if (token) database.prepare("DELETE FROM sessions WHERE id_hash=?").run(hashToken(token, appSecret)); },
    listSessions(userId, { currentIdHash = null } = {}) {
      database.prepare("DELETE FROM sessions WHERE expires_at<=?").run(Date.now());
      return database.prepare("SELECT * FROM sessions WHERE user_id=? ORDER BY last_seen_at DESC")
        .all(userId).map((row) => publicSession(row, currentIdHash));
    },
    deleteUserSession(userId, idHash) {
      return database.prepare("DELETE FROM sessions WHERE user_id=? AND id_hash=?").run(userId, idHash).changes > 0;
    },
    deleteOtherSessions(userId, currentIdHash) {
      return database.prepare("DELETE FROM sessions WHERE user_id=? AND id_hash<>?").run(userId, currentIdHash).changes;
    },
    revokeUserSessions(userId) {
      return database.prepare("DELETE FROM sessions WHERE user_id=?").run(userId).changes;
    },

    writeAudit({ customerId = null, userId = null, actorRole = "system", action, resourceId = null, detail = {}, ipAddress = null }) {
      database.prepare("INSERT INTO audit_logs (customer_id,actor_user_id,actor_role,action,resource_id,detail,ip_address,created_at) VALUES (?,?,?,?,?,?,?,?)")
        .run(customerId, userId, actorRole, action, resourceId, JSON.stringify(detail), ipAddress, Date.now());
    },
    listAudit(customerId = null, { limit = 30, offset = 0, all = false } = {}) {
      const safeLimit = Math.min(100, Math.max(1, Number(limit) || 30));
      const safeOffset = Math.max(0, Number(offset) || 0);
      const where = all ? "" : "WHERE a.customer_id=?";
      const params = all ? [safeLimit, safeOffset] : [customerId, safeLimit, safeOffset];
      const rows = database.prepare(`SELECT a.*,u.display_name,c.name AS customer_name FROM audit_logs a
        LEFT JOIN users u ON u.id=a.actor_user_id LEFT JOIN customers c ON c.id=a.customer_id
        ${where} ORDER BY a.created_at DESC LIMIT ? OFFSET ?`).all(...params);
      const total = all
        ? database.prepare("SELECT COUNT(*) AS count FROM audit_logs").get().count
        : database.prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE customer_id=?").get(customerId).count;
      return { items: rows.map((row) => ({
        id: row.id, customerId: row.customer_id, customerName: row.customer_name, userId: row.actor_user_id,
        displayName: row.display_name, actorRole: row.actor_role, action: row.action, resourceId: row.resource_id,
        detail: parseJson(row.detail, {}), ipAddress: row.ip_address, createdAt: row.created_at,
      })), total, limit: safeLimit, offset: safeOffset };
    },

    createTask({ customerId, userId, clusterId, node, upid, resourceId, action, idempotencyKey = null }) {
      const id = randomToken(18);
      database.prepare(`INSERT INTO api_tasks
        (id,customer_id,user_id,cluster_id,node,upid,resource_id,action,status,idempotency_key,created_at)
        VALUES (?,?,?,?,?,?,?,?,'pending',?,?)`)
        .run(id, customerId, userId, clusterId, node, upid, resourceId, action, idempotencyKey, Date.now());
      return publicTask(database.prepare("SELECT * FROM api_tasks WHERE id=?").get(id));
    },
    getTask(id, user) {
      if (user.role === "admin") return database.prepare("SELECT * FROM api_tasks WHERE id=?").get(id);
      return database.prepare("SELECT * FROM api_tasks WHERE id=? AND customer_id=?").get(id, user.customerId);
    },
    listTasks(user, { resourceId = null, limit = 20 } = {}) {
      const safeLimit = Math.min(50, Math.max(1, Number(limit) || 20));
      const clauses = [];
      const params = [];
      if (user.role !== "admin") {
        clauses.push("customer_id=?");
        params.push(user.customerId);
      }
      if (resourceId) {
        clauses.push("resource_id=?");
        params.push(resourceId);
      }
      const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
      return database.prepare(`SELECT * FROM api_tasks ${where} ORDER BY created_at DESC LIMIT ?`)
        .all(...params, safeLimit)
        .map(publicTask);
    },
    getActiveTask(resourceId, { maxAgeMs = 30 * 60 * 1000 } = {}) {
      return database.prepare(`SELECT * FROM api_tasks
        WHERE resource_id=? AND completed_at IS NULL AND status!='stopped' AND created_at>=?
        ORDER BY created_at DESC LIMIT 1`).get(resourceId, Date.now() - maxAgeMs);
    },
    listActiveTasksForCluster(clusterId, { maxAgeMs = 24 * 60 * 60 * 1000, limit = 100 } = {}) {
      const safeLimit = Math.min(500, Math.max(1, Number(limit) || 100));
      return database.prepare(`SELECT * FROM api_tasks
        WHERE cluster_id=? AND completed_at IS NULL AND status!='stopped' AND created_at>=?
        ORDER BY created_at LIMIT ?`).all(clusterId, Date.now() - maxAgeMs, safeLimit);
    },
    hasRecentSuccessfulTask(resourceId, actions, { since = Date.now() - 15 * 60_000 } = {}) {
      const requested = (Array.isArray(actions) ? actions : [actions]).filter(Boolean);
      if (!requested.length) return false;
      const placeholders = requested.map(() => "?").join(",");
      return Boolean(database.prepare(`SELECT 1 FROM api_tasks
        WHERE resource_id=? AND action IN (${placeholders}) AND exit_status='OK' AND completed_at>=?
        ORDER BY completed_at DESC LIMIT 1`).get(resourceId, ...requested, since));
    },
    hasRecentTaskRequest(resourceId, actions, { since = Date.now() - 15 * 60_000 } = {}) {
      const requested = (Array.isArray(actions) ? actions : [actions]).filter(Boolean);
      if (!requested.length) return false;
      const placeholders = requested.map(() => "?").join(",");
      return Boolean(database.prepare(`SELECT 1 FROM api_tasks
        WHERE resource_id=? AND action IN (${placeholders}) AND created_at>=?
          AND (completed_at IS NULL OR exit_status='OK')
        ORDER BY created_at DESC LIMIT 1`).get(resourceId, ...requested, since));
    },
    publicTask,
    getTaskByIdempotency(userId, key) {
      return key ? database.prepare("SELECT * FROM api_tasks WHERE user_id=? AND idempotency_key=?").get(userId, key) : null;
    },
    updateTask(id, { status, exitStatus = null, completedAt = null }) {
      database.prepare("UPDATE api_tasks SET status=?,exit_status=?,completed_at=?,last_checked_at=? WHERE id=?")
        .run(status, exitStatus, completedAt, Date.now(), id);
      return database.prepare("SELECT * FROM api_tasks WHERE id=?").get(id);
    },

    createConsoleSession({ userId, resourceId, ticket, port, ttlMs = 45_000 }) {
      const token = randomToken(24);
      const now = Date.now();
      database.prepare("DELETE FROM console_sessions WHERE expires_at<=? OR used_at IS NOT NULL").run(now);
      database.prepare("INSERT INTO console_sessions (id_hash,user_id,resource_id,ticket_encrypted,port,expires_at,created_at) VALUES (?,?,?,?,?,?,?)")
        .run(hashToken(token, appSecret), userId, resourceId, encryptSecret(ticket, appSecret), Number(port), now + ttlMs, now);
      return { token, expiresAt: now + ttlMs };
    },
    getConsoleSession(token, userId) {
      const row = database.prepare("SELECT cs.resource_id,cs.ticket_encrypted,cs.expires_at,r.cluster_id,r.node,r.type,r.vmid,r.name FROM console_sessions cs JOIN resources r ON r.id=cs.resource_id WHERE cs.id_hash=? AND cs.user_id=? AND cs.expires_at>? AND cs.used_at IS NULL")
        .get(hashToken(token, appSecret), userId, Date.now());
      return row ? {
        resourceId: row.resource_id, expiresAt: row.expires_at, clusterId: row.cluster_id,
        node: row.node, type: row.type, vmid: row.vmid, name: row.name,
        password: decryptSecret(row.ticket_encrypted, appSecret),
      } : null;
    },
    consumeConsoleSession(token, userId) {
      const idHash = hashToken(token, appSecret);
      const row = database.prepare("SELECT * FROM console_sessions WHERE id_hash=? AND user_id=? AND expires_at>? AND used_at IS NULL")
        .get(idHash, userId, Date.now());
      if (!row) return null;
      database.prepare("UPDATE console_sessions SET used_at=? WHERE id_hash=?").run(Date.now(), idHash);
      return { ...row, ticket: decryptSecret(row.ticket_encrypted, appSecret) };
    },
    close: () => database.close(),
  };
}

export async function bootstrapStore(store, bootstrap) {
  if (store.hasUsers() || !bootstrap.email || !bootstrap.password) return false;
  let customer = null;
  if (bootstrap.customerId) {
    customer = store.createCustomer({
      id: bootstrap.customerId,
      name: bootstrap.customerName || "Demo customer",
      supportEmail: bootstrap.supportEmail || "",
      planName: bootstrap.planName || "Managed infrastructure",
    });
  }
  await store.createUser({
    email: bootstrap.email,
    displayName: bootstrap.displayName || "Administrator",
    password: bootstrap.password,
    role: "admin",
    customerId: null,
  });
  if (bootstrap.customerEmail && customer) {
    await store.createUser({
      email: bootstrap.customerEmail,
      displayName: bootstrap.customerDisplayName || customer.name,
      password: bootstrap.customerPassword,
      role: "customer",
      customerId: customer.id,
    });
  }
  return true;
}
