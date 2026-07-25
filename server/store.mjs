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
} from "./security.mjs";

export const ASSIGNMENT_PERMISSIONS = [
  "view_status", "start", "stop", "shutdown", "reboot", "reset", "suspend", "resume",
  "console", "view_config", "view_usage", "snapshot_create", "snapshot_restore", "snapshot_delete",
  "config_change", "iso_view", "iso_upload", "iso_mount", "iso_delete",
];

export const DEFAULT_PERMISSIONS = [
  "view_status", "start", "stop", "shutdown", "reboot", "suspend", "resume", "console",
  "view_config", "view_usage",
];

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
    createdAt: row.created_at,
    updatedAt: row.updated_at,
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
    permissions,
    metadata,
  };
}

function publicTask(row) {
  if (!row) return null;
  const completed = Boolean(row.completed_at) || row.status === "stopped";
  const success = completed ? row.exit_status === "OK" : null;
  return {
    id: row.id,
    resourceId: row.resource_id,
    node: row.node,
    action: row.action,
    status: row.status,
    state: completed ? (success ? "success" : "failed") : "running",
    completed,
    success,
    message: completed
      ? (success ? "Completed successfully." : "Proxmox reported that the task failed.")
      : "Proxmox is processing this action.",
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

function customerSelect(where = "") {
  return `SELECT c.*,
    (SELECT COUNT(*) FROM customer_resource_assignments a WHERE a.customer_id=c.id AND a.status='active') AS resource_count,
    (SELECT COUNT(*) FROM users u WHERE u.customer_id=c.id) AS user_count
    FROM customers c ${where}`;
}

function userSelect(where = "") {
  return `SELECT u.*,c.name AS customer_name,c.support_email,c.plan_name
    FROM users u LEFT JOIN customers c ON c.id=u.customer_id ${where}`;
}

function clusterSelect(where = "") {
  return `SELECT c.*,pc.token_id,
    (SELECT COUNT(*) FROM resources r WHERE r.cluster_id=c.id) AS resource_count,
    (SELECT COUNT(*) FROM proxmox_nodes n WHERE n.cluster_id=c.id) AS node_count
    FROM proxmox_clusters c LEFT JOIN proxmox_credentials pc ON pc.cluster_id=c.id ${where}`;
}

function resourceSelect(where = "") {
  return `SELECT r.*,pc.name AS cluster_name,a.id AS assignment_id,a.customer_id,a.status AS assignment_status,
    a.display_name,c.name AS customer_name,GROUP_CONCAT(ap.permission) AS permissions
    FROM resources r
    JOIN proxmox_clusters pc ON pc.id=r.cluster_id
    LEFT JOIN customer_resource_assignments a ON a.resource_id=r.id AND a.status='active'
    LEFT JOIN customers c ON c.id=a.customer_id
    LEFT JOIN assignment_permissions ap ON ap.assignment_id=a.id AND ap.allowed=1
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
      role TEXT NOT NULL CHECK(role IN ('admin','customer')),
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
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
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      last_seen_at INTEGER NOT NULL
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
    CREATE UNIQUE INDEX IF NOT EXISTS tasks_idempotency_idx ON api_tasks(user_id,idempotency_key) WHERE idempotency_key IS NOT NULL;
  `);

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
    findUserForLogin: (email) => getUserByEmailRow.get(normalizeEmail(email)),
    getUserForAuth: (id) => getUserRow.get(id),
    listUsers: () => database.prepare(userSelect("ORDER BY u.email")).all().map(publicUser),
    listCustomerUsers: (customerId) => database.prepare(userSelect("WHERE u.customer_id=? ORDER BY u.display_name")).all(customerId).map(publicUser),
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
      database.prepare("UPDATE users SET password_hash=?,updated_at=? WHERE id=?").run(await hashPassword(password), Date.now(), id);
      if (revokeSessions) database.prepare("DELETE FROM sessions WHERE user_id=?").run(id);
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
    assignResource({ customerId, resourceId, displayName = null, permissions = DEFAULT_PERMISSIONS }) {
      if (!getCustomerRow.get(customerId)) throw problem("Customer does not exist", "customer_not_found", 404);
      if (!getResourceRow.get(resourceId)) throw problem("Resource does not exist", "resource_not_found", 404);
      const existing = database.prepare("SELECT * FROM customer_resource_assignments WHERE resource_id=?").get(resourceId);
      if (existing?.customer_id !== customerId && database.prepare("SELECT 1 FROM iso_mounts WHERE resource_id=? AND status='active' LIMIT 1").get(resourceId)) {
        throw problem("Eject the mounted customer ISO before reassigning this resource", "resource_iso_mounted", 409);
      }
      const now = Date.now();
      const assignmentId = existing?.id || randomToken(18);
      database.exec("BEGIN IMMEDIATE");
      try {
        if (existing) {
          database.prepare("UPDATE customer_resource_assignments SET customer_id=?,display_name=?,status='active',updated_at=? WHERE id=?")
            .run(customerId, displayName || null, now, assignmentId);
        } else {
          database.prepare("INSERT INTO customer_resource_assignments (id,customer_id,resource_id,display_name,status,created_at,updated_at) VALUES (?,?,?,?,'active',?,?)")
            .run(assignmentId, customerId, resourceId, displayName || null, now, now);
        }
        replacePermissions(assignmentId, permissions);
        database.exec("COMMIT");
      } catch (error) { database.exec("ROLLBACK"); throw error; }
      return this.getResource(resourceId);
    },
    updateAssignment(resourceId, { displayName, permissions, status }) {
      const existing = database.prepare("SELECT * FROM customer_resource_assignments WHERE resource_id=?").get(resourceId);
      if (!existing) throw problem("Assignment does not exist", "assignment_not_found", 404);
      database.prepare("UPDATE customer_resource_assignments SET display_name=?,status=?,updated_at=? WHERE id=?")
        .run(displayName === undefined ? existing.display_name : (displayName || null), status || existing.status, Date.now(), existing.id);
      if (permissions !== undefined) replacePermissions(existing.id, permissions);
      return this.getResource(resourceId);
    },
    unassignResource(resourceId) {
      if (database.prepare("SELECT 1 FROM iso_mounts WHERE resource_id=? AND status='active' LIMIT 1").get(resourceId)) {
        throw problem("Eject the mounted customer ISO before removing this assignment", "resource_iso_mounted", 409);
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

    createSession({ userId, ttlMs }) {
      const token = randomToken();
      const csrfToken = randomToken(24);
      const now = Date.now();
      database.prepare("DELETE FROM sessions WHERE expires_at<=?").run(now);
      database.prepare("INSERT INTO sessions (id_hash,user_id,csrf_token,expires_at,created_at,last_seen_at) VALUES (?,?,?,?,?,?)")
        .run(hashToken(token, appSecret), userId, csrfToken, now + ttlMs, now, now);
      return { token, csrfToken, expiresAt: now + ttlMs };
    },
    getSession(token) {
      if (!token) return null;
      const row = database.prepare(`SELECT s.*,u.*,c.name AS customer_name,c.status AS customer_status,c.support_email,c.plan_name
        FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN customers c ON c.id=u.customer_id
        WHERE s.id_hash=? AND s.expires_at>?`).get(hashToken(token, appSecret), Date.now());
      if (!row || row.status !== "active" || (row.role === "customer" && row.customer_status !== "active")) return null;
      if (Date.now() - row.last_seen_at > 300000) database.prepare("UPDATE sessions SET last_seen_at=? WHERE id_hash=?").run(Date.now(), row.id_hash);
      return { idHash: row.id_hash, csrfToken: row.csrf_token, expiresAt: row.expires_at, user: publicUser(row) };
    },
    deleteSession(token) { if (token) database.prepare("DELETE FROM sessions WHERE id_hash=?").run(hashToken(token, appSecret)); },

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
