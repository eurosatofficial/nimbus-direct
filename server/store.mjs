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

export const API_PERMISSION_GROUPS = Object.freeze([
  { id: "server_overview", label: "Server overview", description: "Read assigned server status, configuration, usage, network information, and task status.", roles: ["customer", "admin"], resourceScoped: true },
  { id: "power_management", label: "Power management", description: "Start, stop, shut down, reboot, reset, suspend, and resume permitted servers.", roles: ["customer", "admin"], resourceScoped: true },
  { id: "snapshot_management", label: "Snapshot management", description: "View, create, restore, and delete snapshots where the assignment permits it.", roles: ["customer", "admin"], resourceScoped: true },
  { id: "installation_media", label: "Installation media", description: "View, upload, mount, eject, boot, and delete customer ISO images where permitted.", roles: ["customer", "admin"], resourceScoped: true },
  { id: "console_access", label: "Console access", description: "Create short-lived console sessions for permitted servers.", roles: ["customer", "admin"], resourceScoped: true },
  { id: "notifications", label: "Notifications", description: "Read and acknowledge account notifications.", roles: ["customer", "admin"], resourceScoped: false },
  { id: "maintenance_information", label: "Maintenance information", description: "Read maintenance notices that affect the account.", roles: ["customer", "admin"], resourceScoped: false },
  { id: "support_tickets", label: "Support tickets", description: "Read, create, and reply to the account's support tickets.", roles: ["customer"], resourceScoped: false },
  { id: "admin_customers", label: "Customer administration", description: "Manage customer records.", roles: ["admin"], resourceScoped: false },
  { id: "admin_users", label: "User administration", description: "Manage users and secure onboarding.", roles: ["admin"], resourceScoped: false },
  { id: "admin_clusters", label: "Cluster administration", description: "Manage, test, and synchronize Proxmox clusters.", roles: ["admin"], resourceScoped: false },
  { id: "admin_assignments", label: "Assignment administration", description: "Assign resources and maintain assignment policy.", roles: ["admin"], resourceScoped: false },
  { id: "admin_operations", label: "Operations center", description: "Read operations health and acknowledge incidents.", roles: ["admin"], resourceScoped: false },
  { id: "admin_maintenance", label: "Maintenance administration", description: "Create, publish, update, and resolve maintenance notices.", roles: ["admin"], resourceScoped: false },
  { id: "admin_support", label: "Support administration", description: "Manage all customer support tickets.", roles: ["admin"], resourceScoped: false },
  { id: "admin_email", label: "Email administration", description: "Manage email delivery settings and jobs.", roles: ["admin"], resourceScoped: false },
  { id: "admin_security", label: "Security administration", description: "Read the Security Center and update security policy.", roles: ["admin"], resourceScoped: false },
  { id: "admin_iso_policies", label: "ISO policy administration", description: "Manage customer ISO storage policies.", roles: ["admin"], resourceScoped: false },
  { id: "admin_audit", label: "Audit access", description: "Read the complete platform audit log.", roles: ["admin"], resourceScoped: false },
]);

export const API_ACTION_DEFINITIONS = Object.freeze([
  { id: "read_resource", label: "Read resource information", group: "server_overview", permission: "view_status", resourceScoped: true },
  { id: "read_configuration", label: "Read configuration", group: "server_overview", permission: "view_config", resourceScoped: true },
  { id: "read_usage", label: "Read usage statistics", group: "server_overview", permission: "view_usage", resourceScoped: true },
  { id: "start", label: "Start", group: "power_management", permission: "start", resourceScoped: true },
  { id: "stop", label: "Stop", group: "power_management", permission: "stop", resourceScoped: true },
  { id: "shutdown", label: "Shutdown", group: "power_management", permission: "shutdown", resourceScoped: true },
  { id: "reboot", label: "Reboot", group: "power_management", permission: "reboot", resourceScoped: true },
  { id: "reset", label: "Reset", group: "power_management", permission: "reset", resourceScoped: true },
  { id: "suspend", label: "Suspend", group: "power_management", permission: "suspend", resourceScoped: true },
  { id: "resume", label: "Resume", group: "power_management", permission: "resume", resourceScoped: true },
  { id: "snapshot_view", label: "View snapshots", group: "snapshot_management", permission: "view_status", resourceScoped: true },
  { id: "snapshot_create", label: "Create snapshots", group: "snapshot_management", permission: "snapshot_create", resourceScoped: true },
  { id: "snapshot_restore", label: "Restore snapshots", group: "snapshot_management", permission: "snapshot_restore", resourceScoped: true },
  { id: "snapshot_delete", label: "Delete snapshots", group: "snapshot_management", permission: "snapshot_delete", resourceScoped: true },
  { id: "console", label: "Console", group: "console_access", permission: "console", resourceScoped: true },
  { id: "iso_view", label: "View ISO images", group: "installation_media", permission: "iso_view", resourceScoped: true },
  { id: "iso_upload", label: "Upload ISO images", group: "installation_media", permission: "iso_upload", resourceScoped: true },
  { id: "iso_mount", label: "Mount or eject ISO images", group: "installation_media", permission: "iso_mount", resourceScoped: true },
  { id: "iso_boot", label: "Boot from ISO once", group: "installation_media", permission: "iso_boot", resourceScoped: true },
  { id: "iso_delete", label: "Delete ISO images", group: "installation_media", permission: "iso_delete", resourceScoped: true },
]);

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

export const OPERATIONS_THRESHOLDS = Object.freeze({
  nodeCpuWarning: 90,
  nodeCpuCritical: 97,
  nodeMemoryWarning: 90,
  nodeMemoryCritical: 97,
  storageWarning: 85,
  storageCritical: 95,
  stuckTaskMinutes: 15,
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
    kind: "browser",
    current: row.id_hash === currentIdHash,
    ipAddress: row.ip_address || "Unknown",
    userAgent: row.user_agent || "Unknown device",
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
    expiresAt: row.expires_at,
  };
}

function publicApiDeviceSession(row, currentIdHash = null) {
  if (!row) return null;
  const id = `mobile:${row.id}`;
  return {
    id,
    kind: "api",
    current: id === currentIdHash,
    deviceName: row.device_name,
    platform: row.platform,
    appVersion: row.app_version || null,
    ipAddress: row.ip_address || "Unknown",
    userAgent: row.device_name || row.user_agent || "Nimbus API device",
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
    expiresAt: row.refresh_expires_at,
    accessExpiresAt: row.access_expires_at,
  };
}

function publicSecurityPolicy(row = {}) {
  return {
    requireAdminMfa: Boolean(row.require_admin_mfa),
    requireCustomerMfa: Boolean(row.require_customer_mfa),
    newLoginEmail: Boolean(row.new_login_email),
    updatedBy: row.updated_by || null,
    updatedAt: row.updated_at || null,
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
    storageUsageAvailable: metadata.storageUsage?.available !== false,
    storageUsageStale: Boolean(metadata.storageUsage?.lastKnown),
    storageUsageSource: metadata.storageUsage?.source || null,
    storageUsageUpdatedAt: metadata.storageUsage?.collectedAt || null,
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

function publicMaintenanceEvent(row, targets = []) {
  return row && {
    id: row.id,
    kind: row.kind,
    title: row.title,
    message: row.message,
    severity: row.severity,
    status: row.status,
    startsAt: row.starts_at,
    endsAt: row.ends_at || null,
    notifyEmail: Boolean(row.notify_email),
    targets,
    recipientCount: Number(row.recipient_count || 0),
    publishedAt: row.published_at || null,
    resolvedAt: row.resolved_at || null,
    cancelledAt: row.cancelled_at || null,
    createdBy: row.created_by || null,
    createdByName: row.created_by_name || null,
    updatedBy: row.updated_by || null,
    updatedByName: row.updated_by_name || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function publicMaintenanceDelivery(row, targets = []) {
  const event = publicMaintenanceEvent(row, targets);
  return event && {
    ...event,
    deliveryId: row.delivery_id,
    readAt: row.read_at || null,
    emailJobId: row.email_job_id || null,
    resolutionEmailJobId: row.resolution_email_job_id || null,
  };
}

function publicSupportTicket(row, { includeInternal = true } = {}) {
  return row && {
    id: row.id,
    reference: row.reference,
    customerId: row.customer_id,
    customerName: row.customer_name || null,
    createdBy: row.created_by || null,
    createdByName: row.created_by_name || "Former user",
    assignedTo: row.assigned_to || null,
    assignedToName: row.assigned_to_name || null,
    resourceId: row.resource_id || null,
    resourceName: row.resource_name || null,
    resourceType: row.resource_type || null,
    vmid: row.vmid === null || row.vmid === undefined ? null : Number(row.vmid),
    subject: row.subject,
    category: row.category,
    priority: row.priority,
    status: row.status,
    messageCount: includeInternal
      ? Number(row.message_count || 0)
      : Number(row.public_message_count ?? row.message_count ?? 0),
    internalNoteCount: includeInternal ? Number(row.internal_note_count || 0) : 0,
    unread: Boolean(row.unread),
    lastMessageAt: row.last_message_at,
    resolvedAt: row.resolved_at || null,
    closedAt: row.closed_at || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function publicSupportMessage(row) {
  return row && {
    id: row.id,
    ticketId: row.ticket_id,
    authorUserId: row.author_user_id || null,
    authorName: row.author_name || (row.author_role === "system" ? "Nimbus Direct" : "Former user"),
    authorRole: row.author_role,
    internal: Boolean(row.internal),
    body: row.body,
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

function publicOperationsNode(row) {
  return row && {
    clusterId: row.cluster_id,
    clusterName: row.cluster_name || row.cluster_id,
    node: row.node,
    status: row.status || "unknown",
    cpuPercent: Number(row.cpu_percent || 0),
    cpuCores: Number(row.cpu_cores || 0),
    memoryUsedBytes: Number(row.memory_used_bytes || 0),
    memoryTotalBytes: Number(row.memory_total_bytes || 0),
    memoryPercent: Number(row.memory_percent || 0),
    rootUsedBytes: Number(row.root_used_bytes || 0),
    rootTotalBytes: Number(row.root_total_bytes || 0),
    rootPercent: Number(row.root_percent || 0),
    uptime: Number(row.uptime || 0),
    lastSeenAt: row.last_seen_at || null,
    updatedAt: row.updated_at,
  };
}

function publicOperationsStorage(row) {
  return row && {
    clusterId: row.cluster_id,
    clusterName: row.cluster_name || row.cluster_id,
    node: row.node,
    storageId: row.storage_id,
    status: row.status || "unknown",
    type: row.storage_type || "unknown",
    shared: Boolean(row.shared),
    content: String(row.content || "").split(",").filter(Boolean),
    usedBytes: Number(row.used_bytes || 0),
    totalBytes: Number(row.total_bytes || 0),
    availableBytes: Number(row.available_bytes || 0),
    usagePercent: Number(row.usage_percent || 0),
    lastSeenAt: row.last_seen_at || null,
    updatedAt: row.updated_at,
  };
}

function publicOperationsIncident(row) {
  return row && {
    id: row.id,
    clusterId: row.cluster_id || null,
    clusterName: row.cluster_name || row.cluster_id || "Platform",
    scope: row.scope,
    sourceType: row.source_type,
    sourceId: row.source_id,
    type: row.incident_type,
    severity: row.severity,
    status: row.status,
    title: row.title,
    message: row.message,
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
    acknowledgedAt: row.acknowledged_at || null,
    acknowledgedBy: row.acknowledged_by || null,
    acknowledgedByName: row.acknowledged_by_name || null,
    resolvedAt: row.resolved_at || null,
    updatedAt: row.updated_at,
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

function normalizeMaintenanceInput(input = {}, existing = null) {
  const kind = String(input.kind ?? existing?.kind ?? "maintenance").trim().toLowerCase();
  const severity = String(input.severity ?? existing?.severity ?? "info").trim().toLowerCase();
  const title = String(input.title ?? existing?.title ?? "").trim();
  const message = String(input.message ?? existing?.message ?? "").trim();
  const startsAt = Number(input.startsAt ?? existing?.starts_at);
  const rawEndsAt = input.endsAt === undefined ? existing?.ends_at : input.endsAt;
  const endsAt = rawEndsAt === null || rawEndsAt === "" || rawEndsAt === undefined ? null : Number(rawEndsAt);
  if (!["maintenance", "incident"].includes(kind)) throw problem("Choose planned maintenance or an incident", "invalid_maintenance_kind");
  if (!["info", "warning", "critical"].includes(severity)) throw problem("Choose a valid maintenance severity", "invalid_maintenance_severity");
  if (!title || title.length > 160) throw problem("Maintenance title must contain 1-160 characters", "invalid_maintenance_title");
  if (!message || message.length > 4000) throw problem("Maintenance message must contain 1-4000 characters", "invalid_maintenance_message");
  if (!Number.isSafeInteger(startsAt) || startsAt < Date.UTC(2020, 0, 1) || startsAt > Date.UTC(2100, 0, 1)) {
    throw problem("Choose a valid maintenance start time", "invalid_maintenance_schedule");
  }
  if (endsAt !== null && (!Number.isSafeInteger(endsAt) || endsAt <= startsAt)) {
    throw problem("Maintenance end time must be after its start time", "invalid_maintenance_schedule");
  }
  return {
    kind,
    severity,
    title,
    message,
    startsAt,
    endsAt,
    notifyEmail: input.notifyEmail === undefined ? Boolean(existing?.notify_email) : Boolean(input.notifyEmail),
  };
}

function normalizeSupportTicketInput(input = {}) {
  const subject = String(input.subject || "").trim();
  const category = String(input.category || "technical").trim().toLowerCase();
  const priority = String(input.priority || "normal").trim().toLowerCase();
  const resourceId = String(input.resourceId || "").trim() || null;
  const message = String(input.message || "").trim();
  if (subject.length < 3 || subject.length > 160) {
    throw problem("Ticket subject must contain 3-160 characters", "invalid_ticket_subject");
  }
  if (!["technical", "network", "account", "billing", "other"].includes(category)) {
    throw problem("Choose a valid ticket category", "invalid_ticket_category");
  }
  if (!["low", "normal", "high", "urgent"].includes(priority)) {
    throw problem("Choose a valid ticket priority", "invalid_ticket_priority");
  }
  if (resourceId && resourceId.length > 240) throw problem("The selected resource is invalid", "invalid_ticket_resource");
  if (!message || message.length > 8000) {
    throw problem("Ticket message must contain 1-8000 characters", "invalid_ticket_message");
  }
  return { subject, category, priority, resourceId, message };
}

function normalizeSupportMessage(value) {
  const message = String(value || "").trim();
  if (!message || message.length > 8000) {
    throw problem("Ticket message must contain 1-8000 characters", "invalid_ticket_message");
  }
  return message;
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
    (SELECT COUNT(*) FROM customer_resource_assignments a
      JOIN resources r ON r.id=a.resource_id
      WHERE a.customer_id=c.id AND a.status='active' AND r.stale=0
    ) AS resource_count,
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
    (SELECT COUNT(*) FROM resources r WHERE r.cluster_id=c.id AND r.stale=0) AS resource_count,
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

function operationsIncidentSelect(where = "") {
  return `SELECT i.*,c.name AS cluster_name,u.display_name AS acknowledged_by_name
    FROM operations_incidents i
    LEFT JOIN proxmox_clusters c ON c.id=i.cluster_id
    LEFT JOIN users u ON u.id=i.acknowledged_by
    ${where}`;
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

    CREATE TABLE IF NOT EXISTS operations_collection_status (
      cluster_id TEXT PRIMARY KEY REFERENCES proxmox_clusters(id) ON DELETE CASCADE,
      nodes_available INTEGER NOT NULL DEFAULT 0,
      storages_available INTEGER NOT NULL DEFAULT 0,
      nodes_error TEXT,
      storages_error TEXT,
      collected_at INTEGER,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS operations_node_metrics (
      cluster_id TEXT NOT NULL REFERENCES proxmox_clusters(id) ON DELETE CASCADE,
      node TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'unknown',
      cpu_percent REAL NOT NULL DEFAULT 0,
      cpu_cores REAL NOT NULL DEFAULT 0,
      memory_used_bytes INTEGER NOT NULL DEFAULT 0,
      memory_total_bytes INTEGER NOT NULL DEFAULT 0,
      memory_percent REAL NOT NULL DEFAULT 0,
      root_used_bytes INTEGER NOT NULL DEFAULT 0,
      root_total_bytes INTEGER NOT NULL DEFAULT 0,
      root_percent REAL NOT NULL DEFAULT 0,
      uptime INTEGER NOT NULL DEFAULT 0,
      last_seen_at INTEGER,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY(cluster_id,node)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS operations_storage_metrics (
      cluster_id TEXT NOT NULL REFERENCES proxmox_clusters(id) ON DELETE CASCADE,
      node TEXT NOT NULL,
      storage_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'unknown',
      storage_type TEXT NOT NULL DEFAULT 'unknown',
      shared INTEGER NOT NULL DEFAULT 0,
      content TEXT NOT NULL DEFAULT '',
      used_bytes INTEGER NOT NULL DEFAULT 0,
      total_bytes INTEGER NOT NULL DEFAULT 0,
      available_bytes INTEGER NOT NULL DEFAULT 0,
      usage_percent REAL NOT NULL DEFAULT 0,
      last_seen_at INTEGER,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY(cluster_id,node,storage_id)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS operations_incidents (
      id TEXT PRIMARY KEY,
      dedup_key TEXT NOT NULL UNIQUE,
      cluster_id TEXT REFERENCES proxmox_clusters(id) ON DELETE CASCADE,
      scope TEXT NOT NULL,
      source_type TEXT NOT NULL CHECK(source_type IN ('cluster','node','storage','task','resource')),
      source_id TEXT NOT NULL,
      incident_type TEXT NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('warning','critical')),
      status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','acknowledged','resolved')),
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      first_seen_at INTEGER NOT NULL,
      last_seen_at INTEGER NOT NULL,
      acknowledged_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      acknowledged_at INTEGER,
      resolved_at INTEGER,
      updated_at INTEGER NOT NULL
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

    CREATE TABLE IF NOT EXISTS api_device_sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      access_token_hash TEXT NOT NULL UNIQUE,
      device_name TEXT NOT NULL,
      platform TEXT NOT NULL CHECK(platform IN ('ios','android','desktop','other')),
      app_version TEXT,
      ip_address TEXT,
      user_agent TEXT,
      access_expires_at INTEGER NOT NULL,
      refresh_expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      last_seen_at INTEGER NOT NULL,
      rotated_at INTEGER,
      revoked_at INTEGER,
      revoked_reason TEXT
    ) STRICT;

    CREATE TABLE IF NOT EXISTS api_refresh_tokens (
      token_hash TEXT PRIMARY KEY,
      session_id TEXT NOT NULL REFERENCES api_device_sessions(id) ON DELETE CASCADE,
      status TEXT NOT NULL CHECK(status IN ('active','rotated','revoked')),
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      used_at INTEGER
    ) STRICT;

    CREATE TABLE IF NOT EXISTS mobile_push_devices (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      token_encrypted TEXT NOT NULL,
      platform TEXT NOT NULL CHECK(platform IN ('ios')),
      environment TEXT NOT NULL CHECK(environment IN ('sandbox','production')),
      app_version TEXT,
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
      failure_reason TEXT,
      last_registered_at INTEGER NOT NULL,
      last_sent_at INTEGER,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE INDEX IF NOT EXISTS mobile_push_devices_user_status
      ON mobile_push_devices(user_id, status, updated_at DESC);

    CREATE TABLE IF NOT EXISTS user_api_policies (
      user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      enabled INTEGER NOT NULL DEFAULT 0,
      max_active_keys INTEGER NOT NULL DEFAULT 3 CHECK(max_active_keys BETWEEN 1 AND 50),
      max_lifetime_days INTEGER NOT NULL DEFAULT 365 CHECK(max_lifetime_days BETWEEN 1 AND 3650),
      allow_no_expiry INTEGER NOT NULL DEFAULT 0,
      all_visible_resources INTEGER NOT NULL DEFAULT 0,
      updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS user_api_policy_groups (
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      group_id TEXT NOT NULL,
      PRIMARY KEY(user_id,group_id)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS user_api_policy_resources (
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
      PRIMARY KEY(user_id,resource_id)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS user_api_keys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      token_hint TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
      expires_at INTEGER,
      last_used_at INTEGER,
      last_ip TEXT,
      revoked_at INTEGER,
      revoked_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      revoked_reason TEXT,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS user_api_key_groups (
      key_id TEXT NOT NULL REFERENCES user_api_keys(id) ON DELETE CASCADE,
      group_id TEXT NOT NULL,
      PRIMARY KEY(key_id,group_id)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS user_api_key_resources (
      key_id TEXT NOT NULL REFERENCES user_api_keys(id) ON DELETE CASCADE,
      resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
      PRIMARY KEY(key_id,resource_id)
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

    CREATE TABLE IF NOT EXISTS security_policy (
      id TEXT PRIMARY KEY CHECK(id='default'),
      require_admin_mfa INTEGER NOT NULL DEFAULT 0,
      require_customer_mfa INTEGER NOT NULL DEFAULT 0,
      new_login_email INTEGER NOT NULL DEFAULT 0,
      updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
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

    CREATE TABLE IF NOT EXISTS maintenance_events (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL CHECK(kind IN ('maintenance','incident')),
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('info','warning','critical')),
      status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','scheduled','active','resolved','cancelled')),
      starts_at INTEGER NOT NULL,
      ends_at INTEGER,
      notify_email INTEGER NOT NULL DEFAULT 1,
      created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      published_at INTEGER,
      resolved_at INTEGER,
      cancelled_at INTEGER,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      CHECK(ends_at IS NULL OR ends_at > starts_at)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS maintenance_targets (
      event_id TEXT NOT NULL REFERENCES maintenance_events(id) ON DELETE CASCADE,
      target_type TEXT NOT NULL CHECK(target_type IN ('all','cluster','node','resource','customer')),
      target_id TEXT NOT NULL,
      PRIMARY KEY(event_id,target_type,target_id)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS maintenance_deliveries (
      id TEXT PRIMARY KEY,
      event_id TEXT NOT NULL REFERENCES maintenance_events(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      email_job_id TEXT REFERENCES email_jobs(id) ON DELETE SET NULL,
      resolution_email_job_id TEXT REFERENCES email_jobs(id) ON DELETE SET NULL,
      read_at INTEGER,
      created_at INTEGER NOT NULL,
      UNIQUE(event_id,user_id)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS support_tickets (
      id TEXT PRIMARY KEY,
      reference TEXT NOT NULL UNIQUE,
      customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
      created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      assigned_to TEXT REFERENCES users(id) ON DELETE SET NULL,
      resource_id TEXT REFERENCES resources(id) ON DELETE SET NULL,
      subject TEXT NOT NULL,
      category TEXT NOT NULL CHECK(category IN ('technical','network','account','billing','other')),
      priority TEXT NOT NULL CHECK(priority IN ('low','normal','high','urgent')),
      status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','waiting_support','waiting_customer','resolved','closed')),
      last_message_at INTEGER NOT NULL,
      resolved_at INTEGER,
      closed_at INTEGER,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS support_ticket_messages (
      id TEXT PRIMARY KEY,
      ticket_id TEXT NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
      author_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      author_role TEXT NOT NULL CHECK(author_role IN ('admin','customer','system')),
      body TEXT NOT NULL,
      internal INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS support_ticket_reads (
      ticket_id TEXT NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      last_read_at INTEGER NOT NULL,
      PRIMARY KEY(ticket_id,user_id)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS console_sessions (
      id_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
      ticket_encrypted TEXT NOT NULL,
      port INTEGER NOT NULL,
      console_type TEXT NOT NULL DEFAULT 'graphical' CHECK(console_type IN ('graphical','terminal')),
      console_user TEXT,
      expires_at INTEGER NOT NULL,
      used_at INTEGER,
      created_at INTEGER NOT NULL
    ) STRICT;

    CREATE INDEX IF NOT EXISTS users_customer_idx ON users(customer_id);
    CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions(expires_at);
    CREATE INDEX IF NOT EXISTS sessions_user_created_idx ON sessions(user_id,created_at DESC);
    CREATE INDEX IF NOT EXISTS api_device_sessions_user_idx ON api_device_sessions(user_id,last_seen_at DESC);
    CREATE INDEX IF NOT EXISTS api_device_sessions_access_idx ON api_device_sessions(access_token_hash,access_expires_at);
    CREATE INDEX IF NOT EXISTS api_refresh_tokens_session_idx ON api_refresh_tokens(session_id,status,created_at DESC);
    CREATE INDEX IF NOT EXISTS api_refresh_tokens_expiry_idx ON api_refresh_tokens(expires_at,status);
    CREATE INDEX IF NOT EXISTS user_api_keys_user_status_idx ON user_api_keys(user_id,status,created_at DESC);
    CREATE INDEX IF NOT EXISTS user_api_keys_token_idx ON user_api_keys(token_hash,status);
    CREATE INDEX IF NOT EXISTS mfa_challenges_expires_idx ON mfa_login_challenges(expires_at);
    CREATE INDEX IF NOT EXISTS account_tokens_user_purpose_idx ON account_tokens(user_id,purpose,created_at DESC);
    CREATE INDEX IF NOT EXISTS account_tokens_expires_idx ON account_tokens(expires_at);
    CREATE INDEX IF NOT EXISTS resources_cluster_idx ON resources(cluster_id,node,type,vmid);
    CREATE INDEX IF NOT EXISTS operations_nodes_status_idx ON operations_node_metrics(cluster_id,status,updated_at);
    CREATE INDEX IF NOT EXISTS operations_storage_usage_idx ON operations_storage_metrics(cluster_id,usage_percent DESC);
    CREATE INDEX IF NOT EXISTS operations_incidents_status_idx ON operations_incidents(status,severity,last_seen_at DESC);
    CREATE INDEX IF NOT EXISTS operations_incidents_scope_idx ON operations_incidents(scope,status);
    CREATE INDEX IF NOT EXISTS assignments_customer_idx ON customer_resource_assignments(customer_id,status);
    CREATE INDEX IF NOT EXISTS audit_customer_created_idx ON audit_logs(customer_id,created_at DESC);
    CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_logs(created_at DESC);
    CREATE INDEX IF NOT EXISTS audit_action_created_idx ON audit_logs(action,created_at DESC);
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
    CREATE INDEX IF NOT EXISTS maintenance_events_status_schedule_idx ON maintenance_events(status,starts_at,ends_at);
    CREATE INDEX IF NOT EXISTS maintenance_targets_lookup_idx ON maintenance_targets(target_type,target_id,event_id);
    CREATE INDEX IF NOT EXISTS maintenance_deliveries_user_event_idx ON maintenance_deliveries(user_id,event_id);
    CREATE INDEX IF NOT EXISTS support_tickets_customer_status_idx ON support_tickets(customer_id,status,last_message_at DESC);
    CREATE INDEX IF NOT EXISTS support_tickets_assignee_status_idx ON support_tickets(assigned_to,status,last_message_at DESC);
    CREATE INDEX IF NOT EXISTS support_ticket_messages_ticket_created_idx ON support_ticket_messages(ticket_id,created_at);
    CREATE INDEX IF NOT EXISTS support_ticket_reads_user_idx ON support_ticket_reads(user_id,last_read_at);
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
  const apiPolicyColumns = new Set(database.prepare("PRAGMA table_info(user_api_policies)").all().map((column) => column.name));
  if (!apiPolicyColumns.has("all_visible_resources")) database.exec("ALTER TABLE user_api_policies ADD COLUMN all_visible_resources INTEGER NOT NULL DEFAULT 0");
  const emailSettingsColumns = new Set(database.prepare("PRAGMA table_info(email_settings)").all().map((column) => column.name));
  if (!emailSettingsColumns.has("app_url")) database.exec("ALTER TABLE email_settings ADD COLUMN app_url TEXT NOT NULL DEFAULT ''");
  const consoleSessionColumns = new Set(database.prepare("PRAGMA table_info(console_sessions)").all().map((column) => column.name));
  if (!consoleSessionColumns.has("console_type")) database.exec("ALTER TABLE console_sessions ADD COLUMN console_type TEXT NOT NULL DEFAULT 'graphical' CHECK(console_type IN ('graphical','terminal'))");
  if (!consoleSessionColumns.has("console_user")) database.exec("ALTER TABLE console_sessions ADD COLUMN console_user TEXT");
  const securityPolicyNow = Date.now();
  database.prepare(`INSERT OR IGNORE INTO security_policy
    (id,require_admin_mfa,require_customer_mfa,new_login_email,created_at,updated_at)
    VALUES ('default',0,0,0,?,?)`).run(securityPolicyNow, securityPolicyNow);

  const getCustomerRow = database.prepare(customerSelect("WHERE c.id=?"));
  const getUserRow = database.prepare(userSelect("WHERE u.id=?"));
  const getUserByEmailRow = database.prepare(userSelect("WHERE u.email=?"));
  const getClusterRow = database.prepare(clusterSelect("WHERE c.id=?"));
  const getResourceRow = database.prepare(resourceSelect("WHERE r.id=?"));

  function revokeApiDeviceSessionRow(id, reason = "revoked", timestamp = Date.now()) {
    const changed = database.prepare(`UPDATE api_device_sessions
      SET revoked_at=COALESCE(revoked_at,?),revoked_reason=COALESCE(revoked_reason,?)
      WHERE id=? AND revoked_at IS NULL`).run(timestamp, reason, id).changes;
    if (changed) database.prepare("UPDATE api_refresh_tokens SET status='revoked' WHERE session_id=? AND status='active'").run(id);
    return changed > 0;
  }

  function expireApiDeviceSessions(timestamp = Date.now()) {
    const expired = database.prepare(`SELECT id FROM api_device_sessions
      WHERE revoked_at IS NULL AND refresh_expires_at<=?`).all(timestamp);
    for (const row of expired) revokeApiDeviceSessionRow(row.id, "expired", timestamp);
    return expired.length;
  }

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

  function normalizeMaintenanceTargets(targets = []) {
    if (!Array.isArray(targets) || !targets.length || targets.length > 200) {
      throw problem("Choose at least one maintenance audience", "invalid_maintenance_targets");
    }
    const normalized = [];
    const seen = new Set();
    for (const target of targets) {
      const type = String(target?.type || "").trim().toLowerCase();
      const id = String(target?.id || "").trim();
      if (!["all", "cluster", "node", "resource", "customer"].includes(type) || !id || id.length > 240) {
        throw problem("Maintenance audience is invalid", "invalid_maintenance_targets");
      }
      const key = `${type}:${id}`;
      if (!seen.has(key)) normalized.push({ type, id });
      seen.add(key);
    }
    const types = new Set(normalized.map((target) => target.type));
    if (types.size !== 1 || (types.has("all") && (normalized.length !== 1 || normalized[0].id !== "*"))) {
      throw problem("Use one maintenance audience type per notice", "invalid_maintenance_targets");
    }
    for (const target of normalized) {
      const exists = target.type === "all"
        ? true
        : target.type === "cluster"
          ? Boolean(database.prepare("SELECT 1 FROM proxmox_clusters WHERE id=?").get(target.id))
          : target.type === "node"
            ? Boolean(database.prepare("SELECT 1 FROM proxmox_nodes WHERE cluster_id || ':' || name=?").get(target.id))
            : target.type === "resource"
              ? Boolean(database.prepare("SELECT 1 FROM resources WHERE id=?").get(target.id))
              : Boolean(database.prepare("SELECT 1 FROM customers WHERE id=?").get(target.id));
      if (!exists) throw problem("A selected maintenance target no longer exists", "maintenance_target_not_found", 404);
    }
    return normalized;
  }

  function maintenanceTargets(eventId) {
    const rows = database.prepare("SELECT target_type,target_id FROM maintenance_targets WHERE event_id=? ORDER BY target_type,target_id").all(eventId);
    return rows.map((row) => {
      let label = row.target_id;
      if (row.target_type === "all") label = "All customers";
      if (row.target_type === "cluster") {
        label = database.prepare("SELECT name FROM proxmox_clusters WHERE id=?").get(row.target_id)?.name || row.target_id;
      }
      if (row.target_type === "customer") {
        label = database.prepare("SELECT name FROM customers WHERE id=?").get(row.target_id)?.name || row.target_id;
      }
      if (row.target_type === "resource") {
        const resource = database.prepare("SELECT name,type,vmid FROM resources WHERE id=?").get(row.target_id);
        label = resource ? `${resource.name} · ${String(resource.type).toUpperCase()} ${resource.vmid}` : row.target_id;
      }
      if (row.target_type === "node") {
        const node = database.prepare(`SELECT n.name,c.name AS cluster_name FROM proxmox_nodes n
          JOIN proxmox_clusters c ON c.id=n.cluster_id WHERE n.cluster_id || ':' || n.name=?`).get(row.target_id);
        label = node ? `${node.name} · ${node.cluster_name}` : row.target_id;
      }
      return { type: row.target_type, id: row.target_id, label };
    });
  }

  function maintenanceEventRow(id) {
    return database.prepare(`SELECT e.*,
      creator.display_name AS created_by_name,updater.display_name AS updated_by_name,
      (SELECT COUNT(*) FROM maintenance_deliveries d WHERE d.event_id=e.id) AS recipient_count
      FROM maintenance_events e
      LEFT JOIN users creator ON creator.id=e.created_by
      LEFT JOIN users updater ON updater.id=e.updated_by
      WHERE e.id=?`).get(id);
  }

  function maintenanceRecipientsForTargets(targets) {
    let customerIds = null;
    const type = targets[0]?.type;
    const ids = targets.map((target) => target.id);
    if (type !== "all") {
      const selectedCustomers = new Set();
      const placeholders = ids.map(() => "?").join(",");
      if (type === "customer") {
        for (const id of ids) selectedCustomers.add(id);
      } else if (type === "cluster") {
        for (const row of database.prepare(`SELECT DISTINCT a.customer_id FROM customer_resource_assignments a
          JOIN resources r ON r.id=a.resource_id
          WHERE a.status='active' AND r.cluster_id IN (${placeholders})`).all(...ids)) selectedCustomers.add(row.customer_id);
      } else if (type === "resource") {
        for (const row of database.prepare(`SELECT DISTINCT customer_id FROM customer_resource_assignments
          WHERE status='active' AND resource_id IN (${placeholders})`).all(...ids)) selectedCustomers.add(row.customer_id);
      } else if (type === "node") {
        for (const row of database.prepare(`SELECT DISTINCT a.customer_id FROM customer_resource_assignments a
          JOIN resources r ON r.id=a.resource_id
          WHERE a.status='active' AND (r.cluster_id || ':' || r.node) IN (${placeholders})`).all(...ids)) selectedCustomers.add(row.customer_id);
      }
      customerIds = [...selectedCustomers];
      if (!customerIds.length) return [];
    }
    const customerFilter = customerIds
      ? `AND u.customer_id IN (${customerIds.map(() => "?").join(",")})`
      : "";
    return database.prepare(`SELECT u.id,u.customer_id,u.email,u.display_name,
      COALESCE(p.email_enabled,0) AS email_enabled,
      COALESCE(p.infrastructure_alerts,1) AS infrastructure_alerts,
      COALESCE(p.resolution_alerts,1) AS resolution_alerts
      FROM users u JOIN customers c ON c.id=u.customer_id
      LEFT JOIN notification_preferences p ON p.user_id=u.id
      WHERE u.role='customer' AND u.status='active' AND c.status='active' ${customerFilter}
      ORDER BY u.id`).all(...(customerIds || [])).map((row) => ({
      id: row.id,
      customerId: row.customer_id,
      email: row.email,
      displayName: row.display_name,
      emailEnabled: Boolean(row.email_enabled),
      infrastructureAlerts: Boolean(row.infrastructure_alerts),
      resolutionAlerts: Boolean(row.resolution_alerts),
    }));
  }

  function maintenanceDeliveryRecipients(eventId) {
    return database.prepare(`SELECT d.id AS delivery_id,u.id,u.customer_id,u.email,u.display_name,
      COALESCE(p.email_enabled,0) AS email_enabled,
      COALESCE(p.infrastructure_alerts,1) AS infrastructure_alerts,
      COALESCE(p.resolution_alerts,1) AS resolution_alerts
      FROM maintenance_deliveries d JOIN users u ON u.id=d.user_id
      LEFT JOIN notification_preferences p ON p.user_id=u.id
      WHERE d.event_id=? AND u.role='customer' AND u.status='active'
      ORDER BY u.id`).all(eventId).map((row) => ({
      deliveryId: row.delivery_id,
      id: row.id,
      customerId: row.customer_id,
      email: row.email,
      displayName: row.display_name,
      emailEnabled: Boolean(row.email_enabled),
      infrastructureAlerts: Boolean(row.infrastructure_alerts),
      resolutionAlerts: Boolean(row.resolution_alerts),
    }));
  }

  function supportTicketRow(id, userId = null) {
    return database.prepare(`SELECT t.*,c.name AS customer_name,
      creator.display_name AS created_by_name,assignee.display_name AS assigned_to_name,
      r.name AS resource_name,r.type AS resource_type,r.vmid,
      (SELECT COUNT(*) FROM support_ticket_messages m WHERE m.ticket_id=t.id) AS message_count,
      (SELECT COUNT(*) FROM support_ticket_messages m WHERE m.ticket_id=t.id AND m.internal=0) AS public_message_count,
      (SELECT COUNT(*) FROM support_ticket_messages m WHERE m.ticket_id=t.id AND m.internal=1) AS internal_note_count,
      CASE WHEN t.last_message_at>COALESCE(rd.last_read_at,0) THEN 1 ELSE 0 END AS unread
      FROM support_tickets t
      JOIN customers c ON c.id=t.customer_id
      LEFT JOIN users creator ON creator.id=t.created_by
      LEFT JOIN users assignee ON assignee.id=t.assigned_to
      LEFT JOIN resources r ON r.id=t.resource_id
      LEFT JOIN support_ticket_reads rd ON rd.ticket_id=t.id AND rd.user_id=?
      WHERE t.id=?`).get(userId, id);
  }

  function requireSupportTicket(id, scope, userId = scope?.id || null) {
    const row = supportTicketRow(id, userId);
    if (!row || (scope?.role !== "admin" && row.customer_id !== scope?.customerId)) {
      throw problem("Support ticket does not exist", "support_ticket_not_found", 404);
    }
    return row;
  }

  function supportTicketReference(id, now) {
    const date = new Date(now).toISOString().slice(0, 10).replaceAll("-", "");
    const suffix = String(id).replace(/[^A-Za-z0-9]/g, "").slice(0, 6).toUpperCase();
    return `ND-${date}-${suffix}`;
  }

  function supportTicketMessages(ticketId, { includeInternal = false } = {}) {
    return database.prepare(`SELECT m.*,u.display_name AS author_name
      FROM support_ticket_messages m
      LEFT JOIN users u ON u.id=m.author_user_id
      WHERE m.ticket_id=? ${includeInternal ? "" : "AND m.internal=0"}
      ORDER BY m.created_at,m.id`).all(ticketId).map(publicSupportMessage);
  }

  function apiGroupsForRole(role) {
    return API_PERMISSION_GROUPS.filter((group) => group.roles.includes(role));
  }

  function apiVisibleResources(user) {
    if (!user) return [];
    return user.role === "admin"
      ? database.prepare(resourceSelect("WHERE r.stale=0")).all().map(publicResource)
      : database.prepare(resourceSelect("WHERE a.customer_id=? AND a.status='active' AND r.stale=0"))
          .all(user.customerId || user.customer_id).map(publicResource);
  }

  function apiPolicyFor(userId) {
    const user = publicUser(getUserRow.get(userId));
    if (!user) throw problem("User does not exist", "user_not_found", 404);
    const row = database.prepare("SELECT * FROM user_api_policies WHERE user_id=?").get(userId);
    const groupIds = row
      ? database.prepare("SELECT group_id FROM user_api_policy_groups WHERE user_id=? ORDER BY group_id").all(userId).map((entry) => entry.group_id)
      : [];
    const resourceIds = row
      ? database.prepare("SELECT resource_id FROM user_api_policy_resources WHERE user_id=? ORDER BY resource_id").all(userId).map((entry) => entry.resource_id)
      : [];
    const roleGroups = new Set(apiGroupsForRole(user.role).map((group) => group.id));
    const visibleIds = new Set(apiVisibleResources(user).map((resource) => resource.id));
    return {
      userId,
      enabled: Boolean(row?.enabled),
      maxActiveKeys: Number(row?.max_active_keys || 3),
      maxLifetimeDays: Number(row?.max_lifetime_days || 365),
      allowNoExpiry: Boolean(row?.allow_no_expiry),
      groups: groupIds.filter((id) => roleGroups.has(id)),
      resourceIds: resourceIds.filter((id) => visibleIds.has(id)),
      allVisibleResources: Boolean(row?.all_visible_resources),
      updatedBy: row?.updated_by || null,
      createdAt: row?.created_at || null,
      updatedAt: row?.updated_at || null,
    };
  }

  function allowedPolicyResourceIds(user, policy, visibleResources = apiVisibleResources(user)) {
    const visibleIds = new Set(visibleResources.map((resource) => resource.id));
    return policy.allVisibleResources
      ? [...visibleIds]
      : policy.resourceIds.filter((id) => visibleIds.has(id));
  }

  function apiKeyRow(keyId) {
    return database.prepare("SELECT * FROM user_api_keys WHERE id=?").get(keyId);
  }

  function apiKeySelections(keyId) {
    return {
      groups: database.prepare("SELECT group_id FROM user_api_key_groups WHERE key_id=? ORDER BY group_id").all(keyId).map((row) => row.group_id),
      resourceIds: database.prepare("SELECT resource_id FROM user_api_key_resources WHERE key_id=? ORDER BY resource_id").all(keyId).map((row) => row.resource_id),
    };
  }

  function apiKeySummary(user, input, policy = apiPolicyFor(user.id), visibleResources = apiVisibleResources(user)) {
    const selectedGroups = new Set(input.groups || []);
    const selectedResourceIds = new Set(input.resourceIds || []);
    const policyGroups = new Set(policy.groups);
    const policyResources = new Set(allowedPolicyResourceIds(user, policy, visibleResources));
    const effectiveGroups = [...selectedGroups].filter((id) => policyGroups.has(id));
    const effectiveGroupSet = new Set(effectiveGroups);
    const resources = visibleResources.filter((resource) => selectedResourceIds.has(resource.id));
    const effectiveResources = resources.filter((resource) => policyResources.has(resource.id));
    const effectiveResourceIds = new Set(effectiveResources.map((resource) => resource.id));
    const actions = API_ACTION_DEFINITIONS.map((action) => {
      const selected = resources;
      const allowedCount = selected.filter((resource) =>
        effectiveGroupSet.has(action.group)
        && effectiveResourceIds.has(resource.id)
        && (user.role === "admin" || resource.permissions.includes(action.permission))).length;
      const state = allowedCount === 0 ? "denied" : allowedCount === selected.length ? "allowed" : "partial";
      return {
        id: action.id,
        label: action.label,
        group: action.group,
        state,
        allowedCount,
        resourceCount: selected.length,
      };
    });
    return {
      name: String(input.name || "").trim(),
      permissionGroups: apiGroupsForRole(user.role).map((group) => ({
        ...group,
        selected: selectedGroups.has(group.id),
        effective: effectiveGroupSet.has(group.id),
      })),
      resources: resources.map((resource) => ({
        id: resource.id,
        name: resource.displayName || resource.name,
        type: resource.type,
        vmid: resource.vmid,
        clusterId: resource.clusterId,
        node: resource.node,
        effective: effectiveResourceIds.has(resource.id),
      })),
      expiresAt: input.expiresAt || null,
      actions,
    };
  }

  function normalizeApiKeyInput(user, input, { requirePolicy = true } = {}) {
    const policy = apiPolicyFor(user.id);
    if (requirePolicy && !policy.enabled) throw problem("API access is not enabled for this account", "api_access_disabled", 403);
    const name = String(input?.name || "").trim();
    if (!name || name.length > 100) throw problem("API key name must contain 1-100 characters", "invalid_api_key_name");
    const roleGroups = new Set(apiGroupsForRole(user.role).map((group) => group.id));
    const policyGroups = new Set(policy.groups);
    const groups = [...new Set((Array.isArray(input?.groups) ? input.groups : []).map(String))];
    if (!groups.length || groups.some((id) => !roleGroups.has(id) || !policyGroups.has(id))) {
      throw problem("Choose only API permissions enabled by the administrator", "invalid_api_key_groups");
    }
    const visibleResources = apiVisibleResources(user);
    const visibleIds = new Set(visibleResources.map((resource) => resource.id));
    const policyResourceIds = new Set(allowedPolicyResourceIds(user, policy, visibleResources));
    const resourceIds = [...new Set((Array.isArray(input?.resourceIds) ? input.resourceIds : []).map(String))];
    if (resourceIds.some((id) => !visibleIds.has(id) || !policyResourceIds.has(id))) {
      throw problem("Choose only resources enabled for this account", "invalid_api_key_resources");
    }
    const resourceGroups = new Set(apiGroupsForRole(user.role).filter((group) => group.resourceScoped).map((group) => group.id));
    if (groups.some((id) => resourceGroups.has(id)) && !resourceIds.length) {
      throw problem("Choose at least one resource for resource permissions", "api_key_resources_required");
    }
    let expiresAt = null;
    if (input?.expiresAt !== undefined && input.expiresAt !== null && input.expiresAt !== "") {
      expiresAt = typeof input.expiresAt === "number" ? input.expiresAt : Date.parse(String(input.expiresAt));
      if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now() + 60_000) {
        throw problem("API key expiry must be in the future", "invalid_api_key_expiry");
      }
      if (expiresAt > Date.now() + policy.maxLifetimeDays * 86_400_000 + 60_000) {
        throw problem("API key expiry exceeds the administrator limit", "api_key_expiry_too_long");
      }
    } else if (!policy.allowNoExpiry) {
      throw problem("An expiry date is required for this API key", "api_key_expiry_required");
    }
    return { name, groups, resourceIds, expiresAt, policy, visibleResources };
  }

  function publicApiKey(row, user = null) {
    if (!row) return null;
    const owner = user || publicUser(getUserRow.get(row.user_id));
    const selections = apiKeySelections(row.id);
    const expired = Boolean(row.expires_at && Number(row.expires_at) <= Date.now());
    const policy = apiPolicyFor(row.user_id);
    return {
      id: row.id,
      userId: row.user_id,
      name: row.name,
      tokenHint: row.token_hint,
      status: row.status === "active" && expired ? "expired" : row.status,
      active: row.status === "active" && !expired && policy.enabled,
      groups: selections.groups,
      resourceIds: selections.resourceIds,
      expiresAt: row.expires_at || null,
      lastUsedAt: row.last_used_at || null,
      lastIp: row.last_ip || null,
      revokedAt: row.revoked_at || null,
      revokedReason: row.revoked_reason || null,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      summary: apiKeySummary(owner, { name: row.name, ...selections, expiresAt: row.expires_at }, policy),
    };
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
        const now = Date.now();
        database.prepare("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE customer_id=?)").run(id);
        database.prepare(`UPDATE api_device_sessions SET revoked_at=?,revoked_reason='customer_deleted'
          WHERE user_id IN (SELECT id FROM users WHERE customer_id=?) AND revoked_at IS NULL`).run(now, id);
        database.prepare(`UPDATE user_api_keys SET status='revoked',revoked_at=COALESCE(revoked_at,?),
          revoked_reason=COALESCE(revoked_reason,'customer_disabled'),updated_at=?
          WHERE user_id IN (SELECT id FROM users WHERE customer_id=?) AND status='active'`).run(now, now, id);
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
    getUser: (id) => publicUser(getUserRow.get(id)),
    listUsers: () => database.prepare(userSelect("ORDER BY u.email")).all().map(publicUser),
    listCustomerUsers: (customerId) => database.prepare(userSelect("WHERE u.customer_id=? ORDER BY u.display_name")).all(customerId).map(publicUser),
    listActiveCustomerUsers: (customerId) => database.prepare(userSelect("WHERE u.customer_id=? AND u.role='customer' AND u.status='active' ORDER BY u.display_name"))
      .all(customerId).map(publicUser),
    getUserApiPolicy: (userId) => apiPolicyFor(userId),
    listUserApiPolicies() {
      return database.prepare(userSelect("ORDER BY u.email")).all().map((row) => {
        const user = publicUser(row);
        const policy = apiPolicyFor(user.id);
        const activeKeys = database.prepare(`SELECT COUNT(*) AS count FROM user_api_keys
          WHERE user_id=? AND status='active' AND (expires_at IS NULL OR expires_at>?)`).get(user.id, Date.now()).count;
        return { userId: user.id, email: user.email, displayName: user.displayName, role: user.role, activeKeys: Number(activeKeys), ...policy };
      });
    },
    updateUserApiPolicy(userId, input, updatedBy = null) {
      const user = publicUser(getUserRow.get(userId));
      if (!user) throw problem("User does not exist", "user_not_found", 404);
      const enabled = input.enabled === true;
      const maxActiveKeys = Math.max(1, Math.min(50, Number(input.maxActiveKeys) || 3));
      const maxLifetimeDays = Math.max(1, Math.min(3650, Number(input.maxLifetimeDays) || 365));
      const allowNoExpiry = input.allowNoExpiry === true;
      const roleGroups = new Set(apiGroupsForRole(user.role).map((group) => group.id));
      const groups = [...new Set((Array.isArray(input.groups) ? input.groups : []).map(String))];
      if (groups.some((id) => !roleGroups.has(id)) || (enabled && !groups.length)) {
        throw problem("Choose valid API permission groups for this user", "invalid_api_policy_groups");
      }
      const visibleIds = new Set(apiVisibleResources(user).map((resource) => resource.id));
      const resourceIds = [...new Set((Array.isArray(input.resourceIds) ? input.resourceIds : []).map(String))];
      const allVisibleResources = input.allVisibleResources === true
        || (input.allVisibleResources === undefined && resourceIds.length === 0);
      if (resourceIds.some((id) => !visibleIds.has(id))) {
        throw problem("Choose only resources visible to this user", "invalid_api_policy_resources");
      }
      const hasResourceGroups = groups.some((id) => apiGroupsForRole(user.role).find((group) => group.id === id)?.resourceScoped);
      if (enabled && hasResourceGroups && !allVisibleResources && !resourceIds.length) {
        throw problem("Choose at least one maximum resource or allow all visible resources", "invalid_api_policy_resources");
      }
      const now = Date.now();
      database.exec("BEGIN IMMEDIATE");
      try {
        database.prepare(`INSERT INTO user_api_policies
          (user_id,enabled,max_active_keys,max_lifetime_days,allow_no_expiry,all_visible_resources,updated_by,created_at,updated_at)
          VALUES (?,?,?,?,?,?,?,?,?)
          ON CONFLICT(user_id) DO UPDATE SET enabled=excluded.enabled,max_active_keys=excluded.max_active_keys,
            max_lifetime_days=excluded.max_lifetime_days,allow_no_expiry=excluded.allow_no_expiry,
            all_visible_resources=excluded.all_visible_resources,updated_by=excluded.updated_by,updated_at=excluded.updated_at`)
          .run(userId, Number(enabled), maxActiveKeys, maxLifetimeDays, Number(allowNoExpiry), Number(allVisibleResources), updatedBy, now, now);
        database.prepare("DELETE FROM user_api_policy_groups WHERE user_id=?").run(userId);
        const insertGroup = database.prepare("INSERT INTO user_api_policy_groups (user_id,group_id) VALUES (?,?)");
        for (const id of groups) insertGroup.run(userId, id);
        database.prepare("DELETE FROM user_api_policy_resources WHERE user_id=?").run(userId);
        const insertResource = database.prepare("INSERT INTO user_api_policy_resources (user_id,resource_id) VALUES (?,?)");
        for (const id of resourceIds) insertResource.run(userId, id);
        if (!enabled) {
          database.prepare(`UPDATE user_api_keys SET status='revoked',revoked_at=COALESCE(revoked_at,?),
            revoked_by=COALESCE(revoked_by,?),revoked_reason=COALESCE(revoked_reason,'policy_disabled'),updated_at=?
            WHERE user_id=? AND status='active'`).run(now, updatedBy, now, userId);
        } else {
          const excess = database.prepare(`SELECT id FROM user_api_keys
            WHERE user_id=? AND status='active' AND (expires_at IS NULL OR expires_at>?)
            ORDER BY created_at DESC,rowid DESC LIMIT -1 OFFSET ?`).all(userId, now, maxActiveKeys);
          for (const key of excess) {
            database.prepare(`UPDATE user_api_keys SET status='revoked',revoked_at=?,revoked_by=?,
              revoked_reason='policy_key_limit',updated_at=? WHERE id=?`).run(now, updatedBy, now, key.id);
          }
        }
        database.exec("COMMIT");
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
      return apiPolicyFor(userId);
    },
    getUserApiKeyCenter(userId, { includeAllVisible = false } = {}) {
      const user = publicUser(getUserRow.get(userId));
      if (!user) throw problem("User does not exist", "user_not_found", 404);
      const policy = apiPolicyFor(userId);
      const visibleResources = apiVisibleResources(user);
      const allowedIds = new Set(allowedPolicyResourceIds(user, policy, visibleResources));
      return {
        policy,
        groups: apiGroupsForRole(user.role),
        resources: visibleResources.filter((resource) => includeAllVisible || allowedIds.has(resource.id)).map((resource) => ({
          id: resource.id,
          name: resource.displayName || resource.name,
          type: resource.type,
          vmid: resource.vmid,
          clusterId: resource.clusterId,
          clusterName: resource.clusterName,
          node: resource.node,
          permissions: user.role === "admin" ? ASSIGNMENT_PERMISSIONS : resource.permissions,
        })),
        keys: database.prepare("SELECT * FROM user_api_keys WHERE user_id=? ORDER BY created_at DESC").all(userId)
          .map((row) => publicApiKey(row, user)),
      };
    },
    previewUserApiKey(userId, input) {
      const user = publicUser(getUserRow.get(userId));
      if (!user) throw problem("User does not exist", "user_not_found", 404);
      const normalized = normalizeApiKeyInput(user, input);
      return apiKeySummary(user, normalized, normalized.policy, normalized.visibleResources);
    },
    createUserApiKey(userId, input) {
      const user = publicUser(getUserRow.get(userId));
      if (!user) throw problem("User does not exist", "user_not_found", 404);
      const normalized = normalizeApiKeyInput(user, input);
      const activeCount = database.prepare(`SELECT COUNT(*) AS count FROM user_api_keys
        WHERE user_id=? AND status='active' AND (expires_at IS NULL OR expires_at>?)`).get(userId, Date.now()).count;
      if (Number(activeCount) >= normalized.policy.maxActiveKeys) {
        throw problem("The maximum number of active API keys has been reached", "api_key_limit_reached", 409);
      }
      const id = randomToken(18);
      const secret = `nmb_key_${randomToken(48)}`;
      const suffix = secret.slice(-4);
      const tokenHint = `${secret.slice(0, 12)}…${suffix}`;
      const now = Date.now();
      database.exec("BEGIN IMMEDIATE");
      try {
        database.prepare(`INSERT INTO user_api_keys
          (id,user_id,name,token_hash,token_hint,status,expires_at,created_at,updated_at)
          VALUES (?,?,?,?,?,'active',?,?,?)`)
          .run(id, userId, normalized.name, hashToken(secret, appSecret), tokenHint, normalized.expiresAt, now, now);
        const insertGroup = database.prepare("INSERT INTO user_api_key_groups (key_id,group_id) VALUES (?,?)");
        for (const group of normalized.groups) insertGroup.run(id, group);
        const insertResource = database.prepare("INSERT INTO user_api_key_resources (key_id,resource_id) VALUES (?,?)");
        for (const resourceId of normalized.resourceIds) insertResource.run(id, resourceId);
        database.exec("COMMIT");
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
      return { secret, key: publicApiKey(apiKeyRow(id), user) };
    },
    getUserApiKey(userId, keyId) {
      const row = database.prepare("SELECT * FROM user_api_keys WHERE id=? AND user_id=?").get(keyId, userId);
      return row ? publicApiKey(row) : null;
    },
    revokeUserApiKey(userId, keyId, { revokedBy = userId, reason = "user_revoked" } = {}) {
      const now = Date.now();
      const changed = database.prepare(`UPDATE user_api_keys SET status='revoked',revoked_at=?,revoked_by=?,
        revoked_reason=?,updated_at=? WHERE id=? AND user_id=? AND status='active'`)
        .run(now, revokedBy, reason, now, keyId, userId).changes;
      return changed > 0;
    },
    revokeAllUserApiKeys(userId, { revokedBy = null, reason = "admin_revoked_all" } = {}) {
      const now = Date.now();
      return Number(database.prepare(`UPDATE user_api_keys SET status='revoked',revoked_at=?,revoked_by=?,
        revoked_reason=?,updated_at=? WHERE user_id=? AND status='active'`)
        .run(now, revokedBy, reason, now, userId).changes);
    },
    getIntegrationApiSession(token, { ipAddress = null } = {}) {
      if (!String(token || "").startsWith("nmb_key_") || String(token).length > 260) return null;
      const now = Date.now();
      const row = database.prepare(`SELECT k.id AS api_key_id,k.name AS api_key_name,k.expires_at AS api_key_expires_at,
        k.last_used_at AS api_key_last_used_at,u.*,c.name AS customer_name,c.status AS customer_status,
        c.support_email,c.plan_name,CASE WHEN m.enabled=1 THEN 1 ELSE 0 END AS mfa_enabled
        FROM user_api_keys k
        JOIN users u ON u.id=k.user_id
        JOIN user_api_policies p ON p.user_id=u.id AND p.enabled=1
        LEFT JOIN customers c ON c.id=u.customer_id
        LEFT JOIN user_mfa m ON m.user_id=u.id
        WHERE k.token_hash=? AND k.status='active' AND (k.expires_at IS NULL OR k.expires_at>?)`)
        .get(hashToken(token, appSecret), now);
      if (!row || row.status !== "active" || (row.role === "customer" && row.customer_status !== "active")) return null;
      const user = publicUser(row);
      const policy = apiPolicyFor(user.id);
      const selections = apiKeySelections(row.api_key_id);
      const allowedRoleGroups = new Set(apiGroupsForRole(user.role).map((group) => group.id));
      const policyGroups = new Set(policy.groups);
      const groups = selections.groups.filter((id) => allowedRoleGroups.has(id) && policyGroups.has(id));
      const visible = apiVisibleResources(user);
      const visibleIds = new Set(visible.map((resource) => resource.id));
      const policyIds = new Set(allowedPolicyResourceIds(user, policy, visible));
      const resourceIds = selections.resourceIds.filter((id) => visibleIds.has(id) && policyIds.has(id));
      if (now - Number(row.api_key_last_used_at || 0) > 60_000) {
        database.prepare("UPDATE user_api_keys SET last_used_at=?,last_ip=? WHERE id=?")
          .run(now, String(ipAddress || "").slice(0, 80) || null, row.api_key_id);
      }
      return {
        authType: "api_key",
        idHash: `api-key:${row.api_key_id}`,
        apiKeyId: row.api_key_id,
        apiKeyName: row.api_key_name,
        apiKeyGroups: groups,
        apiKeyResourceIds: resourceIds,
        csrfToken: null,
        expiresAt: row.api_key_expires_at || null,
        user,
      };
    },
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
      if (status === "disabled") {
        const now = Date.now();
        database.prepare("DELETE FROM sessions WHERE user_id=?").run(id);
        database.prepare(`UPDATE api_device_sessions SET revoked_at=?,revoked_reason='account_disabled'
          WHERE user_id=? AND revoked_at IS NULL`).run(now, id);
        database.prepare(`UPDATE api_refresh_tokens SET status='revoked'
          WHERE session_id IN (SELECT id FROM api_device_sessions WHERE user_id=?) AND status='active'`).run(id);
        database.prepare(`UPDATE user_api_keys SET status='revoked',revoked_at=COALESCE(revoked_at,?),
          revoked_reason=COALESCE(revoked_reason,'account_disabled'),updated_at=?
          WHERE user_id=? AND status='active'`).run(now, now, id);
      }
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
      if (revokeSessions) {
        database.prepare("DELETE FROM sessions WHERE user_id=?").run(id);
        database.prepare(`UPDATE api_device_sessions SET revoked_at=?,revoked_reason='password_changed'
          WHERE user_id=? AND revoked_at IS NULL`).run(Date.now(), id);
        database.prepare(`UPDATE api_refresh_tokens SET status='revoked'
          WHERE session_id IN (SELECT id FROM api_device_sessions WHERE user_id=?) AND status='active'`).run(id);
      }
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
    listProxmoxNodes: () => database.prepare(`SELECT n.cluster_id,n.name,n.status,n.last_seen_at,c.name AS cluster_name
      FROM proxmox_nodes n JOIN proxmox_clusters c ON c.id=n.cluster_id
      ORDER BY c.name,n.name`).all().map((row) => ({
      clusterId: row.cluster_id,
      clusterName: row.cluster_name,
      node: row.name,
      status: row.status,
      lastSeenAt: row.last_seen_at || null,
    })),
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
      const getExistingUsage = database.prepare("SELECT storage_used,metadata FROM resources WHERE id=?");
      database.exec("BEGIN IMMEDIATE");
      try {
        for (const resource of resources) {
          if (!["qemu", "lxc"].includes(resource.type) || !Number.isInteger(Number(resource.vmid)) || !resource.node) continue;
          const id = `${clusterId}:${resource.type}:${resource.vmid}`;
          const existing = getExistingUsage.get(id);
          const incomingStorageUsed = resource.storageUsed === null || resource.storageUsed === undefined
            ? null
            : Number(resource.storageUsed);
          const hasCurrentStorageUsage = Number.isFinite(incomingStorageUsed);
          const metadata = { ...(resource.metadata || {}) };
          if (!hasCurrentStorageUsage && existing) {
            const previousUsage = parseJson(existing.metadata, {}).storageUsage;
            if (previousUsage?.available) {
              metadata.storageUsage = {
                ...previousUsage,
                lastKnown: true,
                checkedAt: metadata.storageUsage?.checkedAt || now,
                reason: metadata.storageUsage?.reason || "temporarily_unavailable",
              };
            }
          }
          const storageUsed = hasCurrentStorageUsage ? incomingStorageUsed : Number(existing?.storage_used || 0);
          upsertNode.run(clusterId, resource.node, now);
          upsert.run(
            id, clusterId, resource.node, resource.type, Number(resource.vmid), resource.name || `${resource.type}-${resource.vmid}`,
            resource.status || "unknown", Number(resource.vcpu || 0), Number(resource.memory || 0), Number(resource.memoryUsed || 0),
            Number(resource.storage || 0), storageUsed, Number(resource.cpu || 0), Number(resource.uptime || 0),
            resource.ip || null, JSON.stringify(metadata), now, now, now,
          );
        }
        database.prepare("UPDATE proxmox_clusters SET status='active',last_sync_at=?,last_error=NULL,updated_at=? WHERE id=?").run(now, now, clusterId);
        database.exec("COMMIT");
      } catch (error) { database.exec("ROLLBACK"); throw error; }
      return this.listResources({ clusterId });
    },

    saveOperationsSnapshot(clusterId, snapshot = {}) {
      if (!database.prepare("SELECT 1 FROM proxmox_clusters WHERE id=?").get(clusterId)) {
        throw problem("Cluster does not exist", "cluster_not_found", 404);
      }
      const now = Number(snapshot.collectedAt) || Date.now();
      const nodesAvailable = Array.isArray(snapshot.nodes);
      const storagesAvailable = Array.isArray(snapshot.storages);
      const storagesAuthoritative = storagesAvailable && snapshot.storagesAuthoritative === true;
      const cleanError = (value) => value ? String(value).replace(/[^a-z0-9_.-]/gi, "_").slice(0, 100) : null;
      const integer = (value) => Math.max(0, Math.round(Number(value) || 0));
      const decimal = (value) => Math.max(0, Math.round((Number(value) || 0) * 10) / 10);
      const status = (value) => String(value || "unknown").toLowerCase().slice(0, 40);
      const nodesError = nodesAvailable ? null : cleanError(snapshot.errors?.nodes || "telemetry_unavailable");
      const storagesError = storagesAvailable ? null : cleanError(snapshot.errors?.storages || "telemetry_unavailable");
      const upsertCollection = database.prepare(`INSERT INTO operations_collection_status
        (cluster_id,nodes_available,storages_available,nodes_error,storages_error,collected_at,updated_at)
        VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(cluster_id) DO UPDATE SET
          nodes_available=excluded.nodes_available,storages_available=excluded.storages_available,
          nodes_error=excluded.nodes_error,storages_error=excluded.storages_error,
          collected_at=excluded.collected_at,updated_at=excluded.updated_at`);
      const upsertNode = database.prepare(`INSERT INTO operations_node_metrics
        (cluster_id,node,status,cpu_percent,cpu_cores,memory_used_bytes,memory_total_bytes,memory_percent,
         root_used_bytes,root_total_bytes,root_percent,uptime,last_seen_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(cluster_id,node) DO UPDATE SET
          status=excluded.status,cpu_percent=excluded.cpu_percent,cpu_cores=excluded.cpu_cores,
          memory_used_bytes=excluded.memory_used_bytes,memory_total_bytes=excluded.memory_total_bytes,
          memory_percent=excluded.memory_percent,root_used_bytes=excluded.root_used_bytes,
          root_total_bytes=excluded.root_total_bytes,root_percent=excluded.root_percent,
          uptime=excluded.uptime,last_seen_at=excluded.last_seen_at,updated_at=excluded.updated_at`);
      const upsertStorage = database.prepare(`INSERT INTO operations_storage_metrics
        (cluster_id,node,storage_id,status,storage_type,shared,content,used_bytes,total_bytes,
         available_bytes,usage_percent,last_seen_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(cluster_id,node,storage_id) DO UPDATE SET
          status=excluded.status,storage_type=excluded.storage_type,shared=excluded.shared,content=excluded.content,
          used_bytes=excluded.used_bytes,total_bytes=excluded.total_bytes,available_bytes=excluded.available_bytes,
          usage_percent=excluded.usage_percent,last_seen_at=excluded.last_seen_at,updated_at=excluded.updated_at`);
      const upsertLegacyNode = database.prepare(`INSERT INTO proxmox_nodes (cluster_id,name,status,last_seen_at)
        VALUES (?,?,?,?)
        ON CONFLICT(cluster_id,name) DO UPDATE SET
          status=excluded.status,last_seen_at=excluded.last_seen_at`);

      database.exec("BEGIN IMMEDIATE");
      try {
        upsertCollection.run(clusterId, nodesAvailable ? 1 : 0, storagesAvailable ? 1 : 0, nodesError, storagesError, now, now);
        if (nodesAvailable) {
          database.prepare("UPDATE operations_node_metrics SET status='unknown',updated_at=? WHERE cluster_id=?").run(now, clusterId);
          for (const node of snapshot.nodes) {
            const name = String(node?.node || "").trim().slice(0, 120);
            if (!name) continue;
            const nodeStatus = status(node.status);
            upsertNode.run(
              clusterId, name, nodeStatus, decimal(node.cpuPercent), decimal(node.cpuCores),
              integer(node.memoryUsedBytes), integer(node.memoryTotalBytes), decimal(node.memoryPercent),
              integer(node.rootUsedBytes), integer(node.rootTotalBytes), decimal(node.rootPercent),
              integer(node.uptime), now, now,
            );
            upsertLegacyNode.run(clusterId, name, nodeStatus, now);
          }
        }
        if (storagesAvailable) {
          database.prepare("UPDATE operations_storage_metrics SET status='unknown',updated_at=? WHERE cluster_id=?").run(now, clusterId);
          for (const storage of snapshot.storages) {
            const node = String(storage?.node || "").trim().slice(0, 120);
            const storageId = String(storage?.storageId || "").trim().slice(0, 120);
            if (!node || !storageId) continue;
            upsertStorage.run(
              clusterId, node, storageId, status(storage.status),
              String(storage.type || "unknown").slice(0, 80), storage.shared ? 1 : 0,
              (Array.isArray(storage.content) ? storage.content : String(storage.content || "").split(","))
                .map((entry) => String(entry).trim()).filter(Boolean).join(",").slice(0, 500),
              integer(storage.usedBytes), integer(storage.totalBytes), integer(storage.availableBytes),
              decimal(storage.usagePercent), now, now,
            );
          }
          if (storagesAuthoritative) {
            database.prepare("DELETE FROM operations_storage_metrics WHERE cluster_id=? AND status IN ('unknown','disabled')")
              .run(clusterId);
          }
        }
        database.exec("COMMIT");
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
      return {
        clusterId,
        nodesAvailable,
        storagesAvailable,
        nodesError,
        storagesError,
        collectedAt: now,
      };
    },

    reconcileOperations(clusterId, {
      staleAfterMs = 5 * 60_000,
      stuckTaskMs = OPERATIONS_THRESHOLDS.stuckTaskMinutes * 60_000,
    } = {}) {
      const cluster = database.prepare("SELECT * FROM proxmox_clusters WHERE id=?").get(clusterId);
      if (!cluster) throw problem("Cluster does not exist", "cluster_not_found", 404);
      const now = Date.now();
      const collection = database.prepare("SELECT * FROM operations_collection_status WHERE cluster_id=?").get(clusterId);
      const conditions = [];
      const evaluatedScopes = new Set([`cluster:${clusterId}`, `tasks:${clusterId}`, `resources:${clusterId}`]);
      const addCondition = ({ scope, sourceType, sourceId, type, severity, title, message }) => {
        conditions.push({
          dedupKey: `${scope}:${type}:${sourceId}`,
          clusterId,
          scope,
          sourceType,
          sourceId: String(sourceId),
          type,
          severity,
          title: String(title).slice(0, 180),
          message: String(message).slice(0, 1000),
        });
      };

      if (cluster.status !== "disabled") {
        if (cluster.status === "error") {
          const message = {
            proxmox_timeout: "The Proxmox API did not respond before the synchronization timeout.",
            proxmox_unreachable: "Nimbus could not establish a secure connection to the Proxmox API.",
            proxmox_auth_failed: "Proxmox rejected the configured API token.",
            proxmox_permission_denied: "The API token lacks permission required for resource synchronization.",
          }[cluster.last_error] || `The latest synchronization failed (${cluster.last_error || "unknown error"}).`;
          addCondition({
            scope: `cluster:${clusterId}`,
            sourceType: "cluster",
            sourceId: clusterId,
            type: "cluster_unreachable",
            severity: "critical",
            title: `${cluster.name} is unreachable`,
            message,
          });
        } else if (!cluster.last_sync_at) {
          addCondition({
            scope: `cluster:${clusterId}`,
            sourceType: "cluster",
            sourceId: clusterId,
            type: "cluster_never_synced",
            severity: "warning",
            title: `${cluster.name} has not synchronized`,
            message: "Run the first synchronization to populate inventory and health telemetry.",
          });
        } else if (now - cluster.last_sync_at > Math.max(60_000, Number(staleAfterMs) || 0)) {
          addCondition({
            scope: `cluster:${clusterId}`,
            sourceType: "cluster",
            sourceId: clusterId,
            type: "cluster_sync_stale",
            severity: "warning",
            title: `${cluster.name} telemetry is stale`,
            message: `The latest successful synchronization was ${Math.round((now - cluster.last_sync_at) / 60_000)} minutes ago.`,
          });
        }

        if (collection?.nodes_available) {
          const scope = `nodes:${clusterId}`;
          evaluatedScopes.add(scope);
          const nodes = database.prepare("SELECT * FROM operations_node_metrics WHERE cluster_id=?").all(clusterId);
          for (const node of nodes) {
            if (node.status !== "online") {
              addCondition({
                scope,
                sourceType: "node",
                sourceId: node.node,
                type: "node_offline",
                severity: "critical",
                title: `${node.node} is not online`,
                message: `Proxmox currently reports the node state as ${node.status || "unknown"}.`,
              });
            }
            if (node.cpu_percent >= OPERATIONS_THRESHOLDS.nodeCpuWarning) {
              addCondition({
                scope,
                sourceType: "node",
                sourceId: node.node,
                type: "node_cpu_pressure",
                severity: node.cpu_percent >= OPERATIONS_THRESHOLDS.nodeCpuCritical ? "critical" : "warning",
                title: `High CPU pressure on ${node.node}`,
                message: `Node CPU usage is ${Math.round(node.cpu_percent)}% across ${Number(node.cpu_cores || 0)} cores.`,
              });
            }
            if (node.memory_percent >= OPERATIONS_THRESHOLDS.nodeMemoryWarning) {
              addCondition({
                scope,
                sourceType: "node",
                sourceId: node.node,
                type: "node_memory_pressure",
                severity: node.memory_percent >= OPERATIONS_THRESHOLDS.nodeMemoryCritical ? "critical" : "warning",
                title: `High memory pressure on ${node.node}`,
                message: `Node memory usage is ${Math.round(node.memory_percent)}%.`,
              });
            }
          }
        }

        if (collection?.storages_available) {
          const scope = `storages:${clusterId}`;
          evaluatedScopes.add(scope);
          const storages = database.prepare(`SELECT * FROM operations_storage_metrics
            WHERE cluster_id=? AND status NOT IN ('unknown','disabled')`).all(clusterId);
          for (const storage of storages) {
            if (!["active", "available", "online"].includes(storage.status)) {
              addCondition({
                scope,
                sourceType: "storage",
                sourceId: `${storage.node}:${storage.storage_id}`,
                type: "storage_unavailable",
                severity: "critical",
                title: `${storage.storage_id} is unavailable on ${storage.node}`,
                message: `Proxmox currently reports the storage state as ${storage.status || "unknown"}.`,
              });
            }
            if (storage.total_bytes > 0 && storage.usage_percent >= OPERATIONS_THRESHOLDS.storageWarning) {
              addCondition({
                scope,
                sourceType: "storage",
                sourceId: `${storage.node}:${storage.storage_id}`,
                type: "storage_capacity",
                severity: storage.usage_percent >= OPERATIONS_THRESHOLDS.storageCritical ? "critical" : "warning",
                title: `${storage.storage_id} is filling up`,
                message: `Storage usage on ${storage.node} is ${Math.round(storage.usage_percent)}%.`,
              });
            }
          }
        }

        const staleAssignments = Number(database.prepare(`SELECT COUNT(*) AS count
          FROM resources r JOIN customer_resource_assignments a ON a.resource_id=r.id AND a.status='active'
          WHERE r.cluster_id=? AND r.stale=1`).get(clusterId).count);
        if (staleAssignments) {
          addCondition({
            scope: `resources:${clusterId}`,
            sourceType: "resource",
            sourceId: clusterId,
            type: "assigned_resources_stale",
            severity: "warning",
            title: `${staleAssignments} assigned ${staleAssignments === 1 ? "resource is" : "resources are"} missing`,
            message: "The assignment remains protected locally, but the latest successful Proxmox inventory did not return the resource.",
          });
        }

        const stuckTasks = database.prepare(`SELECT t.*,r.name AS resource_name
          FROM api_tasks t LEFT JOIN resources r ON r.id=t.resource_id
          WHERE t.cluster_id=? AND t.completed_at IS NULL AND t.status!='stopped' AND t.created_at<=?`)
          .all(clusterId, now - Math.max(60_000, Number(stuckTaskMs) || 0));
        for (const task of stuckTasks) {
          const ageMinutes = Math.max(1, Math.round((now - task.created_at) / 60_000));
          addCondition({
            scope: `tasks:${clusterId}`,
            sourceType: "task",
            sourceId: task.id,
            type: "task_stuck",
            severity: ageMinutes >= 60 ? "critical" : "warning",
            title: `${task.action.replace(/_/g, " ")} task is taking too long`,
            message: `${task.resource_name || task.resource_id} has been waiting for ${ageMinutes} minutes on ${task.node}.`,
          });
        }
      } else {
        evaluatedScopes.add(`nodes:${clusterId}`);
        evaluatedScopes.add(`storages:${clusterId}`);
      }

      const activeKeys = new Set(conditions.map((condition) => condition.dedupKey));
      const getIncident = database.prepare("SELECT * FROM operations_incidents WHERE dedup_key=?");
      const createIncident = database.prepare(`INSERT INTO operations_incidents
        (id,dedup_key,cluster_id,scope,source_type,source_id,incident_type,severity,status,title,message,
         first_seen_at,last_seen_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,'open',?,?,?,?,?)`);
      const updateIncident = database.prepare(`UPDATE operations_incidents SET
        severity=?,title=?,message=?,last_seen_at=?,updated_at=? WHERE id=?`);
      const reopenIncident = database.prepare(`UPDATE operations_incidents SET
        severity=?,status='open',title=?,message=?,first_seen_at=?,last_seen_at=?,
        acknowledged_by=NULL,acknowledged_at=NULL,resolved_at=NULL,updated_at=? WHERE id=?`);
      const resolveIncident = database.prepare(`UPDATE operations_incidents SET
        status='resolved',resolved_at=?,updated_at=? WHERE id=?`);

      database.exec("BEGIN IMMEDIATE");
      try {
        for (const condition of conditions) {
          const existing = getIncident.get(condition.dedupKey);
          if (!existing) {
            createIncident.run(
              randomToken(18), condition.dedupKey, condition.clusterId, condition.scope,
              condition.sourceType, condition.sourceId, condition.type, condition.severity,
              condition.title, condition.message, now, now, now,
            );
          } else if (existing.status === "resolved") {
            reopenIncident.run(condition.severity, condition.title, condition.message, now, now, now, existing.id);
          } else {
            updateIncident.run(condition.severity, condition.title, condition.message, now, now, existing.id);
          }
        }
        const unresolved = database.prepare("SELECT * FROM operations_incidents WHERE cluster_id=? AND status!='resolved'").all(clusterId);
        for (const incident of unresolved) {
          if (evaluatedScopes.has(incident.scope) && !activeKeys.has(incident.dedup_key)) {
            resolveIncident.run(now, now, incident.id);
          }
        }
        database.exec("COMMIT");
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
      return database.prepare(operationsIncidentSelect("WHERE i.cluster_id=? AND i.status!='resolved' ORDER BY CASE i.severity WHEN 'critical' THEN 0 ELSE 1 END,i.last_seen_at DESC"))
        .all(clusterId).map(publicOperationsIncident);
    },

    acknowledgeOperationsIncident(id, userId) {
      const incident = database.prepare("SELECT * FROM operations_incidents WHERE id=?").get(id);
      if (!incident) throw problem("Operations incident does not exist", "operations_incident_not_found", 404);
      if (incident.status === "resolved") throw problem("Resolved incidents cannot be acknowledged", "operations_incident_resolved", 409);
      const user = database.prepare("SELECT id FROM users WHERE id=? AND role='admin' AND status='active'").get(userId);
      if (!user) throw problem("An active administrator is required", "admin_required", 403);
      const now = Date.now();
      database.prepare(`UPDATE operations_incidents SET status='acknowledged',
        acknowledged_by=?,acknowledged_at=?,updated_at=? WHERE id=?`)
        .run(userId, now, now, id);
      return publicOperationsIncident(database.prepare(operationsIncidentSelect("WHERE i.id=?")).get(id));
    },

    getOperationsCenter({ taskWindowMs = 24 * 60 * 60_000 } = {}) {
      const clusters = database.prepare(clusterSelect("ORDER BY c.name")).all().map(publicCluster);
      const collections = new Map(database.prepare("SELECT * FROM operations_collection_status").all().map((row) => [row.cluster_id, row]));
      const nodes = database.prepare(`SELECT n.*,c.name AS cluster_name FROM operations_node_metrics n
        JOIN proxmox_clusters c ON c.id=n.cluster_id ORDER BY c.name,n.node`).all().map(publicOperationsNode);
      const storages = database.prepare(`SELECT s.*,c.name AS cluster_name FROM operations_storage_metrics s
        JOIN proxmox_clusters c ON c.id=s.cluster_id
        WHERE s.status NOT IN ('unknown','disabled')
        ORDER BY c.name,s.node,s.storage_id`).all().map(publicOperationsStorage);
      const incidents = database.prepare(operationsIncidentSelect(`WHERE i.status!='resolved'
        ORDER BY CASE i.severity WHEN 'critical' THEN 0 ELSE 1 END,
        CASE i.status WHEN 'open' THEN 0 ELSE 1 END,i.last_seen_at DESC LIMIT 100`)).all().map(publicOperationsIncident);
      const recentResolved = database.prepare(operationsIncidentSelect(`WHERE i.status='resolved'
        ORDER BY i.resolved_at DESC LIMIT 20`)).all().map(publicOperationsIncident);
      const rawTasks = database.prepare(`SELECT t.*,c.name AS cluster_name,r.name AS resource_name,r.vmid,r.type,
          u.display_name AS user_name,cu.name AS customer_name
        FROM api_tasks t
        JOIN proxmox_clusters c ON c.id=t.cluster_id
        LEFT JOIN resources r ON r.id=t.resource_id
        LEFT JOIN users u ON u.id=t.user_id
        LEFT JOIN customers cu ON cu.id=t.customer_id
        WHERE (t.completed_at IS NULL AND t.status!='stopped')
           OR (t.completed_at>=? AND t.exit_status IS NOT NULL AND t.exit_status!='OK')
        ORDER BY CASE WHEN t.completed_at IS NULL THEN 0 ELSE 1 END,t.created_at DESC LIMIT 50`)
        .all(Date.now() - Math.max(60_000, Number(taskWindowMs) || 0));
      const tasks = rawTasks.map((row) => {
        const task = publicTask(row);
        return {
          ...task,
          clusterId: row.cluster_id,
          clusterName: row.cluster_name,
          resourceName: row.resource_name || row.resource_id,
          vmid: row.vmid === null || row.vmid === undefined ? null : Number(row.vmid),
          resourceType: row.type || null,
          exitStatus: row.exit_status || null,
          userName: row.user_name || null,
          customerName: row.customer_name || null,
          durationMs: Math.max(0, Number((row.completed_at || Date.now()) - row.created_at)),
        };
      });
      const activeByCluster = new Map();
      for (const incident of incidents) {
        const entry = activeByCluster.get(incident.clusterId) || { total: 0, critical: 0 };
        entry.total += 1;
        if (incident.severity === "critical") entry.critical += 1;
        activeByCluster.set(incident.clusterId, entry);
      }
      const clusterRows = clusters.map((cluster) => {
        const collection = collections.get(cluster.id);
        const clusterNodes = nodes.filter((node) => node.clusterId === cluster.id);
        const clusterStorages = storages.filter((storage) => storage.clusterId === cluster.id);
        const active = activeByCluster.get(cluster.id) || { total: 0, critical: 0 };
        return {
          ...cluster,
          health: cluster.status === "disabled"
            ? "disabled"
            : active.critical ? "critical" : active.total ? "warning" : cluster.lastSyncAt ? "healthy" : "pending",
          incidentCount: active.total,
          criticalIncidentCount: active.critical,
          onlineNodes: clusterNodes.filter((node) => node.status === "online").length,
          telemetryNodes: clusterNodes.length,
          telemetryStorages: clusterStorages.length,
          telemetry: {
            nodesAvailable: Boolean(collection?.nodes_available),
            storagesAvailable: Boolean(collection?.storages_available),
            nodesError: collection?.nodes_error || null,
            storagesError: collection?.storages_error || null,
            collectedAt: collection?.collected_at || null,
          },
        };
      });
      const uniqueStorages = new Map();
      for (const storage of storages.filter((entry) => entry.status !== "unknown")) {
        const key = storage.shared
          ? `${storage.clusterId}:${storage.storageId}`
          : `${storage.clusterId}:${storage.node}:${storage.storageId}`;
        const current = uniqueStorages.get(key);
        if (!current || storage.totalBytes > current.totalBytes) uniqueStorages.set(key, storage);
      }
      const storageTotals = [...uniqueStorages.values()].reduce((total, storage) => ({
        used: total.used + storage.usedBytes,
        capacity: total.capacity + storage.totalBytes,
      }), { used: 0, capacity: 0 });
      const staleAssignedResources = Number(database.prepare(`SELECT COUNT(*) AS count
        FROM resources r JOIN customer_resource_assignments a ON a.resource_id=r.id AND a.status='active'
        WHERE r.stale=1`).get().count);
      return {
        generatedAt: Date.now(),
        thresholds: OPERATIONS_THRESHOLDS,
        summary: {
          clusters: clusterRows.length,
          healthyClusters: clusterRows.filter((cluster) => cluster.health === "healthy").length,
          nodes: nodes.length,
          onlineNodes: nodes.filter((node) => node.status === "online").length,
          storageUsedBytes: storageTotals.used,
          storageTotalBytes: storageTotals.capacity,
          activeIncidents: incidents.length,
          criticalIncidents: incidents.filter((incident) => incident.severity === "critical").length,
          failedTasks24h: tasks.filter((task) => task.completed && !task.success).length,
          stuckTasks: tasks.filter((task) => !task.completed
            && task.durationMs >= OPERATIONS_THRESHOLDS.stuckTaskMinutes * 60_000).length,
          staleAssignedResources,
        },
        clusters: clusterRows,
        nodes,
        storages,
        incidents,
        recentResolved,
        tasks,
      };
    },

    listResources({ clusterId = null, customerId = null, includeStale = false } = {}) {
      const current = includeStale ? "" : " AND r.stale=0";
      if (customerId) {
        return database.prepare(resourceSelect(`WHERE a.customer_id=? AND a.status='active'${current}`))
          .all(customerId).map(publicResource);
      }
      if (clusterId) {
        return database.prepare(resourceSelect(`WHERE r.cluster_id=?${current}`))
          .all(clusterId).map(publicResource);
      }
      const where = includeStale ? "" : "WHERE r.stale=0";
      return database.prepare(resourceSelect(where)).all().map(publicResource).sort((left, right) =>
        left.clusterName.localeCompare(right.clusterName) || left.node.localeCompare(right.node) || left.vmid - right.vmid);
    },
    getResource: (id) => publicResource(getResourceRow.get(id)),
    setResourceStatus(id, status) {
      database.prepare("UPDATE resources SET status=?,updated_at=? WHERE id=?").run(status, Date.now(), id);
      return publicResource(getResourceRow.get(id));
    },
    assignResource({ customerId, resourceId, displayName = null, permissions = DEFAULT_PERMISSIONS, snapshotLimit, alertPolicy }) {
      if (!getCustomerRow.get(customerId)) throw problem("Customer does not exist", "customer_not_found", 404);
      const target = getResourceRow.get(resourceId);
      if (!target || target.stale) throw problem("Resource does not exist", "resource_not_found", 404);
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
        AND r.stale=0
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
    registerPushDevice(userId, {
      token,
      platform = "ios",
      environment = "production",
      appVersion = "",
    }) {
      if (!getUserRow.get(userId)) throw problem("User does not exist", "user_not_found", 404);
      const cleanToken = String(token || "").trim().toLowerCase();
      if (!/^[a-f0-9]{64,200}$/.test(cleanToken)) {
        throw problem("The push device token is invalid", "invalid_push_token");
      }
      if (platform !== "ios" || !["sandbox", "production"].includes(environment)) {
        throw problem("The push device registration is invalid", "invalid_push_device");
      }
      const tokenHash = hashToken(cleanToken, appSecret);
      const existing = database.prepare("SELECT * FROM mobile_push_devices WHERE token_hash=?").get(tokenHash);
      const id = existing?.id || randomToken(18);
      const now = Date.now();
      database.prepare(`INSERT INTO mobile_push_devices
        (id,user_id,token_hash,token_encrypted,platform,environment,app_version,status,failure_reason,last_registered_at,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,'active',NULL,?,?,?)
        ON CONFLICT(token_hash) DO UPDATE SET
          user_id=excluded.user_id,token_encrypted=excluded.token_encrypted,platform=excluded.platform,
          environment=excluded.environment,app_version=excluded.app_version,status='active',
          failure_reason=NULL,last_registered_at=excluded.last_registered_at,updated_at=excluded.updated_at`)
        .run(
          id,
          userId,
          tokenHash,
          encryptSecret(cleanToken, appSecret),
          platform,
          environment,
          String(appVersion || "").trim().slice(0, 40) || null,
          now,
          existing?.created_at || now,
          now,
        );
      return { id, registered: true };
    },
    unregisterPushDevice(userId, token) {
      const tokenHash = hashToken(String(token || "").trim().toLowerCase(), appSecret);
      return Boolean(database.prepare("DELETE FROM mobile_push_devices WHERE user_id=? AND token_hash=?")
        .run(userId, tokenHash).changes);
    },
    listPushDevices(userId) {
      return database.prepare(`SELECT * FROM mobile_push_devices
        WHERE user_id=? AND status='active' ORDER BY updated_at DESC`).all(userId).map((row) => ({
        id: row.id,
        token: decryptSecret(row.token_encrypted, appSecret),
        platform: row.platform,
        environment: row.environment,
        appVersion: row.app_version || null,
      }));
    },
    markPushDeviceSent(id) {
      database.prepare("UPDATE mobile_push_devices SET last_sent_at=?,updated_at=? WHERE id=?")
        .run(Date.now(), Date.now(), id);
    },
    disablePushDevice(id, reason = "delivery_failed") {
      database.prepare(`UPDATE mobile_push_devices SET status='disabled',failure_reason=?,updated_at=?
        WHERE id=?`).run(String(reason).slice(0, 120), Date.now(), id);
    },

    createMaintenanceEvent(input, { userId = null } = {}) {
      const event = normalizeMaintenanceInput(input);
      const targets = normalizeMaintenanceTargets(input.targets);
      const id = randomToken(18);
      const now = Date.now();
      database.exec("BEGIN IMMEDIATE");
      try {
        database.prepare(`INSERT INTO maintenance_events
          (id,kind,title,message,severity,status,starts_at,ends_at,notify_email,created_by,updated_by,created_at,updated_at)
          VALUES (?,?,?,?,?,'draft',?,?,?,?,?,?,?)`)
          .run(
            id,
            event.kind,
            event.title,
            event.message,
            event.severity,
            event.startsAt,
            event.endsAt,
            event.notifyEmail ? 1 : 0,
            userId,
            userId,
            now,
            now,
          );
        const insertTarget = database.prepare("INSERT INTO maintenance_targets (event_id,target_type,target_id) VALUES (?,?,?)");
        for (const target of targets) insertTarget.run(id, target.type, target.id);
        database.exec("COMMIT");
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
      return publicMaintenanceEvent(maintenanceEventRow(id), maintenanceTargets(id));
    },
    updateMaintenanceEvent(id, input, { userId = null } = {}) {
      const row = database.prepare("SELECT * FROM maintenance_events WHERE id=?").get(id);
      if (!row) throw problem("Maintenance notice does not exist", "maintenance_not_found", 404);
      if (row.status !== "draft") throw problem("Published maintenance notices cannot be edited", "maintenance_not_editable", 409);
      const event = normalizeMaintenanceInput(input, row);
      const targets = input.targets === undefined ? maintenanceTargets(id).map(({ type, id: targetId }) => ({ type, id: targetId })) : normalizeMaintenanceTargets(input.targets);
      const now = Date.now();
      database.exec("BEGIN IMMEDIATE");
      try {
        database.prepare(`UPDATE maintenance_events SET kind=?,title=?,message=?,severity=?,starts_at=?,ends_at=?,
          notify_email=?,updated_by=?,updated_at=? WHERE id=?`)
          .run(
            event.kind,
            event.title,
            event.message,
            event.severity,
            event.startsAt,
            event.endsAt,
            event.notifyEmail ? 1 : 0,
            userId,
            now,
            id,
          );
        if (input.targets !== undefined) {
          database.prepare("DELETE FROM maintenance_targets WHERE event_id=?").run(id);
          const insertTarget = database.prepare("INSERT INTO maintenance_targets (event_id,target_type,target_id) VALUES (?,?,?)");
          for (const target of targets) insertTarget.run(id, target.type, target.id);
        }
        database.exec("COMMIT");
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
      return publicMaintenanceEvent(maintenanceEventRow(id), maintenanceTargets(id));
    },
    publishMaintenanceEvent(id, { userId = null } = {}) {
      const row = database.prepare("SELECT * FROM maintenance_events WHERE id=?").get(id);
      if (!row) throw problem("Maintenance notice does not exist", "maintenance_not_found", 404);
      if (row.status !== "draft") throw problem("This maintenance notice was already published", "maintenance_already_published", 409);
      if (row.ends_at !== null && Number(row.ends_at) <= Date.now()) {
        throw problem("The maintenance window has already ended", "maintenance_ended", 409);
      }
      const targets = normalizeMaintenanceTargets(
        maintenanceTargets(id).map(({ type, id: targetId }) => ({ type, id: targetId })),
      );
      const recipients = maintenanceRecipientsForTargets(targets);
      if (!recipients.length) throw problem("No active customer users are affected by this audience", "maintenance_no_recipients", 409);
      const now = Date.now();
      const status = Number(row.starts_at) <= now ? "active" : "scheduled";
      const deliveries = [];
      database.exec("BEGIN IMMEDIATE");
      try {
        database.prepare(`UPDATE maintenance_events SET status=?,published_at=?,updated_by=?,updated_at=? WHERE id=?`)
          .run(status, now, userId, now, id);
        const insertDelivery = database.prepare(`INSERT INTO maintenance_deliveries
          (id,event_id,user_id,created_at) VALUES (?,?,?,?)`);
        for (const recipient of recipients) {
          const deliveryId = randomToken(18);
          insertDelivery.run(deliveryId, id, recipient.id, now);
          deliveries.push({ ...recipient, deliveryId });
        }
        database.exec("COMMIT");
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
      return {
        event: publicMaintenanceEvent(maintenanceEventRow(id), maintenanceTargets(id)),
        deliveries,
      };
    },
    listMaintenanceEvents({ limit = 100, offset = 0 } = {}) {
      this.advanceMaintenanceEvents();
      const safeLimit = Math.min(250, Math.max(1, Number(limit) || 100));
      const safeOffset = Math.max(0, Number(offset) || 0);
      const rows = database.prepare(`SELECT e.*,
        creator.display_name AS created_by_name,updater.display_name AS updated_by_name,
        (SELECT COUNT(*) FROM maintenance_deliveries d WHERE d.event_id=e.id) AS recipient_count
        FROM maintenance_events e
        LEFT JOIN users creator ON creator.id=e.created_by
        LEFT JOIN users updater ON updater.id=e.updated_by
        ORDER BY CASE e.status WHEN 'active' THEN 0 WHEN 'scheduled' THEN 1 WHEN 'draft' THEN 2 ELSE 3 END,
          e.starts_at DESC LIMIT ? OFFSET ?`).all(safeLimit, safeOffset);
      return {
        items: rows.map((row) => publicMaintenanceEvent(row, maintenanceTargets(row.id))),
        total: Number(database.prepare("SELECT COUNT(*) AS count FROM maintenance_events").get().count),
        limit: safeLimit,
        offset: safeOffset,
      };
    },
    getMaintenanceEvent(id) {
      const row = maintenanceEventRow(id);
      return row ? publicMaintenanceEvent(row, maintenanceTargets(id)) : null;
    },
    listMaintenanceForUser(userId, { limit = 100, offset = 0 } = {}) {
      this.advanceMaintenanceEvents();
      const safeLimit = Math.min(250, Math.max(1, Number(limit) || 100));
      const safeOffset = Math.max(0, Number(offset) || 0);
      const select = `SELECT e.*,d.id AS delivery_id,d.read_at,d.email_job_id,d.resolution_email_job_id
        FROM maintenance_deliveries d JOIN maintenance_events e ON e.id=d.event_id
        WHERE d.user_id=? AND e.status!='draft'`;
      const rows = database.prepare(`${select}
        ORDER BY CASE e.status WHEN 'active' THEN 0 WHEN 'scheduled' THEN 1 ELSE 2 END,
          e.starts_at DESC LIMIT ? OFFSET ?`).all(userId, safeLimit, safeOffset);
      const counts = database.prepare(`SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN d.read_at IS NULL THEN 1 ELSE 0 END) AS unread,
        SUM(CASE WHEN e.status='active' THEN 1 ELSE 0 END) AS active_count,
        SUM(CASE WHEN e.status='scheduled' THEN 1 ELSE 0 END) AS upcoming_count
        FROM maintenance_deliveries d JOIN maintenance_events e ON e.id=d.event_id
        WHERE d.user_id=? AND e.status!='draft'`).get(userId);
      return {
        items: rows.map((row) => publicMaintenanceDelivery(row, maintenanceTargets(row.id))),
        total: Number(counts.total || 0),
        unread: Number(counts.unread || 0),
        activeCount: Number(counts.active_count || 0),
        upcomingCount: Number(counts.upcoming_count || 0),
        limit: safeLimit,
        offset: safeOffset,
      };
    },
    markMaintenanceRead(deliveryId, userId) {
      const result = database.prepare(`UPDATE maintenance_deliveries SET read_at=COALESCE(read_at,?)
        WHERE id=? AND user_id=?`).run(Date.now(), deliveryId, userId);
      if (!result.changes) throw problem("Maintenance notice does not exist", "maintenance_not_found", 404);
    },
    setMaintenanceEmailJob(deliveryId, emailJobId, { resolution = false } = {}) {
      const column = resolution ? "resolution_email_job_id" : "email_job_id";
      database.prepare(`UPDATE maintenance_deliveries SET ${column}=? WHERE id=?`).run(emailJobId, deliveryId);
    },
    resolveMaintenanceEvent(id, { userId = null } = {}) {
      this.advanceMaintenanceEvents();
      const row = database.prepare("SELECT * FROM maintenance_events WHERE id=?").get(id);
      if (!row) throw problem("Maintenance notice does not exist", "maintenance_not_found", 404);
      if (!["active", "scheduled"].includes(row.status)) {
        throw problem("Only active or scheduled maintenance can be resolved", "maintenance_not_resolvable", 409);
      }
      const now = Date.now();
      database.prepare(`UPDATE maintenance_events SET status='resolved',resolved_at=?,updated_by=?,updated_at=? WHERE id=?`)
        .run(now, userId, now, id);
      return {
        event: publicMaintenanceEvent(maintenanceEventRow(id), maintenanceTargets(id)),
        deliveries: maintenanceDeliveryRecipients(id),
      };
    },
    cancelMaintenanceEvent(id, { userId = null } = {}) {
      const row = database.prepare("SELECT * FROM maintenance_events WHERE id=?").get(id);
      if (!row) throw problem("Maintenance notice does not exist", "maintenance_not_found", 404);
      if (!["draft", "scheduled"].includes(row.status)) {
        throw problem("Only draft or scheduled maintenance can be cancelled", "maintenance_not_cancellable", 409);
      }
      const now = Date.now();
      database.prepare(`UPDATE maintenance_events SET status='cancelled',cancelled_at=?,updated_by=?,updated_at=? WHERE id=?`)
        .run(now, userId, now, id);
      return publicMaintenanceEvent(maintenanceEventRow(id), maintenanceTargets(id));
    },
    deleteMaintenanceEvent(id) {
      const row = database.prepare("SELECT status FROM maintenance_events WHERE id=?").get(id);
      if (!row) throw problem("Maintenance notice does not exist", "maintenance_not_found", 404);
      if (row.status !== "draft") throw problem("Only drafts can be deleted", "maintenance_not_deletable", 409);
      database.prepare("DELETE FROM maintenance_events WHERE id=?").run(id);
    },
    advanceMaintenanceEvents(now = Date.now()) {
      database.prepare(`UPDATE maintenance_events SET status='active',updated_at=?
        WHERE status='scheduled' AND starts_at<=?`).run(now, now);
      const resolved = database.prepare(`UPDATE maintenance_events SET status='resolved',
        resolved_at=COALESCE(resolved_at,?),updated_at=?
        WHERE status='active' AND ends_at IS NOT NULL AND ends_at<=?`).run(now, now, now);
      return resolved.changes;
    },

    createSupportTicket(input, { customerId, userId }) {
      const ticket = normalizeSupportTicketInput(input);
      const customer = database.prepare("SELECT status FROM customers WHERE id=?").get(customerId);
      if (!customer || customer.status !== "active") {
        throw problem("Customer account does not exist", "customer_not_found", 404);
      }
      if (ticket.resourceId) {
        const assignment = database.prepare(`SELECT 1 FROM customer_resource_assignments
          WHERE customer_id=? AND resource_id=? AND status='active'`).get(customerId, ticket.resourceId);
        if (!assignment) throw problem("The selected resource is not assigned to this customer", "invalid_ticket_resource", 404);
      }
      const id = randomToken(18);
      const messageId = randomToken(18);
      const now = Date.now();
      database.exec("BEGIN IMMEDIATE");
      try {
        database.prepare(`INSERT INTO support_tickets
          (id,reference,customer_id,created_by,resource_id,subject,category,priority,status,last_message_at,created_at,updated_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
          .run(
            id,
            supportTicketReference(id, now),
            customerId,
            userId,
            ticket.resourceId,
            ticket.subject,
            ticket.category,
            ticket.priority,
            "waiting_support",
            now,
            now,
            now,
          );
        database.prepare(`INSERT INTO support_ticket_messages
          (id,ticket_id,author_user_id,author_role,body,internal,created_at)
          VALUES (?,?,?,?,?,0,?)`).run(messageId, id, userId, "customer", ticket.message, now);
        database.prepare(`INSERT INTO support_ticket_reads (ticket_id,user_id,last_read_at)
          VALUES (?,?,?)`).run(id, userId, now);
        database.exec("COMMIT");
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
      return this.getSupportTicket(id, { role: "customer", customerId, id: userId });
    },
    listSupportTickets(scope, { limit = 100, offset = 0, status = "", priority = "", search = "" } = {}) {
      const safeLimit = Math.min(250, Math.max(1, Number(limit) || 100));
      const safeOffset = Math.max(0, Number(offset) || 0);
      const filters = [];
      const values = [scope?.id || null];
      if (scope?.role !== "admin") {
        if (!scope?.customerId) return { items: [], total: 0, unread: 0, active: 0, waitingSupport: 0, waitingCustomer: 0, resolved: 0, limit: safeLimit, offset: safeOffset };
        filters.push("t.customer_id=?");
        values.push(scope.customerId);
      }
      if (status && ["open", "waiting_support", "waiting_customer", "resolved", "closed"].includes(status)) {
        filters.push("t.status=?");
        values.push(status);
      }
      if (priority && ["low", "normal", "high", "urgent"].includes(priority)) {
        filters.push("t.priority=?");
        values.push(priority);
      }
      const cleanSearch = String(search || "").trim().toLowerCase().slice(0, 160);
      if (cleanSearch) {
        filters.push("(LOWER(t.reference) LIKE ? OR LOWER(t.subject) LIKE ? OR LOWER(c.name) LIKE ?)");
        const like = `%${cleanSearch.replace(/[%_]/g, "\\$&")}%`;
        values.push(like, like, like);
      }
      const where = filters.length ? `WHERE ${filters.join(" AND ")}` : "";
      const select = `SELECT t.*,c.name AS customer_name,
        creator.display_name AS created_by_name,assignee.display_name AS assigned_to_name,
        r.name AS resource_name,r.type AS resource_type,r.vmid,
        (SELECT COUNT(*) FROM support_ticket_messages m WHERE m.ticket_id=t.id) AS message_count,
        (SELECT COUNT(*) FROM support_ticket_messages m WHERE m.ticket_id=t.id AND m.internal=0) AS public_message_count,
        (SELECT COUNT(*) FROM support_ticket_messages m WHERE m.ticket_id=t.id AND m.internal=1) AS internal_note_count,
        CASE WHEN t.last_message_at>COALESCE(rd.last_read_at,0) THEN 1 ELSE 0 END AS unread
        FROM support_tickets t
        JOIN customers c ON c.id=t.customer_id
        LEFT JOIN users creator ON creator.id=t.created_by
        LEFT JOIN users assignee ON assignee.id=t.assigned_to
        LEFT JOIN resources r ON r.id=t.resource_id
        LEFT JOIN support_ticket_reads rd ON rd.ticket_id=t.id AND rd.user_id=?
        ${where}`;
      const items = database.prepare(`${select}
        ORDER BY CASE t.status WHEN 'waiting_support' THEN 0 WHEN 'open' THEN 1 WHEN 'waiting_customer' THEN 2 WHEN 'resolved' THEN 3 ELSE 4 END,
          CASE t.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END,
          t.last_message_at DESC LIMIT ? OFFSET ?`).all(...values, safeLimit, safeOffset)
        .map((row) => publicSupportTicket(row, { includeInternal: scope?.role === "admin" }));
      const scopeFilter = scope?.role === "admin" ? "" : "WHERE customer_id=?";
      const scopeValues = scope?.role === "admin" ? [] : [scope.customerId];
      const counts = database.prepare(`SELECT COUNT(*) AS total,
        SUM(CASE WHEN status IN ('open','waiting_support','waiting_customer') THEN 1 ELSE 0 END) AS active,
        SUM(CASE WHEN status='waiting_support' THEN 1 ELSE 0 END) AS waiting_support,
        SUM(CASE WHEN status='waiting_customer' THEN 1 ELSE 0 END) AS waiting_customer,
        SUM(CASE WHEN status='resolved' THEN 1 ELSE 0 END) AS resolved
        FROM support_tickets ${scopeFilter}`).get(...scopeValues);
      const unreadFilter = scope?.role === "admin" ? "" : "AND t.customer_id=?";
      const unread = Number(database.prepare(`SELECT COUNT(*) AS count FROM support_tickets t
        LEFT JOIN support_ticket_reads rd ON rd.ticket_id=t.id AND rd.user_id=?
        WHERE t.last_message_at>COALESCE(rd.last_read_at,0) ${unreadFilter}`)
        .get(scope?.id || null, ...scopeValues).count || 0);
      return {
        items,
        total: Number(counts.total || 0),
        unread,
        active: Number(counts.active || 0),
        waitingSupport: Number(counts.waiting_support || 0),
        waitingCustomer: Number(counts.waiting_customer || 0),
        resolved: Number(counts.resolved || 0),
        limit: safeLimit,
        offset: safeOffset,
      };
    },
    getSupportTicket(id, scope) {
      const row = requireSupportTicket(id, scope);
      return {
        ticket: publicSupportTicket(row, { includeInternal: scope?.role === "admin" }),
        messages: supportTicketMessages(id, { includeInternal: scope?.role === "admin" }),
      };
    },
    addSupportTicketMessage(id, input, scope, { internal = false } = {}) {
      const row = requireSupportTicket(id, scope);
      if (internal && scope?.role !== "admin") {
        throw problem("Only administrators can create internal notes", "admin_required", 403);
      }
      if (!internal && ["resolved", "closed"].includes(row.status)) {
        throw problem("Reopen this ticket before replying", "support_ticket_not_replyable", 409);
      }
      const body = normalizeSupportMessage(input?.message);
      const messageId = randomToken(18);
      const now = Date.now();
      const authorRole = scope.role === "admin" ? "admin" : "customer";
      const nextStatus = internal ? row.status : authorRole === "admin" ? "waiting_customer" : "waiting_support";
      database.exec("BEGIN IMMEDIATE");
      try {
        database.prepare(`INSERT INTO support_ticket_messages
          (id,ticket_id,author_user_id,author_role,body,internal,created_at)
          VALUES (?,?,?,?,?,?,?)`).run(messageId, id, scope.id, authorRole, body, internal ? 1 : 0, now);
        if (!internal) {
          database.prepare(`UPDATE support_tickets SET status=?,last_message_at=?,updated_at=? WHERE id=?`)
            .run(nextStatus, now, now, id);
        }
        database.prepare(`INSERT INTO support_ticket_reads (ticket_id,user_id,last_read_at) VALUES (?,?,?)
          ON CONFLICT(ticket_id,user_id) DO UPDATE SET last_read_at=excluded.last_read_at`).run(id, scope.id, now);
        database.exec("COMMIT");
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
      return {
        ...this.getSupportTicket(id, scope),
        message: publicSupportMessage(database.prepare(`SELECT m.*,u.display_name AS author_name
          FROM support_ticket_messages m LEFT JOIN users u ON u.id=m.author_user_id WHERE m.id=?`).get(messageId)),
      };
    },
    updateSupportTicket(id, input, adminUser) {
      const row = requireSupportTicket(id, adminUser);
      if (adminUser?.role !== "admin") throw problem("Administrator access is required", "admin_required", 403);
      const status = input.status === undefined ? row.status : String(input.status).trim().toLowerCase();
      const priority = input.priority === undefined ? row.priority : String(input.priority).trim().toLowerCase();
      const rawAssignee = input.assignedTo === undefined ? row.assigned_to : String(input.assignedTo || "").trim();
      const assignedTo = rawAssignee || null;
      if (!["open", "waiting_support", "waiting_customer", "resolved", "closed"].includes(status)) {
        throw problem("Choose a valid ticket status", "invalid_ticket_status");
      }
      if (!["low", "normal", "high", "urgent"].includes(priority)) {
        throw problem("Choose a valid ticket priority", "invalid_ticket_priority");
      }
      if (assignedTo) {
        const assignee = database.prepare("SELECT role,status FROM users WHERE id=?").get(assignedTo);
        if (!assignee || assignee.role !== "admin" || assignee.status !== "active") {
          throw problem("Choose an active administrator", "invalid_ticket_assignee");
        }
      }
      const now = Date.now();
      const resolvedAt = status === "resolved" ? (row.resolved_at || now) : null;
      const closedAt = status === "closed" ? (row.closed_at || now) : null;
      database.prepare(`UPDATE support_tickets SET status=?,priority=?,assigned_to=?,resolved_at=?,closed_at=?,updated_at=?
        WHERE id=?`).run(status, priority, assignedTo, resolvedAt, closedAt, now, id);
      return publicSupportTicket(supportTicketRow(id, adminUser.id), { includeInternal: true });
    },
    closeSupportTicket(id, scope) {
      const row = requireSupportTicket(id, scope);
      if (row.status === "closed") return publicSupportTicket(row, { includeInternal: scope?.role === "admin" });
      const now = Date.now();
      database.prepare(`UPDATE support_tickets SET status='closed',closed_at=?,updated_at=? WHERE id=?`).run(now, now, id);
      return publicSupportTicket(supportTicketRow(id, scope.id), { includeInternal: scope?.role === "admin" });
    },
    reopenSupportTicket(id, scope) {
      const row = requireSupportTicket(id, scope);
      if (!["resolved", "closed"].includes(row.status)) {
        throw problem("Only resolved or closed tickets can be reopened", "support_ticket_not_reopenable", 409);
      }
      const now = Date.now();
      database.prepare(`UPDATE support_tickets SET status='waiting_support',resolved_at=NULL,closed_at=NULL,updated_at=?
        WHERE id=?`).run(now, id);
      return publicSupportTicket(supportTicketRow(id, scope.id), { includeInternal: scope?.role === "admin" });
    },
    markSupportTicketRead(id, scope) {
      requireSupportTicket(id, scope);
      database.prepare(`INSERT INTO support_ticket_reads (ticket_id,user_id,last_read_at) VALUES (?,?,?)
        ON CONFLICT(ticket_id,user_id) DO UPDATE SET last_read_at=excluded.last_read_at`)
        .run(id, scope.id, Date.now());
    },
    listSupportTicketRecipients(id, audience = "customer") {
      const row = supportTicketRow(id);
      if (!row) throw problem("Support ticket does not exist", "support_ticket_not_found", 404);
      if (audience === "admin") {
        if (row.assigned_to) {
          const assigned = database.prepare(`SELECT id,email,display_name FROM users
            WHERE id=? AND role='admin' AND status='active'`).get(row.assigned_to);
          if (assigned) return [{ id: assigned.id, email: assigned.email, displayName: assigned.display_name }];
        }
        return database.prepare(`SELECT id,email,display_name FROM users
          WHERE role='admin' AND status='active' ORDER BY id`).all().map((entry) => ({
          id: entry.id, email: entry.email, displayName: entry.display_name,
        }));
      }
      return database.prepare(`SELECT u.id,u.email,u.display_name FROM users u
        JOIN customers c ON c.id=u.customer_id
        WHERE u.customer_id=? AND u.role='customer' AND u.status='active' AND c.status='active'
        ORDER BY u.id`).all(row.customer_id).map((entry) => ({
        id: entry.id, email: entry.email, displayName: entry.display_name,
      }));
    },
    listSupportAssignees() {
      return database.prepare(`SELECT id,email,display_name FROM users
        WHERE role='admin' AND status='active' ORDER BY display_name`).all().map((row) => ({
        id: row.id, email: row.email, displayName: row.display_name,
      }));
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
        database.prepare(`UPDATE api_device_sessions SET revoked_at=?,revoked_reason='account_token_completed'
          WHERE user_id=? AND revoked_at IS NULL`).run(now, userId);
        database.prepare(`UPDATE api_refresh_tokens SET status='revoked'
          WHERE session_id IN (SELECT id FROM api_device_sessions WHERE user_id=?) AND status='active'`).run(userId);
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

    createApiDeviceSession({
      userId,
      accessTtlMs,
      refreshTtlMs,
      deviceName = "Nimbus mobile device",
      platform = "other",
      appVersion = null,
      ipAddress = null,
      userAgent = null,
      maxSessions = 10,
    }) {
      const user = getUserRow.get(userId);
      if (!user || user.status !== "active" || (user.role === "customer" && user.customer_status !== "active")) {
        throw problem("Account is not available", "authentication_required", 401);
      }
      const normalizedDeviceName = String(deviceName || "Nimbus mobile device").trim().slice(0, 100);
      const normalizedPlatform = String(platform || "other").toLowerCase();
      if (!normalizedDeviceName) throw problem("Device name is required", "invalid_device");
      if (!["ios", "android", "desktop", "other"].includes(normalizedPlatform)) {
        throw problem("Device platform is invalid", "invalid_device");
      }
      const now = Date.now();
      const id = randomToken(18);
      const accessToken = `nmb_at_${randomToken(32)}`;
      const refreshToken = `nmb_rt_${randomToken(48)}`;
      const accessExpiresAt = now + Number(accessTtlMs);
      const refreshExpiresAt = now + Number(refreshTtlMs);
      if (!Number.isSafeInteger(accessExpiresAt) || !Number.isSafeInteger(refreshExpiresAt)
        || accessExpiresAt <= now || refreshExpiresAt <= accessExpiresAt) {
        throw problem("API token lifetime is invalid", "invalid_token_lifetime", 500);
      }
      database.exec("BEGIN IMMEDIATE");
      try {
        expireApiDeviceSessions(now);
        database.prepare(`INSERT INTO api_device_sessions
          (id,user_id,access_token_hash,device_name,platform,app_version,ip_address,user_agent,
           access_expires_at,refresh_expires_at,created_at,last_seen_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(
          id,
          userId,
          hashToken(accessToken, appSecret),
          normalizedDeviceName,
          normalizedPlatform,
          String(appVersion || "").trim().slice(0, 60) || null,
          String(ipAddress || "").slice(0, 80) || null,
          String(userAgent || "").slice(0, 300) || null,
          accessExpiresAt,
          refreshExpiresAt,
          now,
          now,
        );
        database.prepare(`INSERT INTO api_refresh_tokens
          (token_hash,session_id,status,expires_at,created_at)
          VALUES (?,?,'active',?,?)`).run(hashToken(refreshToken, appSecret), id, refreshExpiresAt, now);
        const limit = Math.max(1, Math.min(100, Number(maxSessions) || 10));
        const older = database.prepare(`SELECT id FROM api_device_sessions
          WHERE user_id=? AND revoked_at IS NULL
          ORDER BY created_at DESC,rowid DESC LIMIT -1 OFFSET ?`).all(userId, limit);
        for (const row of older) revokeApiDeviceSessionRow(row.id, "session_limit", now);
        database.exec("COMMIT");
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
      return {
        tokenType: "Bearer",
        accessToken,
        accessTokenExpiresAt: accessExpiresAt,
        refreshToken,
        refreshTokenExpiresAt: refreshExpiresAt,
        session: publicApiDeviceSession(database.prepare("SELECT * FROM api_device_sessions WHERE id=?").get(id), `mobile:${id}`),
      };
    },
    getApiAccessSession(accessToken) {
      if (!String(accessToken || "").startsWith("nmb_at_") || String(accessToken).length > 200) return null;
      const now = Date.now();
      const row = database.prepare(`SELECT d.id AS api_session_id,d.access_expires_at,d.refresh_expires_at,
        d.last_seen_at AS api_last_seen_at,u.*,c.name AS customer_name,c.status AS customer_status,
        c.support_email,c.plan_name,CASE WHEN m.enabled=1 THEN 1 ELSE 0 END AS mfa_enabled
        FROM api_device_sessions d
        JOIN users u ON u.id=d.user_id
        LEFT JOIN customers c ON c.id=u.customer_id
        LEFT JOIN user_mfa m ON m.user_id=u.id
        WHERE d.access_token_hash=? AND d.revoked_at IS NULL
          AND d.access_expires_at>? AND d.refresh_expires_at>?`)
        .get(hashToken(accessToken, appSecret), now, now);
      if (!row || row.status !== "active" || (row.role === "customer" && row.customer_status !== "active")) return null;
      if (now - Number(row.api_last_seen_at || 0) > 60_000) {
        database.prepare("UPDATE api_device_sessions SET last_seen_at=? WHERE id=?").run(now, row.api_session_id);
      }
      return {
        authType: "bearer",
        idHash: `mobile:${row.api_session_id}`,
        mobileSessionId: row.api_session_id,
        csrfToken: null,
        expiresAt: row.access_expires_at,
        refreshExpiresAt: row.refresh_expires_at,
        user: publicUser(row),
      };
    },
    rotateApiRefreshToken(refreshToken, {
      accessTtlMs,
      ipAddress = null,
      userAgent = null,
    } = {}) {
      if (!String(refreshToken || "").startsWith("nmb_rt_") || String(refreshToken).length > 260) {
        throw problem("Refresh token is invalid", "invalid_refresh_token", 401);
      }
      const now = Date.now();
      const tokenHash = hashToken(refreshToken, appSecret);
      const nextAccessToken = `nmb_at_${randomToken(32)}`;
      const nextRefreshToken = `nmb_rt_${randomToken(48)}`;
      let result = null;
      let failure = null;
      database.exec("BEGIN IMMEDIATE");
      try {
        const row = database.prepare(`SELECT
          r.token_hash,r.status AS refresh_status,r.expires_at AS token_expires_at,
          d.*,u.status AS user_status,u.role,c.status AS customer_status
          FROM api_refresh_tokens r
          JOIN api_device_sessions d ON d.id=r.session_id
          JOIN users u ON u.id=d.user_id
          LEFT JOIN customers c ON c.id=u.customer_id
          WHERE r.token_hash=?`).get(tokenHash);
        if (!row) {
          failure = problem("Refresh token is invalid", "invalid_refresh_token", 401);
        } else if (row.refresh_status === "rotated") {
          revokeApiDeviceSessionRow(row.id, "refresh_token_reuse", now);
          failure = problem("Refresh token reuse was detected and the device session was revoked", "refresh_token_reused", 401);
        } else if (row.refresh_status !== "active" || row.revoked_at
          || Number(row.token_expires_at) <= now || Number(row.refresh_expires_at) <= now
          || row.user_status !== "active" || (row.role === "customer" && row.customer_status !== "active")) {
          revokeApiDeviceSessionRow(row.id, "refresh_token_invalid", now);
          failure = problem("Refresh token is invalid", "invalid_refresh_token", 401);
        } else {
          const accessExpiresAt = Math.min(now + Number(accessTtlMs), Number(row.refresh_expires_at));
          if (!Number.isSafeInteger(accessExpiresAt) || accessExpiresAt <= now) {
            revokeApiDeviceSessionRow(row.id, "refresh_token_expired", now);
            failure = problem("Refresh token is invalid", "invalid_refresh_token", 401);
          } else {
          database.prepare("UPDATE api_refresh_tokens SET status='rotated',used_at=? WHERE token_hash=?")
            .run(now, tokenHash);
          database.prepare(`UPDATE api_device_sessions SET
            access_token_hash=?,access_expires_at=?,last_seen_at=?,rotated_at=?,ip_address=?,user_agent=?
            WHERE id=?`).run(
            hashToken(nextAccessToken, appSecret),
            accessExpiresAt,
            now,
            now,
            String(ipAddress || row.ip_address || "").slice(0, 80) || null,
            String(userAgent || row.user_agent || "").slice(0, 300) || null,
            row.id,
          );
          database.prepare(`INSERT INTO api_refresh_tokens
            (token_hash,session_id,status,expires_at,created_at)
            VALUES (?,?,'active',?,?)`).run(
            hashToken(nextRefreshToken, appSecret),
            row.id,
            row.refresh_expires_at,
            now,
          );
          result = {
            tokenType: "Bearer",
            accessToken: nextAccessToken,
            accessTokenExpiresAt: accessExpiresAt,
            refreshToken: nextRefreshToken,
            refreshTokenExpiresAt: row.refresh_expires_at,
            session: publicApiDeviceSession(
              database.prepare("SELECT * FROM api_device_sessions WHERE id=?").get(row.id),
              `mobile:${row.id}`,
            ),
          };
          }
        }
        database.exec("COMMIT");
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
      if (failure) throw failure;
      return result;
    },
    listApiDeviceSessions(userId, { currentIdHash = null } = {}) {
      expireApiDeviceSessions();
      return database.prepare(`SELECT * FROM api_device_sessions
        WHERE user_id=? AND revoked_at IS NULL AND refresh_expires_at>?
        ORDER BY last_seen_at DESC`).all(userId, Date.now())
        .map((row) => publicApiDeviceSession(row, currentIdHash));
    },
    revokeApiDeviceSession(userId, sessionId, reason = "user_revoked") {
      const normalized = String(sessionId || "").replace(/^mobile:/, "");
      const row = database.prepare("SELECT id FROM api_device_sessions WHERE id=? AND user_id=?").get(normalized, userId);
      return row ? revokeApiDeviceSessionRow(row.id, reason) : false;
    },

    createSession({ userId, ttlMs, ipAddress = null, userAgent = null, maxSessions = null }) {
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
      if (Number.isInteger(maxSessions) && maxSessions > 0) {
        database.prepare(`DELETE FROM sessions
          WHERE user_id=? AND id_hash NOT IN (
            SELECT id_hash FROM sessions WHERE user_id=? ORDER BY created_at DESC, rowid DESC LIMIT ?
          )`).run(userId, userId, maxSessions);
      }
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
      const browser = database.prepare("SELECT * FROM sessions WHERE user_id=? ORDER BY last_seen_at DESC")
        .all(userId).map((row) => publicSession(row, currentIdHash));
      const devices = this.listApiDeviceSessions(userId, { currentIdHash });
      return [...browser, ...devices].sort((left, right) => Number(right.lastSeenAt) - Number(left.lastSeenAt));
    },
    deleteUserSession(userId, idHash) {
      if (String(idHash || "").startsWith("mobile:")) {
        return this.revokeApiDeviceSession(userId, idHash, "user_revoked");
      }
      return database.prepare("DELETE FROM sessions WHERE user_id=? AND id_hash=?").run(userId, idHash).changes > 0;
    },
    deleteOtherSessions(userId, currentIdHash) {
      const mobileCurrent = String(currentIdHash || "").startsWith("mobile:")
        ? String(currentIdHash).slice("mobile:".length)
        : null;
      const browserChanges = mobileCurrent
        ? database.prepare("DELETE FROM sessions WHERE user_id=?").run(userId).changes
        : database.prepare("DELETE FROM sessions WHERE user_id=? AND id_hash<>?").run(userId, currentIdHash).changes;
      const mobileRows = mobileCurrent
        ? database.prepare("SELECT id FROM api_device_sessions WHERE user_id=? AND id<>? AND revoked_at IS NULL").all(userId, mobileCurrent)
        : database.prepare("SELECT id FROM api_device_sessions WHERE user_id=? AND revoked_at IS NULL").all(userId);
      for (const row of mobileRows) revokeApiDeviceSessionRow(row.id, "other_sessions_revoked");
      return browserChanges + mobileRows.length;
    },
    revokeUserSessions(userId) {
      const browserChanges = database.prepare("DELETE FROM sessions WHERE user_id=?").run(userId).changes;
      const mobileRows = database.prepare("SELECT id FROM api_device_sessions WHERE user_id=? AND revoked_at IS NULL").all(userId);
      for (const row of mobileRows) revokeApiDeviceSessionRow(row.id, "account_sessions_revoked");
      return browserChanges + mobileRows.length;
    },

    getSecurityPolicy() {
      return publicSecurityPolicy(database.prepare("SELECT * FROM security_policy WHERE id='default'").get());
    },
    updateSecurityPolicy(input = {}, updatedBy = null) {
      for (const field of ["requireAdminMfa", "requireCustomerMfa", "newLoginEmail"]) {
        if (input[field] !== undefined && typeof input[field] !== "boolean") {
          throw problem("Security policy values must be true or false", "invalid_security_policy");
        }
      }
      const current = this.getSecurityPolicy();
      const next = {
        requireAdminMfa: input.requireAdminMfa ?? current.requireAdminMfa,
        requireCustomerMfa: input.requireCustomerMfa ?? current.requireCustomerMfa,
        newLoginEmail: input.newLoginEmail ?? current.newLoginEmail,
      };
      database.prepare(`UPDATE security_policy SET
        require_admin_mfa=?,require_customer_mfa=?,new_login_email=?,updated_by=?,updated_at=?
        WHERE id='default'`).run(
        Number(next.requireAdminMfa),
        Number(next.requireCustomerMfa),
        Number(next.newLoginEmail),
        updatedBy,
        Date.now(),
      );
      return this.getSecurityPolicy();
    },
    isMfaRequiredForUser(user) {
      if (!user) return false;
      const policy = this.getSecurityPolicy();
      return user.role === "admin" ? policy.requireAdminMfa : policy.requireCustomerMfa;
    },
    listSecurityEvents({ limit = 100, offset = 0 } = {}) {
      const safeLimit = Math.min(200, Math.max(1, Number(limit) || 100));
      const safeOffset = Math.max(0, Number(offset) || 0);
      const predicate = `(a.action LIKE 'auth.%' OR a.action LIKE 'security.%' OR a.action LIKE 'password.%'
        OR a.action IN ('admin.user.password_reset','admin.user.mfa_reset','admin.security.policy_updated'))`;
      const rows = database.prepare(`SELECT a.*,u.display_name,u.email,u.role AS user_role,c.name AS customer_name
        FROM audit_logs a
        LEFT JOIN users u ON u.id=a.actor_user_id
        LEFT JOIN customers c ON c.id=a.customer_id
        WHERE ${predicate}
        ORDER BY a.created_at DESC LIMIT ? OFFSET ?`).all(safeLimit, safeOffset);
      const total = database.prepare(`SELECT COUNT(*) AS count FROM audit_logs a WHERE ${predicate}`).get().count;
      return {
        items: rows.map((row) => ({
          id: row.id,
          customerId: row.customer_id,
          customerName: row.customer_name,
          userId: row.actor_user_id,
          displayName: row.display_name,
          email: row.email,
          actorRole: row.actor_role,
          userRole: row.user_role,
          action: row.action,
          detail: parseJson(row.detail, {}),
          ipAddress: row.ip_address,
          createdAt: row.created_at,
        })),
        total,
        limit: safeLimit,
        offset: safeOffset,
      };
    },
    getSecurityCenter({ limit = 100 } = {}) {
      database.prepare("DELETE FROM sessions WHERE expires_at<=?").run(Date.now());
      expireApiDeviceSessions();
      const policy = this.getSecurityPolicy();
      const accounts = database.prepare(`SELECT
        COUNT(*) AS active_accounts,
        COALESCE(SUM(CASE WHEN u.role='admin' THEN 1 ELSE 0 END),0) AS admins,
        COALESCE(SUM(CASE WHEN u.role='customer' THEN 1 ELSE 0 END),0) AS customers,
        COALESCE(SUM(CASE WHEN m.enabled=1 THEN 1 ELSE 0 END),0) AS mfa_protected,
        COALESCE(SUM(CASE WHEN u.role='admin' AND m.enabled=1 THEN 1 ELSE 0 END),0) AS protected_admins,
        COALESCE(SUM(CASE WHEN u.role='customer' AND m.enabled=1 THEN 1 ELSE 0 END),0) AS protected_customers
        FROM users u LEFT JOIN user_mfa m ON m.user_id=u.id
        WHERE u.status='active'`).get();
      const since = Date.now() - 24 * 60 * 60 * 1000;
      const successfulLogins = database.prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE action IN ('auth.login','auth.api_login') AND created_at>=?").get(since).count;
      const failedLogins = database.prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE action IN ('auth.login_failed','auth.mfa_failed') AND created_at>=?").get(since).count;
      const activeAccounts = Number(accounts.active_accounts || 0);
      const mfaProtected = Number(accounts.mfa_protected || 0);
      const requiredPending =
        (policy.requireAdminMfa ? Number(accounts.admins || 0) - Number(accounts.protected_admins || 0) : 0)
        + (policy.requireCustomerMfa ? Number(accounts.customers || 0) - Number(accounts.protected_customers || 0) : 0);
      const browserSessions = Number(database.prepare("SELECT COUNT(*) AS count FROM sessions").get().count || 0);
      const apiDeviceSessions = Number(database.prepare(`SELECT COUNT(*) AS count FROM api_device_sessions
        WHERE revoked_at IS NULL AND refresh_expires_at>?`).get(Date.now()).count || 0);
      return {
        policy,
        summary: {
          activeAccounts,
          mfaProtected,
          mfaCoverage: activeAccounts ? Math.round(mfaProtected / activeAccounts * 100) : 100,
          requiredPending,
          activeSessions: browserSessions + apiDeviceSessions,
          browserSessions,
          apiDeviceSessions,
          successfulLogins24h: Number(successfulLogins || 0),
          failedLogins24h: Number(failedLogins || 0),
        },
        events: this.listSecurityEvents({ limit }),
      };
    },

    writeAudit({ customerId = null, userId = null, actorRole = "system", action, resourceId = null, detail = {}, ipAddress = null }) {
      database.prepare("INSERT INTO audit_logs (customer_id,actor_user_id,actor_role,action,resource_id,detail,ip_address,created_at) VALUES (?,?,?,?,?,?,?,?)")
        .run(customerId, userId, actorRole, action, resourceId, JSON.stringify(detail), ipAddress, Date.now());
    },
    listAudit(customerId = null, { limit = 30, offset = 0, all = false, customerVisible = false } = {}) {
      const safeLimit = Math.min(100, Math.max(1, Number(limit) || 30));
      const safeOffset = Math.max(0, Number(offset) || 0);
      const where = all
        ? ""
        : `WHERE a.customer_id=?${customerVisible ? " AND a.action!='admin.support.internal_note_added'" : ""}`;
      const params = all ? [safeLimit, safeOffset] : [customerId, safeLimit, safeOffset];
      const rows = database.prepare(`SELECT a.*,u.display_name,c.name AS customer_name FROM audit_logs a
        LEFT JOIN users u ON u.id=a.actor_user_id LEFT JOIN customers c ON c.id=a.customer_id
        ${where} ORDER BY a.created_at DESC LIMIT ? OFFSET ?`).all(...params);
      const total = all
        ? database.prepare("SELECT COUNT(*) AS count FROM audit_logs").get().count
        : database.prepare(`SELECT COUNT(*) AS count FROM audit_logs WHERE customer_id=?
          ${customerVisible ? "AND action!='admin.support.internal_note_added'" : ""}`).get(customerId).count;
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

    createConsoleSession({ userId, resourceId, ticket, port, consoleType = "graphical", consoleUser = null, ttlMs = 45_000 }) {
      const token = randomToken(24);
      const now = Date.now();
      const type = consoleType === "terminal" ? "terminal" : "graphical";
      database.prepare("DELETE FROM console_sessions WHERE expires_at<=? OR used_at IS NOT NULL").run(now);
      database.prepare("INSERT INTO console_sessions (id_hash,user_id,resource_id,ticket_encrypted,port,console_type,console_user,expires_at,created_at) VALUES (?,?,?,?,?,?,?,?,?)")
        .run(hashToken(token, appSecret), userId, resourceId, encryptSecret(ticket, appSecret), Number(port), type, consoleUser, now + ttlMs, now);
      return { token, expiresAt: now + ttlMs };
    },
    getConsoleSession(token, userId) {
      const row = database.prepare("SELECT cs.resource_id,cs.ticket_encrypted,cs.console_type,cs.console_user,cs.expires_at,r.cluster_id,r.node,r.type,r.vmid,r.name FROM console_sessions cs JOIN resources r ON r.id=cs.resource_id WHERE cs.id_hash=? AND cs.user_id=? AND cs.expires_at>? AND cs.used_at IS NULL")
        .get(hashToken(token, appSecret), userId, Date.now());
      return row ? {
        resourceId: row.resource_id, expiresAt: row.expires_at, clusterId: row.cluster_id,
        node: row.node, type: row.type, vmid: row.vmid, name: row.name,
        consoleType: row.console_type, consoleUser: row.console_user,
        password: decryptSecret(row.ticket_encrypted, appSecret),
      } : null;
    },
    getConsoleSessionByToken(token) {
      const row = database.prepare("SELECT cs.user_id,cs.resource_id,cs.ticket_encrypted,cs.console_type,cs.console_user,cs.expires_at,r.cluster_id,r.node,r.type,r.vmid,r.name FROM console_sessions cs JOIN resources r ON r.id=cs.resource_id WHERE cs.id_hash=? AND cs.expires_at>? AND cs.used_at IS NULL")
        .get(hashToken(token, appSecret), Date.now());
      return row ? {
        userId: row.user_id, resourceId: row.resource_id, expiresAt: row.expires_at, clusterId: row.cluster_id,
        node: row.node, type: row.type, vmid: row.vmid, name: row.name,
        consoleType: row.console_type, consoleUser: row.console_user,
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
