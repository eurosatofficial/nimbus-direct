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
  maintenanceEmailTemplate,
  passwordResetEmailTemplate,
  securityEmailTemplate,
  supportTicketEmailTemplate,
} from "./server/email.mjs";
import { createTotpEnrollment, generateRecoveryCodes, verifyTotp } from "./server/mfa.mjs";
import { createNotificationService } from "./server/notifications.mjs";
import { createPushService } from "./server/push.mjs";
import { nimbusOpenApi } from "./server/openapi.mjs";
import { ProxmoxRegistry } from "./server/proxmox-registry.mjs";
import { RateLimiter } from "./server/rate-limit.mjs";
import {
  ASSIGNMENT_PERMISSIONS,
  bootstrapStore,
  DEFAULT_PERMISSIONS,
  openStore,
} from "./server/store.mjs";
import { assertDemoReadOnlyStore, isDemoReadOnlyRequestAllowed } from "./server/demo-mode.mjs";
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
if (config.demoReadOnly) assertDemoReadOnlyStore(config, store);
const bootstrapped = await bootstrapStore(store, config.bootstrap);
const proxmox = new ProxmoxRegistry({
  getConnection: (clusterId) => store.getClusterConnection(clusterId),
  timeoutMs: config.proxmoxTimeoutMs,
});
const loginLimiter = new RateLimiter({ limit: 8, windowMs: 15 * 60 * 1000 });
const mfaLimiter = new RateLimiter({ limit: 8, windowMs: 10 * 60 * 1000 });
const apiRefreshLimiter = new RateLimiter({ limit: 30, windowMs: 10 * 60 * 1000 });
const securityActionLimiter = new RateLimiter({ limit: 10, windowMs: 15 * 60 * 1000 });
const forgotPasswordLimiter = new RateLimiter({ limit: 5, windowMs: 15 * 60 * 1000 });
const forgotAccountLimiter = new RateLimiter({ limit: 3, windowMs: 60 * 60 * 1000 });
const accountTokenLimiter = new RateLimiter({ limit: 12, windowMs: 15 * 60 * 1000 });
const invitationLimiter = new RateLimiter({ limit: 20, windowMs: 60 * 60 * 1000 });
const actionLimiter = new RateLimiter({ limit: 30, windowMs: 60 * 1000 });
const uploadLimiter = new RateLimiter({ limit: 5, windowMs: 60 * 60 * 1000 });
const emailConnectionTestLimiter = new RateLimiter({ limit: 12, windowMs: 5 * 60 * 1000 });
const emailMessageTestLimiter = new RateLimiter({ limit: 10, windowMs: 15 * 60 * 1000 });
const operationsRefreshLimiter = new RateLimiter({ limit: 6, windowMs: 5 * 60 * 1000 });
const maintenancePublishLimiter = new RateLimiter({ limit: 30, windowMs: 60 * 60 * 1000 });
const supportTicketCreateLimiter = new RateLimiter({ limit: 10, windowMs: 60 * 60 * 1000 });
const supportTicketMessageLimiter = new RateLimiter({ limit: 60, windowMs: 60 * 60 * 1000 });
const root = fileURLToPath(new URL("./public", import.meta.url));
const noVncRoot = fileURLToPath(new URL("./node_modules/@novnc/novnc", import.meta.url));
const xtermRoot = fileURLToPath(new URL("./node_modules/@xterm/xterm", import.meta.url));
const xtermFitRoot = fileURLToPath(new URL("./node_modules/@xterm/addon-fit", import.meta.url));
const headers = securityHeaders();
const cookieName = sessionCookieName(config.secureCookies);
const consoleCookieName = config.secureCookies ? "__Secure-nimbus_console" : "nimbus_console";

const demoResources = [
  { vmid: 101, type: "qemu", name: "atlas-web-01", node: "pve-ber-01", status: "running", vcpu: 4, memory: 8, memoryUsed: 3.8, storage: 80, storageUsed: 42, ip: "10.24.1.31", cpu: 38, uptime: 834223 },
  { vmid: 105, type: "qemu", name: "atlas-db-01", node: "pve-ber-02", status: "running", vcpu: 8, memory: 16, memoryUsed: 10.2, storage: 240, storageUsed: 121, ip: "10.24.1.35", cpu: 57, uptime: 733103 },
  { vmid: 203, type: "qemu", name: "nova-api-01", node: "pve-fra-01", status: "stopped", vcpu: 4, memory: 8, memoryUsed: 0, storage: 100, storageUsed: 61, ip: "10.31.2.18", cpu: 0, uptime: 0 },
  { vmid: 301, type: "lxc", name: "cache-edge-01", node: "pve-ber-03", status: "running", vcpu: 2, memory: 4, memoryUsed: 1.7, storage: 32, storageUsed: 12, ip: "10.24.3.44", cpu: 21, uptime: 338441 },
  { vmid: 302, type: "qemu", name: "worker-gpu-01", node: "pve-fra-02", status: "suspended", vcpu: 12, memory: 32, memoryUsed: 18.4, storage: 300, storageUsed: 201, ip: "10.31.2.55", cpu: 0, uptime: 129223 },
];
const demoOperations = {
  nodes: [
    { node: "pve-ber-01", status: "online", cpuPercent: 42, cpuCores: 16, memoryUsedBytes: 39 * 1024 ** 3, memoryTotalBytes: 64 * 1024 ** 3, memoryPercent: 60.9, rootUsedBytes: 46 * 1024 ** 3, rootTotalBytes: 96 * 1024 ** 3, rootPercent: 47.9, uptime: 2_592_000 },
    { node: "pve-ber-02", status: "online", cpuPercent: 31, cpuCores: 24, memoryUsedBytes: 71 * 1024 ** 3, memoryTotalBytes: 128 * 1024 ** 3, memoryPercent: 55.5, rootUsedBytes: 51 * 1024 ** 3, rootTotalBytes: 96 * 1024 ** 3, rootPercent: 53.1, uptime: 1_814_400 },
    { node: "pve-ber-03", status: "online", cpuPercent: 18, cpuCores: 12, memoryUsedBytes: 22 * 1024 ** 3, memoryTotalBytes: 64 * 1024 ** 3, memoryPercent: 34.4, rootUsedBytes: 33 * 1024 ** 3, rootTotalBytes: 96 * 1024 ** 3, rootPercent: 34.4, uptime: 950_400 },
    { node: "pve-fra-01", status: "online", cpuPercent: 27, cpuCores: 16, memoryUsedBytes: 44 * 1024 ** 3, memoryTotalBytes: 96 * 1024 ** 3, memoryPercent: 45.8, rootUsedBytes: 40 * 1024 ** 3, rootTotalBytes: 96 * 1024 ** 3, rootPercent: 41.7, uptime: 1_296_000 },
    { node: "pve-fra-02", status: "online", cpuPercent: 63, cpuCores: 32, memoryUsedBytes: 122 * 1024 ** 3, memoryTotalBytes: 192 * 1024 ** 3, memoryPercent: 63.5, rootUsedBytes: 58 * 1024 ** 3, rootTotalBytes: 128 * 1024 ** 3, rootPercent: 45.3, uptime: 691_200 },
  ],
  storages: [
    { node: "pve-ber-01", storageId: "local", status: "available", type: "dir", shared: false, content: ["iso", "vztmpl"], usedBytes: 54 * 1024 ** 3, totalBytes: 180 * 1024 ** 3, availableBytes: 126 * 1024 ** 3, usagePercent: 30 },
    { node: "pve-ber-01", storageId: "ceph-vm", status: "available", type: "rbd", shared: true, content: ["images", "rootdir"], usedBytes: 5.4 * 1024 ** 4, totalBytes: 12 * 1024 ** 4, availableBytes: 6.6 * 1024 ** 4, usagePercent: 45 },
    { node: "pve-fra-01", storageId: "fra-zfs", status: "available", type: "zfspool", shared: false, content: ["images", "rootdir"], usedBytes: 2.1 * 1024 ** 4, totalBytes: 4 * 1024 ** 4, availableBytes: 1.9 * 1024 ** 4, usagePercent: 52.5 },
  ],
};
const demoSnapshots = new Map();

if (config.allowDemoData && !store.listClusters().length) {
  store.createCluster({ id: "demo-eu", name: "Nimbus Demo EU", apiUrl: "https://demo.invalid:8006", tokenId: "demo@pve!panel", tokenSecret: "demo-secret-never-used" });
  store.syncResources("demo-eu", demoResources);
  store.saveOperationsSnapshot("demo-eu", { ...demoOperations, collectedAt: Date.now() });
  const customer = store.listCustomers()[0];
  if (customer) {
    for (const resource of store.listResources({ clusterId: "demo-eu" }).slice(0, 3)) {
      store.assignResource({ customerId: customer.id, resourceId: resource.id, permissions: DEFAULT_PERMISSIONS });
    }
  }
}
assertDemoReadOnlyStore(config, store);
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
const push = createPushService({ store, config: config.apns, log });
const notifications = createNotificationService({ store, email, push, log });

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

function securityUser(user) {
  if (!user) return user;
  const mfaEnabled = Boolean(user.mfaEnabled ?? user.mfa_enabled);
  return {
    ...user,
    mfaEnrollmentRequired: store.isMfaRequiredForUser(user) && !mfaEnabled,
  };
}

function bearerToken(request) {
  const authorization = String(request.headers.authorization || "");
  const match = authorization.match(/^Bearer ([A-Za-z0-9_-]{20,260})$/);
  return match?.[1] || null;
}

function currentSession(request) {
  const hasAuthorization = Boolean(request.headers.authorization);
  const accessToken = bearerToken(request);
  const session = hasAuthorization
    ? (accessToken
        ? (accessToken.startsWith("nmb_key_")
            ? store.getIntegrationApiSession(accessToken, { ipAddress: clientIp(request) })
            : store.getApiAccessSession(accessToken))
        : null)
    : store.getSession(parseCookies(request.headers.cookie)[cookieName]);
  if (session && !session.authType) session.authType = "browser";
  if (session) session.user = securityUser(session.user);
  return session;
}

function consoleCookie(value, maxAge) {
  const attributes = [
    `${consoleCookieName}=${encodeURIComponent(value)}`,
    "Path=/api/v1/console",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${Math.max(0, Math.floor(maxAge / 1000))}`,
  ];
  if (config.secureCookies) attributes.push("Secure");
  return attributes.join("; ");
}

function nativeConsoleContext(request, token) {
  const cookieToken = parseCookies(request.headers.cookie)[consoleCookieName];
  if (!cookieToken || !safeEqual(cookieToken, token)) return null;
  const pending = store.getConsoleSessionByToken(token);
  const user = pending ? store.getUser(pending.userId) : null;
  if (!pending || !user || user.status !== "active"
    || !resourceFor(user, pending.resourceId, "console")) return null;
  return { pending, user };
}

function sendConsoleSession(response, token, consoleSession) {
  sendJson(response, 200, {
    resource: {
      name: consoleSession.name,
      node: consoleSession.node,
      type: consoleSession.type,
      vmid: consoleSession.vmid,
    },
    expiresAt: consoleSession.expiresAt,
    demo: config.allowDemoData && consoleSession.clusterId === "demo-eu",
    console: {
      type: consoleSession.consoleType || "graphical",
      label: consoleSession.consoleType === "terminal" ? "Terminal console" : "Graphical console",
    },
    websocketUrl: `/api/v1/console/ws/${encodeURIComponent(token)}`,
    credentials: { password: consoleSession.password, user: consoleSession.consoleUser || null },
  });
}

function routeNativeConsole(request, response, pathname) {
  let match = pathname.match(/^\/api\/v1\/console\/native-launch\/([^/]+)$/);
  if (match && request.method === "GET") {
    const token = decodeURIComponent(match[1]);
    const pending = store.getConsoleSessionByToken(token);
    const user = pending ? store.getUser(pending.userId) : null;
    if (!pending || !user || user.status !== "active"
      || !resourceFor(user, pending.resourceId, "console")) {
      sendJson(response, 404, { error: "console_session_not_found" });
      return true;
    }
    response.writeHead(303, {
      ...headers,
      "cache-control": "no-store",
      location: `/console.html?token=${encodeURIComponent(token)}`,
      "set-cookie": consoleCookie(token, pending.expiresAt - Date.now()),
    });
    response.end();
    return true;
  }

  match = pathname.match(/^\/api\/v1\/console\/session\/([^/]+)$/);
  if (match && request.method === "GET") {
    const token = decodeURIComponent(match[1]);
    const context = nativeConsoleContext(request, token);
    if (!context) return false;
    sendConsoleSession(response, token, context.pending);
    return true;
  }
  return false;
}

function requireSession(request, response) {
  const session = currentSession(request);
  if (!session) sendJson(response, 401, { error: "authentication_required" });
  return session;
}

function requireCsrf(request, response, session) {
  if (session.authType !== "browser") return true;
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

function apiKeyHasGroup(session, group) {
  return session?.authType !== "api_key" || session.apiKeyGroups?.includes(group);
}

function apiKeyHasResource(session, resourceId) {
  return session?.authType !== "api_key" || session.apiKeyResourceIds?.includes(resourceId);
}

function filterApiKeyResources(session, resources) {
  return session?.authType === "api_key"
    ? resources.filter((resource) => apiKeyHasResource(session, resource.id))
    : resources;
}

function authorizeIntegrationKeyRequest(request, response, pathname, session) {
  if (session?.authType !== "api_key") return true;
  const method = String(request.method || "GET").toUpperCase();
  const deny = (error = "api_key_scope_denied") => {
    sendJson(response, 403, { error });
    return false;
  };
  if (pathname.startsWith("/api/v1/auth/")
    || pathname.startsWith("/api/v1/security/")
    || pathname.startsWith("/api/v1/api-keys")
    || pathname === "/api/v1/me"
    || pathname === "/api/v1/dashboard"
    || pathname === "/api/v1/profile"
    || pathname === "/api/v1/password") return deny("api_key_route_forbidden");

  const adminPath = pathname.replace(/^\/api\/v1\/admin/, "/api/admin");
  if (adminPath.startsWith("/api/admin/")) {
    if (session.user.role !== "admin") return deny("admin_required");
    if (/^\/api\/admin\/users\/[^/]+\/(?:api-access|api-keys)/.test(adminPath)) return deny("api_key_route_forbidden");
    const required = adminPath === "/api/admin/state"
      ? null
      : adminPath.startsWith("/api/admin/customers") ? "admin_customers"
        : adminPath.startsWith("/api/admin/users") || adminPath === "/api/admin/invitations" ? "admin_users"
          : adminPath.startsWith("/api/admin/clusters") ? "admin_clusters"
            : adminPath.startsWith("/api/admin/assignments") || /^\/api\/admin\/resources\/.+\/assignment$/.test(adminPath) ? "admin_assignments"
              : adminPath.startsWith("/api/admin/operations") ? "admin_operations"
                : adminPath.startsWith("/api/admin/maintenance-events") ? "admin_maintenance"
                  : adminPath.startsWith("/api/admin/email") ? "admin_email"
                    : adminPath.startsWith("/api/admin/security") ? "admin_security"
                      : adminPath.startsWith("/api/admin/iso-policies") ? "admin_iso_policies"
                        : null;
    if (adminPath === "/api/admin/state") {
      return session.apiKeyGroups.some((group) => group.startsWith("admin_")) || deny();
    }
    return required ? (apiKeyHasGroup(session, required) || deny()) : deny("api_key_route_forbidden");
  }

  let required = null;
  if (pathname === "/api/v1/resources" || pathname === "/api/v1/network"
    || pathname === "/api/v1/tasks" || /^\/api\/v1\/tasks\/[^/]+$/.test(pathname)) required = "server_overview";
  else if (/^\/api\/v1\/console\/session\/[^/]+$/.test(pathname)) required = "console_access";
  else if (pathname.startsWith("/api/v1/notifications")) required = "notifications";
  else if (pathname.startsWith("/api/v1/maintenance")) required = "maintenance_information";
  else if (pathname.startsWith("/api/v1/support/")) required = session.user.role === "admin" ? "admin_support" : "support_tickets";
  else {
    const resourceMatch = pathname.match(/^\/api\/v1\/resources\/(.+?)(?:\/(network|history|actions|console|snapshots|media|config)(?:\/.*)?)?$/);
    if (resourceMatch) {
      const resourceId = decodeURIComponent(resourceMatch[1]);
      if (!apiKeyHasResource(session, resourceId)) return deny("api_key_resource_denied");
      const section = resourceMatch[2] || "details";
      required = section === "actions" ? "power_management"
        : section === "console" ? "console_access"
          : section === "snapshots" ? "snapshot_management"
            : section === "media" ? "installation_media"
              : section === "config" ? null
                : "server_overview";
      if (section === "config") return deny("api_key_route_forbidden");
    }
  }
  if (!required) return deny("api_key_route_forbidden");
  return apiKeyHasGroup(session, required) || deny();
}

function requireAdmin(response, session) {
  if (session.user.role !== "admin") {
    sendJson(response, 403, { error: "admin_required" });
    return false;
  }
  return true;
}

function audit(request, session, action, { customerId = session.user.customerId, resourceId = null, detail = {} } = {}) {
  if (config.demoReadOnly) return;
  store.writeAudit({
    customerId,
    userId: session.user.id,
    actorRole: session.user.role,
    action,
    resourceId,
    detail: session.authType === "api_key"
      ? { ...detail, apiKeyId: session.apiKeyId, apiKeyName: session.apiKeyName }
      : detail,
    ipAddress: clientIp(request),
  });
}

function demoSafeEventPage(page) {
  if (!config.demoReadOnly) return page;
  return {
    ...page,
    items: (page?.items || []).map((entry) => ({ ...entry, ipAddress: null })),
  };
}

function demoSafeSecurityCenter(center) {
  if (!config.demoReadOnly) return center;
  return { ...center, events: demoSafeEventPage(center.events) };
}

function createLoginSession(request, userId) {
  return store.createSession({
    userId,
    ttlMs: config.sessionTtlMs,
    ipAddress: clientIp(request),
    userAgent: request.headers["user-agent"],
    maxSessions: config.demoReadOnly ? 200 : null,
  });
}

function createApiLoginSession(request, userId, input = {}) {
  return store.createApiDeviceSession({
    userId,
    accessTtlMs: config.apiAccessTokenTtlMs,
    refreshTtlMs: config.apiRefreshTokenTtlMs,
    deviceName: input.deviceName,
    platform: input.platform,
    appVersion: input.appVersion,
    ipAddress: clientIp(request),
    userAgent: request.headers["user-agent"],
    maxSessions: config.demoReadOnly ? 200 : config.apiMaxDeviceSessions,
  });
}

function sendAuthenticated(response, session) {
  const activeSession = store.getSession(session.token);
  sendJson(response, 200, {
    user: securityUser(activeSession.user),
    csrfToken: session.csrfToken,
    expiresAt: session.expiresAt,
    demoReadOnly: config.demoReadOnly,
  }, {
    "set-cookie": sessionCookie(session.token, {
      secure: config.secureCookies,
      maxAge: config.sessionTtlMs,
      name: cookieName,
    }),
  });
}

function sendApiAuthenticated(response, tokenSession) {
  const activeSession = store.getApiAccessSession(tokenSession.accessToken);
  sendJson(response, 200, {
    ...tokenSession,
    apiVersion: "v1",
    user: securityUser(activeSession?.user),
    demoReadOnly: config.demoReadOnly,
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

function queueNewLoginNotice(user, request) {
  if (!store.getSecurityPolicy().newLoginEmail) return;
  queueSecurityNotice(user, {
    title: "New sign-in to your account",
    message: "A successful sign-in to your Nimbus Direct account was completed.",
    ipAddress: clientIp(request),
  });
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

function maintenancePanelUrl() {
  const value = store.getEmailSettings().appUrl;
  if (!value) return "";
  const url = new URL(value);
  url.hash = "maintenance";
  return url.toString();
}

function queueMaintenanceEmails({ event, deliveries }, { resolution = false, createdBy = null } = {}) {
  const settings = store.getEmailSettings();
  if (!event.notifyEmail || !settings.enabled || !deliveries?.length) return 0;
  let queued = 0;
  for (const delivery of deliveries) {
    const eligible = delivery.emailEnabled
      && (resolution ? delivery.resolutionAlerts : delivery.infrastructureAlerts);
    if (!eligible || !delivery.email) continue;
    try {
      const content = maintenanceEmailTemplate({
        displayName: delivery.displayName,
        event,
        appUrl: maintenancePanelUrl(),
      });
      const job = store.queueEmail({
        to: delivery.email,
        ...content,
        category: resolution ? "maintenance_resolution" : "maintenance_notice",
        createdBy,
        maxAttempts: 4,
      });
      store.setMaintenanceEmailJob(delivery.deliveryId, job.id, { resolution });
      queued += 1;
    } catch (error) {
      log("error", "maintenance_email_queue_failed", {
        eventId: event.id,
        userId: delivery.id,
        error: error.code || error.message,
      });
    }
  }
  if (queued) void email.processDue();
  return queued;
}

function supportPanelUrl(ticketId) {
  const value = store.getEmailSettings().appUrl;
  if (!value) return "";
  const url = new URL(value);
  url.hash = `support/${encodeURIComponent(ticketId)}`;
  return url.toString();
}

function queueSupportEmails({
  ticket,
  message,
  actor,
  audience,
  eventType = "reply",
  createdBy = null,
}) {
  const settings = store.getEmailSettings();
  if (!settings.enabled || !ticket || !message) return 0;
  const recipients = store.listSupportTicketRecipients(ticket.id, audience);
  let queued = 0;
  for (const recipient of recipients) {
    if (!recipient.email || recipient.id === actor?.id) continue;
    try {
      const content = supportTicketEmailTemplate({
        displayName: recipient.displayName,
        ticket,
        message,
        actorName: actor?.displayName || "Nimbus Direct support",
        eventType,
        appUrl: supportPanelUrl(ticket.id),
      });
      store.queueEmail({
        to: recipient.email,
        ...content,
        category: eventType === "created" ? "support_ticket_created" : "support_ticket_update",
        createdBy,
        maxAttempts: 4,
      });
      queued += 1;
    } catch (error) {
      log("error", "support_email_queue_failed", {
        ticketId: ticket.id,
        userId: recipient.id,
        error: error.code || error.message,
      });
    }
  }
  if (queued) void email.processDue();
  return queued;
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
  if (user.role === "admin") {
    const resource = store.getResource(resourceId);
    return resource && !resource.stale
      ? { ...resource, permissions: [...ASSIGNMENT_PERMISSIONS] }
      : null;
  }
  return store.authorizeResource(user.customerId, resourceId, permission);
}

function resourcesFor(user) {
  if (user.role === "admin") {
    return store.listResources().map((resource) => ({
      ...resource,
      permissions: [...ASSIGNMENT_PERMISSIONS],
    }));
  }
  return store.listResources({ customerId: user.customerId })
    .filter((resource) => resource.permissions.includes("view_status"));
}

function requireResource(response, user, resourceId, permission) {
  const resource = resourceFor(user, resourceId, permission);
  if (!resource) {
    sendJson(response, 404, { error: "resource_not_found" });
    return null;
  }
  if (!enforceMaintenanceAction(response, user, resource, permission)) return null;
  return resource;
}

function enforceMaintenanceAction(response, user, resource, permission) {
  if (user.role === "admin") return true;
  const lock = store.getMaintenanceActionLock(user.id, resource, permission);
  if (!lock) return true;
  store.writeAudit({
    customerId: user.customerId,
    userId: user.id,
    actorRole: user.role,
    action: "resource.action_blocked_by_maintenance",
    resourceId: resource.id,
    detail: {
      requestedPermission: permission,
      maintenanceId: lock.eventId,
      lockGroup: lock.group.id,
    },
  });
  sendJson(response, 423, { error: "maintenance_action_locked", lock });
  return false;
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
    store.saveOperationsSnapshot(clusterId, { ...demoOperations, collectedAt: Date.now() });
    await refreshClusterTasks(clusterId);
    store.reconcileOperations(clusterId, {
      staleAfterMs: Math.max(config.syncIntervalMs * 3, 5 * 60_000),
    });
    try { await notifications.evaluateResourceAlerts({ clusterId }); }
    catch (error) { log("error", "alert_evaluation_failed", { clusterId, error: error.code || error.message }); }
    return synced;
  }
  try {
    const client = proxmox.forCluster(clusterId);
    const [resources, operations] = await Promise.all([
      client.listVirtualMachines(),
      client.getOperationsMetrics(),
    ]);
    const synced = store.syncResources(clusterId, resources);
    store.saveOperationsSnapshot(clusterId, operations);
    await refreshClusterTasks(clusterId);
    store.reconcileOperations(clusterId, {
      staleAfterMs: Math.max(config.syncIntervalMs * 3, 5 * 60_000),
    });
    try { await notifications.evaluateResourceAlerts({ clusterId }); }
    catch (error) { log("error", "alert_evaluation_failed", { clusterId, error: error.code || error.message }); }
    return synced;
  } catch (error) {
    store.setClusterSync(clusterId, { error: error.code || "proxmox_sync_failed" });
    store.reconcileOperations(clusterId, {
      staleAfterMs: Math.max(config.syncIntervalMs * 3, 5 * 60_000),
    });
    throw error;
  }
}

async function syncAllClusters() {
  const results = [];
  for (const cluster of store.listClusters().filter((entry) => entry.status !== "disabled")) {
    try {
      await syncCluster(cluster.id);
      results.push({ clusterId: cluster.id, success: true });
    } catch (error) {
      results.push({ clusterId: cluster.id, success: false, error: error.code || "proxmox_sync_failed" });
      log("error", "cluster_sync_failed", { clusterId: cluster.id, error: error.code || error.message });
    }
  }
  return results;
}

function reconcileAllOperations() {
  if (config.demoReadOnly) return;
  for (const cluster of store.listClusters()) {
    store.reconcileOperations(cluster.id, {
      staleAfterMs: Math.max(config.syncIntervalMs * 3, 5 * 60_000),
    });
  }
}

async function routeAuth(request, response, pathname) {
  if (pathname === "/api/auth/session" && request.method === "GET") {
    const session = currentSession(request);
    if (!session) {
      sendJson(response, 401, { error: "authentication_required", demoReadOnly: config.demoReadOnly });
      return true;
    }
    sendJson(response, 200, {
      user: session.user,
      csrfToken: session.csrfToken,
      expiresAt: session.expiresAt,
      demoReadOnly: config.demoReadOnly,
    });
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
      if (!config.demoReadOnly) {
        store.writeAudit({
          customerId: user?.customer_id || null,
          userId: user?.id || null,
          actorRole: user?.role || "system",
          action: "auth.login_failed",
          detail: { stage: "password" },
          ipAddress: ip,
        });
      }
      sendJson(response, 401, { error: "invalid_credentials" }); return true;
    }
    loginLimiter.clear(ip);
    if (user.mfa_enabled) {
      const challenge = store.createMfaChallenge({ userId: user.id });
      if (!config.demoReadOnly) {
        store.writeAudit({
          customerId: user.customer_id,
          userId: user.id,
          actorRole: user.role,
          action: "auth.mfa_challenge",
          ipAddress: ip,
        });
      }
      sendJson(response, 202, {
        mfaRequired: true,
        challengeToken: challenge.token,
        expiresAt: challenge.expiresAt,
      });
      return true;
    }
    const session = createLoginSession(request, user.id);
    if (!config.demoReadOnly) {
      store.writeAudit({ customerId: user.customer_id, userId: user.id, actorRole: user.role, action: "auth.login", ipAddress: ip });
      queueNewLoginNotice(user, request);
    }
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
      if (!config.demoReadOnly) {
        store.writeAudit({
          customerId: user.customer_id,
          userId: user.id,
          actorRole: user.role,
          action: "auth.mfa_failed",
          ipAddress: ip,
        });
      }
      sendJson(response, 401, { error: "invalid_mfa_code" });
      return true;
    }
    if (!store.consumeMfaChallenge(challengeToken)) {
      sendJson(response, 401, { error: "invalid_mfa_challenge" });
      return true;
    }
    mfaLimiter.clear(ip);
    const session = createLoginSession(request, user.id);
    if (!config.demoReadOnly) {
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
      queueNewLoginNotice(user, request);
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
    if (session.authType === "bearer") {
      audit(request, session, "auth.api_logout", {
        detail: { deviceSessionId: session.mobileSessionId, compatibilityRoute: true },
      });
      store.revokeApiDeviceSession(session.user.id, session.mobileSessionId, "logout");
      sendJson(response, 204, null);
      return true;
    }
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
  if (session.user.mfaEnrollmentRequired) {
    sendJson(response, 403, { error: "mfa_enrollment_required" });
    return true;
  }
  if (request.method !== "GET" && !requireCsrf(request, response, session)) return true;

  if (pathname === "/api/admin/state" && request.method === "GET") {
    reconcileAllOperations();
    const state = {
      mode: config.demoReadOnly ? "demo_read_only" : config.allowDemoData ? "demo" : "live",
      demoReadOnly: config.demoReadOnly,
      clusters: store.listClusters(), nodes: store.listProxmoxNodes(), customers: store.listCustomers(), users: store.listUsers(),
      resources: store.listResources(), isoPolicies: store.listIsoPolicies(),
      apiPolicies: store.listUserApiPolicies(),
      emailSettings: store.getEmailSettings(), emailJobs: store.listEmailJobs({ limit: 30 }),
      notificationEvents: store.listNotificationEvents({ limit: 50 }),
      maintenanceEvents: store.listMaintenanceEvents({ limit: 100 }),
      operations: store.getOperationsCenter(),
      security: demoSafeSecurityCenter(store.getSecurityCenter({ limit: 100 })),
      audit: demoSafeEventPage(store.listAudit(null, { all: true, limit: 50 })),
    };
    if (session.authType === "api_key") {
      const has = (group) => apiKeyHasGroup(session, group);
      if (!has("admin_clusters")) { state.clusters = []; state.nodes = []; }
      if (!has("admin_customers")) state.customers = [];
      if (!has("admin_users")) { state.users = []; state.apiPolicies = []; }
      if (!has("admin_assignments") && !has("admin_operations") && !has("admin_clusters")) state.resources = [];
      if (!has("admin_iso_policies")) state.isoPolicies = [];
      if (!has("admin_email")) { state.emailSettings = {}; state.emailJobs = []; }
      if (!has("admin_operations")) { state.notificationEvents = []; state.operations = {}; }
      if (!has("admin_maintenance")) state.maintenanceEvents = [];
      if (!has("admin_security")) state.security = {};
      if (!has("admin_audit")) state.audit = { items: [], total: 0, limit: 0, offset: 0 };
    }
    sendJson(response, 200, state);
    return true;
  }
  if (pathname === "/api/admin/security/policy" && request.method === "PATCH") {
    if (!requireSecurityActionRate(request, response, session.user.id)) return true;
    const policy = store.updateSecurityPolicy(await readBody(request), session.user.id);
    audit(request, session, "admin.security.policy_updated", { detail: policy });
    sendJson(response, 200, { policy, security: store.getSecurityCenter({ limit: 100 }) });
    return true;
  }
  if (pathname === "/api/admin/maintenance-events" && request.method === "POST") {
    const input = await readBody(request);
    const shouldPublish = input.publication !== "draft";
    if (shouldPublish) {
      const limit = maintenancePublishLimiter.consume(`${session.user.id}:${clientIp(request)}`);
      if (!limit.allowed) {
        sendJson(response, 429, { error: "maintenance_publish_rate_limited" }, { "retry-after": String(limit.retryAfter) });
        return true;
      }
    }
    const event = store.createMaintenanceEvent(input, { userId: session.user.id });
    let published = null;
    let queuedEmails = 0;
    if (shouldPublish) {
      published = store.publishMaintenanceEvent(event.id, { userId: session.user.id });
      queuedEmails = queueMaintenanceEmails(published, { createdBy: session.user.id });
    }
    const result = published?.event || event;
    audit(request, session, published ? "admin.maintenance.published" : "admin.maintenance.draft_created", {
      detail: {
        maintenanceId: result.id,
        kind: result.kind,
        severity: result.severity,
        status: result.status,
        recipientCount: result.recipientCount,
        lockGroups: result.lockGroups.map((group) => group.id),
        queuedEmails,
      },
    });
    sendJson(response, 201, { event: result, queuedEmails });
    return true;
  }
  let maintenanceMatch = pathname.match(/^\/api\/admin\/maintenance-events\/([^/]+)$/);
  if (maintenanceMatch && request.method === "PATCH") {
    const event = store.updateMaintenanceEvent(
      decodeURIComponent(maintenanceMatch[1]),
      await readBody(request),
      { userId: session.user.id },
    );
    audit(request, session, "admin.maintenance.draft_updated", {
      detail: {
        maintenanceId: event.id,
        kind: event.kind,
        severity: event.severity,
        lockGroups: event.lockGroups.map((group) => group.id),
      },
    });
    sendJson(response, 200, { event });
    return true;
  }
  if (maintenanceMatch && request.method === "DELETE") {
    const id = decodeURIComponent(maintenanceMatch[1]);
    store.deleteMaintenanceEvent(id);
    audit(request, session, "admin.maintenance.draft_deleted", { detail: { maintenanceId: id } });
    sendJson(response, 204, null);
    return true;
  }
  maintenanceMatch = pathname.match(/^\/api\/admin\/maintenance-events\/([^/]+)\/(publish|resolve|cancel)$/);
  if (maintenanceMatch && request.method === "POST") {
    const id = decodeURIComponent(maintenanceMatch[1]);
    const operation = maintenanceMatch[2];
    let event;
    let queuedEmails = 0;
    if (operation === "publish") {
      const limit = maintenancePublishLimiter.consume(`${session.user.id}:${clientIp(request)}`);
      if (!limit.allowed) {
        sendJson(response, 429, { error: "maintenance_publish_rate_limited" }, { "retry-after": String(limit.retryAfter) });
        return true;
      }
      const result = store.publishMaintenanceEvent(id, { userId: session.user.id });
      event = result.event;
      queuedEmails = queueMaintenanceEmails(result, { createdBy: session.user.id });
    } else if (operation === "resolve") {
      const result = store.resolveMaintenanceEvent(id, { userId: session.user.id });
      event = result.event;
      queuedEmails = queueMaintenanceEmails(result, { resolution: true, createdBy: session.user.id });
    } else {
      event = store.cancelMaintenanceEvent(id, { userId: session.user.id });
    }
    const auditAction = {
      publish: "admin.maintenance.published",
      resolve: "admin.maintenance.resolved",
      cancel: "admin.maintenance.cancelled",
    }[operation];
    audit(request, session, auditAction, {
      detail: {
        maintenanceId: event.id,
        kind: event.kind,
        status: event.status,
        recipientCount: event.recipientCount,
        lockGroups: event.lockGroups.map((group) => group.id),
        queuedEmails,
      },
    });
    sendJson(response, 200, { event, queuedEmails });
    return true;
  }
  if (pathname === "/api/admin/operations" && request.method === "GET") {
    reconcileAllOperations();
    sendJson(response, 200, { operations: store.getOperationsCenter() });
    return true;
  }
  if (pathname === "/api/admin/operations/refresh" && request.method === "POST") {
    const limit = operationsRefreshLimiter.consume(`${session.user.id}:${clientIp(request)}`);
    if (!limit.allowed) {
      sendJson(response, 429, { error: "operations_refresh_rate_limited" }, { "retry-after": String(limit.retryAfter) });
      return true;
    }
    const results = await syncAllClusters();
    reconcileAllOperations();
    const succeeded = results.filter((result) => result.success).length;
    audit(request, session, "admin.operations.refreshed", {
      detail: { clusters: results.length, succeeded, failed: results.length - succeeded },
    });
    sendJson(response, 200, { results, operations: store.getOperationsCenter() });
    return true;
  }
  const operationsIncidentMatch = pathname.match(/^\/api\/admin\/operations\/incidents\/([^/]+)\/acknowledge$/);
  if (operationsIncidentMatch && request.method === "POST") {
    const incident = store.acknowledgeOperationsIncident(
      decodeURIComponent(operationsIncidentMatch[1]),
      session.user.id,
    );
    audit(request, session, "admin.operations.incident_acknowledged", {
      detail: {
        incidentId: incident.id,
        clusterId: incident.clusterId,
        incidentType: incident.type,
        severity: incident.severity,
      },
    });
    sendJson(response, 200, { incident });
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
  match = pathname.match(/^\/api\/admin\/users\/([^/]+)\/api-access$/);
  if (match && request.method === "GET") {
    const targetUserId = decodeURIComponent(match[1]);
    sendJson(response, 200, store.getUserApiKeyCenter(targetUserId, { includeAllVisible: true }));
    return true;
  }
  if (match && request.method === "PATCH") {
    if (!requireSecurityActionRate(request, response, session.user.id)) return true;
    const targetUserId = decodeURIComponent(match[1]);
    const policy = store.updateUserApiPolicy(targetUserId, await readBody(request), session.user.id);
    audit(request, session, "admin.user.api_policy_updated", {
      detail: {
        targetUserId,
        enabled: policy.enabled,
        groups: policy.groups,
        resourceIds: policy.resourceIds,
        allVisibleResources: policy.allVisibleResources,
        maxActiveKeys: policy.maxActiveKeys,
        maxLifetimeDays: policy.maxLifetimeDays,
        allowNoExpiry: policy.allowNoExpiry,
      },
    });
    sendJson(response, 200, { policy, center: store.getUserApiKeyCenter(targetUserId, { includeAllVisible: true }) });
    return true;
  }
  match = pathname.match(/^\/api\/admin\/users\/([^/]+)\/api-keys\/([^/]+)$/);
  if (match && request.method === "DELETE") {
    if (!requireSecurityActionRate(request, response, session.user.id)) return true;
    const targetUserId = decodeURIComponent(match[1]);
    const keyId = decodeURIComponent(match[2]);
    if (!store.revokeUserApiKey(targetUserId, keyId, { revokedBy: session.user.id, reason: "admin_revoked" })) {
      sendJson(response, 404, { error: "api_key_not_found" });
      return true;
    }
    audit(request, session, "admin.user.api_key_revoked", { detail: { targetUserId, keyId } });
    sendJson(response, 204, null);
    return true;
  }
  match = pathname.match(/^\/api\/admin\/users\/([^/]+)\/api-keys\/revoke-all$/);
  if (match && request.method === "POST") {
    if (!requireSecurityActionRate(request, response, session.user.id)) return true;
    const targetUserId = decodeURIComponent(match[1]);
    const revoked = store.revokeAllUserApiKeys(targetUserId, { revokedBy: session.user.id });
    audit(request, session, "admin.user.api_keys_revoked", { detail: { targetUserId, revoked } });
    sendJson(response, 200, { revoked });
    return true;
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
    const targetUserId = decodeURIComponent(match[1]);
    const target = store.getUserForAuth(targetUserId);
    if (!target) { sendJson(response, 404, { error: "user_not_found" }); return true; }
    await store.updatePassword(targetUserId, (await readBody(request)).password);
    audit(request, session, "admin.user.password_reset", { customerId: target.customer_id, detail: { targetUserId } });
    queueSecurityNotice(target, {
      title: "Your password was reset",
      message: "An administrator reset your Nimbus Direct password and signed out every active session. Contact your infrastructure provider if this was unexpected.",
      ipAddress: clientIp(request),
    });
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

async function routeApiAuth(request, response, pathname) {
  if (pathname === "/api/v1/auth/token" && request.method === "POST") {
    const ip = clientIp(request);
    const limit = loginLimiter.consume(ip);
    if (!limit.allowed) {
      sendJson(response, 429, { error: "too_many_attempts" }, { "retry-after": String(limit.retryAfter) });
      return true;
    }
    const input = await readBody(request);
    const user = store.findUserForLogin(input.email);
    if (!user || user.status !== "active" || !user.password_set
      || (user.role === "customer" && user.customer_status !== "active")
      || !(await verifyPassword(String(input.password || ""), user.password_hash))) {
      if (!config.demoReadOnly) {
        store.writeAudit({
          customerId: user?.customer_id || null,
          userId: user?.id || null,
          actorRole: user?.role || "system",
          action: "auth.login_failed",
          detail: { stage: "password", client: "api" },
          ipAddress: ip,
        });
      }
      sendJson(response, 401, { error: "invalid_credentials" });
      return true;
    }
    loginLimiter.clear(ip);
    if (user.mfa_enabled) {
      const challenge = store.createMfaChallenge({ userId: user.id });
      if (!config.demoReadOnly) {
        store.writeAudit({
          customerId: user.customer_id,
          userId: user.id,
          actorRole: user.role,
          action: "auth.mfa_challenge",
          detail: { client: "api" },
          ipAddress: ip,
        });
      }
      sendJson(response, 202, {
        mfaRequired: true,
        challengeToken: challenge.token,
        expiresAt: challenge.expiresAt,
      });
      return true;
    }
    const tokenSession = createApiLoginSession(request, user.id, input);
    if (!config.demoReadOnly) {
      store.writeAudit({
        customerId: user.customer_id,
        userId: user.id,
        actorRole: user.role,
        action: "auth.api_login",
        detail: { deviceName: tokenSession.session.deviceName, platform: tokenSession.session.platform },
        ipAddress: ip,
      });
      queueNewLoginNotice(user, request);
    }
    sendApiAuthenticated(response, tokenSession);
    return true;
  }

  if (pathname === "/api/v1/auth/mfa" && request.method === "POST") {
    const ip = clientIp(request);
    const limit = mfaLimiter.consume(ip);
    if (!limit.allowed) {
      sendJson(response, 429, { error: "too_many_mfa_attempts" }, { "retry-after": String(limit.retryAfter) });
      return true;
    }
    const input = await readBody(request);
    const challenge = store.getMfaChallenge(String(input.challengeToken || ""));
    const user = challenge ? store.getUserForAuth(challenge.user_id) : null;
    if (!challenge || !user || user.status !== "active"
      || (user.role === "customer" && user.customer_status !== "active") || !user.mfa_enabled) {
      sendJson(response, 401, { error: "invalid_mfa_challenge" });
      return true;
    }
    const verification = verifyMfaCredential(user.id, input.code);
    if (!verification.valid) {
      store.failMfaChallenge(input.challengeToken);
      if (!config.demoReadOnly) {
        store.writeAudit({
          customerId: user.customer_id,
          userId: user.id,
          actorRole: user.role,
          action: "auth.mfa_failed",
          detail: { client: "api" },
          ipAddress: ip,
        });
      }
      sendJson(response, 401, { error: "invalid_mfa_code" });
      return true;
    }
    if (!store.consumeMfaChallenge(input.challengeToken)) {
      sendJson(response, 401, { error: "invalid_mfa_challenge" });
      return true;
    }
    mfaLimiter.clear(ip);
    const tokenSession = createApiLoginSession(request, user.id, input);
    if (!config.demoReadOnly) {
      store.writeAudit({
        customerId: user.customer_id,
        userId: user.id,
        actorRole: user.role,
        action: "auth.api_login",
        detail: {
          mfa: true,
          recoveryCode: verification.recoveryCode,
          deviceName: tokenSession.session.deviceName,
          platform: tokenSession.session.platform,
        },
        ipAddress: ip,
      });
      if (verification.recoveryCode) {
        queueSecurityNotice(user, {
          title: "A recovery code was used",
          message: "A one-time recovery code was used to sign in. Review your active sessions and regenerate codes if this was unexpected.",
          ipAddress: ip,
        });
      }
      queueNewLoginNotice(user, request);
    }
    sendApiAuthenticated(response, tokenSession);
    return true;
  }

  if (pathname === "/api/v1/auth/refresh" && request.method === "POST") {
    const ip = clientIp(request);
    const limit = apiRefreshLimiter.consume(ip);
    if (!limit.allowed) {
      sendJson(response, 429, { error: "too_many_refresh_attempts" }, { "retry-after": String(limit.retryAfter) });
      return true;
    }
    const { refreshToken } = await readBody(request);
    const tokenSession = store.rotateApiRefreshToken(refreshToken, {
      accessTtlMs: config.apiAccessTokenTtlMs,
      ipAddress: ip,
      userAgent: request.headers["user-agent"],
    });
    sendApiAuthenticated(response, tokenSession);
    return true;
  }

  if (pathname === "/api/v1/auth/logout" && request.method === "POST") {
    const session = requireSession(request, response);
    if (!session) return true;
    if (session.authType !== "bearer") {
      sendJson(response, 400, { error: "api_bearer_required" });
      return true;
    }
    audit(request, session, "auth.api_logout", {
      detail: { deviceSessionId: session.mobileSessionId },
    });
    store.revokeApiDeviceSession(session.user.id, session.mobileSessionId, "logout");
    sendJson(response, 204, null);
    return true;
  }

  if (pathname === "/api/v1/auth/session" && request.method === "GET") {
    const session = requireSession(request, response);
    if (!session) return true;
    if (session.authType !== "bearer") {
      sendJson(response, 400, { error: "api_bearer_required" });
      return true;
    }
    const device = store.listApiDeviceSessions(session.user.id, { currentIdHash: session.idHash })
      .find((entry) => entry.current);
    sendJson(response, 200, {
      apiVersion: "v1",
      user: session.user,
      session: device,
      accessTokenExpiresAt: session.expiresAt,
      refreshTokenExpiresAt: session.refreshExpiresAt,
      demoReadOnly: config.demoReadOnly,
    });
    return true;
  }

  if (pathname === "/api/v1/auth/devices" && request.method === "GET") {
    const session = requireSession(request, response);
    if (!session) return true;
    sendJson(response, 200, {
      devices: store.listApiDeviceSessions(session.user.id, { currentIdHash: session.idHash }),
    });
    return true;
  }

  const deviceMatch = pathname.match(/^\/api\/v1\/auth\/devices\/([^/]+)$/);
  if (deviceMatch && request.method === "DELETE") {
    const session = requireSession(request, response);
    if (!session || !requireCsrf(request, response, session)
      || !requireSecurityActionRate(request, response, session.user.id)) return true;
    const sessionId = decodeURIComponent(deviceMatch[1]);
    const current = sessionId === session.idHash || sessionId === session.mobileSessionId;
    if (!store.revokeApiDeviceSession(session.user.id, sessionId, "user_revoked")) {
      sendJson(response, 404, { error: "device_session_not_found" });
      return true;
    }
    audit(request, session, "security.api_device_revoked", { detail: { current, sessionId } });
    sendJson(response, 204, null);
    return true;
  }

  sendJson(response, 404, { error: "not_found" });
  return true;
}

async function routeCustomer(request, response, pathname) {
  const session = requireSession(request, response);
  if (!session) return true;
  const user = session.user;
  const enrollmentRequired = Boolean(user.mfaEnrollmentRequired);
  const enrollmentPath = pathname === "/api/v1/security/mfa/setup" || pathname === "/api/v1/security/mfa/confirm";
  if (enrollmentRequired && pathname !== "/api/v1/dashboard" && pathname !== "/api/v1/me" && !enrollmentPath) {
    sendJson(response, 403, { error: "mfa_enrollment_required" });
    return true;
  }

  if (pathname === "/api/v1/me" && request.method === "GET") {
    const accountSessions = store.listSessions(user.id, { currentIdHash: session.idHash });
    sendJson(response, 200, {
      apiVersion: "v1",
      mode: config.demoReadOnly ? "demo_read_only" : config.allowDemoData ? "demo" : "live",
      demoReadOnly: config.demoReadOnly,
      user,
      security: {
        mfa: {
          ...store.getMfaStatus(user.id),
          requiredByPolicy: store.isMfaRequiredForUser(user),
          enrollmentRequired,
        },
        sessions: config.demoReadOnly
          ? accountSessions.filter((entry) => entry.current).map((entry) => ({
              ...entry,
              ipAddress: "Hidden in public demo",
              userAgent: "Public demo client",
            }))
          : accountSessions,
      },
      capabilities: {
        mobileApi: true,
        rotatingRefreshTokens: true,
        integrationApiKeys: true,
        directAssignments: true,
        proxmoxPools: false,
        consoleTickets: true,
        customerIsoMedia: true,
        notificationCenter: true,
        maintenanceCenter: true,
        maintenanceActionLocks: true,
        supportTicketCenter: true,
        twoFactorAuthentication: true,
        demoReadOnly: config.demoReadOnly,
      },
    });
    return true;
  }

  if (pathname === "/api/v1/api-keys" && request.method === "GET") {
    if (session.authType === "api_key") {
      sendJson(response, 403, { error: "api_key_route_forbidden" });
      return true;
    }
    sendJson(response, 200, store.getUserApiKeyCenter(user.id));
    return true;
  }
  if (pathname === "/api/v1/api-keys/preview" && request.method === "POST") {
    if (session.authType === "api_key" || !requireCsrf(request, response, session)) {
      if (session.authType === "api_key") sendJson(response, 403, { error: "api_key_route_forbidden" });
      return true;
    }
    sendJson(response, 200, { preview: store.previewUserApiKey(user.id, await readBody(request)) });
    return true;
  }
  if (pathname === "/api/v1/api-keys" && request.method === "POST") {
    if (session.authType === "api_key" || !requireCsrf(request, response, session)
      || !requireSecurityActionRate(request, response, user.id)) {
      if (session.authType === "api_key") sendJson(response, 403, { error: "api_key_route_forbidden" });
      return true;
    }
    const input = await readBody(request);
    const authUser = await requireCurrentPassword(response, user.id, input.currentPassword);
    if (!authUser) return true;
    if (authUser.mfa_enabled) {
      const verification = verifyMfaCredential(user.id, input.code);
      if (!verification.valid) {
        sendJson(response, 400, { error: "invalid_mfa_code" });
        return true;
      }
    }
    const result = store.createUserApiKey(user.id, input);
    audit(request, session, "security.api_key_created", {
      detail: {
        keyId: result.key.id,
        name: result.key.name,
        groups: result.key.groups,
        resourceIds: result.key.resourceIds,
        expiresAt: result.key.expiresAt,
      },
    });
    queueSecurityNotice(authUser, {
      title: "A new API key was created",
      message: `The API key “${result.key.name}” was created for your Nimbus Direct account. Revoke it immediately if you did not create it.`,
      ipAddress: clientIp(request),
    });
    sendJson(response, 201, result);
    return true;
  }
  let apiKeyMatch = pathname.match(/^\/api\/v1\/api-keys\/([^/]+)$/);
  if (apiKeyMatch && request.method === "GET") {
    if (session.authType === "api_key") {
      sendJson(response, 403, { error: "api_key_route_forbidden" });
      return true;
    }
    const key = store.getUserApiKey(user.id, decodeURIComponent(apiKeyMatch[1]));
    if (!key) {
      sendJson(response, 404, { error: "api_key_not_found" });
      return true;
    }
    sendJson(response, 200, { key });
    return true;
  }
  if (apiKeyMatch && request.method === "DELETE") {
    if (session.authType === "api_key" || !requireCsrf(request, response, session)
      || !requireSecurityActionRate(request, response, user.id)) {
      if (session.authType === "api_key") sendJson(response, 403, { error: "api_key_route_forbidden" });
      return true;
    }
    const keyId = decodeURIComponent(apiKeyMatch[1]);
    if (!store.revokeUserApiKey(user.id, keyId)) {
      sendJson(response, 404, { error: "api_key_not_found" });
      return true;
    }
    audit(request, session, "security.api_key_revoked", { detail: { keyId } });
    sendJson(response, 204, null);
    return true;
  }

  if (pathname === "/api/v1/resources" && request.method === "GET") {
    const search = new URL(request.url, `http://${request.headers.host || "localhost"}`).searchParams;
    const limit = Math.min(200, Math.max(1, Number(search.get("limit")) || 50));
    const offset = Math.max(0, Number(search.get("offset")) || 0);
    const type = String(search.get("type") || "").toLowerCase();
    const status = String(search.get("status") || "").toLowerCase();
    const clusterId = String(search.get("clusterId") || "");
    const query = String(search.get("search") || "").trim().toLowerCase();
    const visible = filterApiKeyResources(session, resourcesFor(user))
      .filter((resource) => !type || resource.type === type)
      .filter((resource) => !status || resource.status === status)
      .filter((resource) => !clusterId || resource.clusterId === clusterId)
      .filter((resource) => !query || [
        resource.name,
        resource.displayName,
        resource.node,
        resource.clusterName,
        resource.vmid,
      ].some((value) => String(value || "").toLowerCase().includes(query)));
    sendJson(response, 200, {
      resources: {
        items: visible.slice(offset, offset + limit),
        total: visible.length,
        limit,
        offset,
      },
    });
    return true;
  }

  if (pathname === "/api/v1/dashboard" && request.method === "GET") {
    const resources = enrollmentRequired
      ? []
      : resourcesFor(user);
    const accountSessions = store.listSessions(user.id, { currentIdHash: session.idHash });
    const visibleSessions = config.demoReadOnly
      ? accountSessions.filter((entry) => entry.current).map((entry) => ({
          ...entry,
          ipAddress: "Hidden in public demo",
          userAgent: "Public demo browser",
        }))
      : accountSessions;
    sendJson(response, 200, {
      mode: config.demoReadOnly ? "demo_read_only" : config.allowDemoData ? "demo" : "live",
      demoReadOnly: config.demoReadOnly,
      user, summary: summarize(resources), resources,
      activity: enrollmentRequired
        ? { items: [], total: 0, limit: 10, offset: 0 }
        : demoSafeEventPage(store.listAudit(user.customerId, { limit: 10, customerVisible: user.role !== "admin" })),
      tasks: enrollmentRequired ? [] : store.listTasks(user, { limit: 12 }),
      notifications: enrollmentRequired ? { items: [], unread: 0, total: 0 } : store.listNotifications(user.id, { limit: 8 }),
      maintenance: enrollmentRequired ? { items: [], unread: 0, total: 0 } : store.listMaintenanceForUser(user.id, { limit: 8 }),
      maintenanceLocks: enrollmentRequired || user.role !== "customer"
        ? { items: [], activeCount: 0 }
        : store.listActiveMaintenanceLocksForUser(user.id, resources),
      support: enrollmentRequired ? { items: [], unread: 0, total: 0 } : store.listSupportTickets(user, { limit: 6 }),
      notificationPreferences: store.getNotificationPreferences(user.id),
      emailDeliveryAvailable: store.getEmailSettings().enabled,
      security: {
        mfa: {
          ...store.getMfaStatus(user.id),
          requiredByPolicy: store.isMfaRequiredForUser(user),
          enrollmentRequired,
        },
        sessions: visibleSessions,
      },
      capabilities: {
        directAssignments: true,
        proxmoxPools: false,
        consoleTickets: true,
        customerIsoMedia: true,
        notificationCenter: true,
        maintenanceCenter: true,
        maintenanceActionLocks: true,
        supportTicketCenter: true,
        twoFactorAuthentication: true,
        customerInvitations: true,
        passwordRecovery: true,
        mobileApi: true,
        rotatingRefreshTokens: true,
        integrationApiKeys: true,
        demoReadOnly: config.demoReadOnly,
      },
    });
    return true;
  }

  if (pathname === "/api/v1/network" && request.method === "GET") {
    const resources = filterApiKeyResources(session, resourcesFor(user));
    const networks = {};
    const clusters = new Map();
    for (const resource of resources) {
      if (isDemo(resource)) {
        networks[resource.id] = {
          status: resource.status === "running" ? "available" : "stopped",
          source: "demo",
          primaryIp: resource.ip,
          addresses: resource.ip ? [{ address: resource.ip, family: "ipv4", interface: "eth0", prefix: null }] : [],
          interfaces: [],
        };
        continue;
      }
      const clusterResources = clusters.get(resource.clusterId) || [];
      clusterResources.push(resource);
      clusters.set(resource.clusterId, clusterResources);
    }
    await Promise.all([...clusters.values()].map(async (clusterResources) => {
      const discovered = await clientFor(clusterResources[0]).getNetworks(clusterResources);
      Object.assign(networks, discovered);
    }));
    sendJson(response, 200, { networks, collectedAt: Date.now() });
    return true;
  }

  let mobileResourceMatch = pathname.match(/^\/api\/v1\/resources\/(.+)\/network$/);
  if (mobileResourceMatch && request.method === "GET") {
    const resourceId = decodeURIComponent(mobileResourceMatch[1]);
    const resource = requireResource(response, user, resourceId, "view_status");
    if (!resource) return true;
    if (isDemo(resource)) {
      sendJson(response, 200, {
        network: {
          status: resource.status === "running" ? "available" : "stopped",
          source: "demo",
          primaryIp: resource.ip,
          addresses: resource.ip ? [{ address: resource.ip, family: "ipv4", interface: "eth0", prefix: null }] : [],
          interfaces: [],
        },
        collectedAt: Date.now(),
      });
      return true;
    }
    const discovered = await clientFor(resource).getNetworks([resource]);
    sendJson(response, 200, {
      network: discovered[resource.id] || {
        status: resource.status === "running" ? "unavailable" : "stopped",
        source: "proxmox",
        primaryIp: null,
        addresses: [],
        interfaces: [],
      },
      collectedAt: Date.now(),
    });
    return true;
  }

  mobileResourceMatch = pathname.match(/^\/api\/v1\/resources\/(.+)\/snapshots$/);
  if (mobileResourceMatch && request.method === "GET") {
    const resourceId = decodeURIComponent(mobileResourceMatch[1]);
    const resource = requireResource(response, user, resourceId, "view_status");
    if (!resource) return true;
    if (!canViewSnapshots(resource, user)) {
      sendJson(response, 403, { error: "snapshot_access_denied" });
      return true;
    }
    const snapshots = isDemo(resource)
      ? demoSnapshotsFor(resource)
      : await clientFor(resource).listSnapshots(resource);
    sendJson(response, 200, {
      snapshots,
      policy: snapshotPolicy(resource, snapshots),
    });
    return true;
  }

  if (pathname === "/api/v1/support/tickets" && request.method === "GET") {
    const search = new URL(request.url, `http://${request.headers.host || "localhost"}`).searchParams;
    sendJson(response, 200, {
      tickets: store.listSupportTickets(user, {
        limit: search.get("limit") || 100,
        offset: search.get("offset") || 0,
        status: search.get("status") || "",
        priority: search.get("priority") || "",
        search: search.get("search") || "",
      }),
      assignees: user.role === "admin" ? store.listSupportAssignees() : [],
    });
    return true;
  }
  if (pathname === "/api/v1/support/tickets" && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    if (user.role !== "customer") {
      sendJson(response, 403, { error: "customer_required" });
      return true;
    }
    const limit = supportTicketCreateLimiter.consume(`${user.id}:${clientIp(request)}`);
    if (!limit.allowed) {
      sendJson(response, 429, { error: "support_ticket_rate_limited" }, { "retry-after": String(limit.retryAfter) });
      return true;
    }
    const result = store.createSupportTicket(await readBody(request), {
      customerId: user.customerId,
      userId: user.id,
    });
    const queuedEmails = queueSupportEmails({
      ticket: result.ticket,
      message: result.messages[0]?.body,
      actor: user,
      audience: "admin",
      eventType: "created",
      createdBy: user.id,
    });
    audit(request, session, "support.ticket.created", {
      customerId: result.ticket.customerId,
      resourceId: result.ticket.resourceId,
      detail: {
        ticketId: result.ticket.id,
        reference: result.ticket.reference,
        category: result.ticket.category,
        priority: result.ticket.priority,
        queuedEmails,
      },
    });
    sendJson(response, 201, { ...result, queuedEmails });
    return true;
  }
  let supportTicketMatch = pathname.match(/^\/api\/v1\/support\/tickets\/([^/]+)$/);
  if (supportTicketMatch && request.method === "GET") {
    const id = decodeURIComponent(supportTicketMatch[1]);
    sendJson(response, 200, {
      ...store.getSupportTicket(id, user),
      assignees: user.role === "admin" ? store.listSupportAssignees() : [],
    });
    return true;
  }
  if (supportTicketMatch && request.method === "PATCH") {
    if (!requireCsrf(request, response, session)) return true;
    if (user.role !== "admin") {
      sendJson(response, 403, { error: "admin_required" });
      return true;
    }
    const id = decodeURIComponent(supportTicketMatch[1]);
    const previous = store.getSupportTicket(id, user).ticket;
    const ticket = store.updateSupportTicket(id, await readBody(request), user);
    let queuedEmails = 0;
    if (previous.status !== ticket.status) {
      queuedEmails = queueSupportEmails({
        ticket,
        message: `The ticket status changed from ${previous.status.replaceAll("_", " ")} to ${ticket.status.replaceAll("_", " ")}.`,
        actor: user,
        audience: "customer",
        eventType: "status",
        createdBy: user.id,
      });
    }
    audit(request, session, "admin.support.ticket_updated", {
      customerId: ticket.customerId,
      resourceId: ticket.resourceId,
      detail: {
        ticketId: ticket.id,
        reference: ticket.reference,
        status: ticket.status,
        priority: ticket.priority,
        assignedTo: ticket.assignedTo,
        queuedEmails,
      },
    });
    sendJson(response, 200, { ticket, queuedEmails });
    return true;
  }
  supportTicketMatch = pathname.match(/^\/api\/v1\/support\/tickets\/([^/]+)\/messages$/);
  if (supportTicketMatch && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    const limit = supportTicketMessageLimiter.consume(`${user.id}:${clientIp(request)}`);
    if (!limit.allowed) {
      sendJson(response, 429, { error: "support_message_rate_limited" }, { "retry-after": String(limit.retryAfter) });
      return true;
    }
    const id = decodeURIComponent(supportTicketMatch[1]);
    const input = await readBody(request);
    const internal = user.role === "admin" && Boolean(input.internal);
    const result = store.addSupportTicketMessage(id, input, user, { internal });
    const queuedEmails = internal ? 0 : queueSupportEmails({
      ticket: result.ticket,
      message: result.message.body,
      actor: user,
      audience: user.role === "admin" ? "customer" : "admin",
      eventType: "reply",
      createdBy: user.id,
    });
    audit(request, session, internal ? "admin.support.internal_note_added" : "support.ticket.replied", {
      customerId: result.ticket.customerId,
      resourceId: result.ticket.resourceId,
      detail: {
        ticketId: result.ticket.id,
        reference: result.ticket.reference,
        messageId: result.message.id,
        internal,
        queuedEmails,
      },
    });
    sendJson(response, 201, { ...result, queuedEmails });
    return true;
  }
  supportTicketMatch = pathname.match(/^\/api\/v1\/support\/tickets\/([^/]+)\/(read|close|reopen)$/);
  if (supportTicketMatch && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    const id = decodeURIComponent(supportTicketMatch[1]);
    const operation = supportTicketMatch[2];
    if (operation === "read") {
      store.markSupportTicketRead(id, user);
      sendJson(response, 204, null);
      return true;
    }
    const ticket = operation === "close"
      ? store.closeSupportTicket(id, user)
      : store.reopenSupportTicket(id, user);
    const queuedEmails = queueSupportEmails({
      ticket,
      message: operation === "close"
        ? "The customer marked this support request as closed."
        : "The support request was reopened and is waiting for support.",
      actor: user,
      audience: user.role === "admin" ? "customer" : "admin",
      eventType: "status",
      createdBy: user.id,
    });
    audit(request, session, operation === "close" ? "support.ticket.closed" : "support.ticket.reopened", {
      customerId: ticket.customerId,
      resourceId: ticket.resourceId,
      detail: { ticketId: ticket.id, reference: ticket.reference, queuedEmails },
    });
    sendJson(response, 200, { ticket, queuedEmails });
    return true;
  }

  if (pathname === "/api/v1/maintenance" && request.method === "GET") {
    const search = new URL(request.url, `http://${request.headers.host || "localhost"}`).searchParams;
    sendJson(response, 200, {
      maintenance: store.listMaintenanceForUser(user.id, {
        limit: search.get("limit") || 100,
        offset: search.get("offset") || 0,
      }),
    });
    return true;
  }
  let maintenanceDeliveryMatch = pathname.match(/^\/api\/v1\/maintenance\/([^/]+)\/read$/);
  if (maintenanceDeliveryMatch && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    store.markMaintenanceRead(decodeURIComponent(maintenanceDeliveryMatch[1]), user.id);
    sendJson(response, 204, null);
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
  if (pathname === "/api/v1/push/devices" && request.method === "POST") {
    if (session.authType !== "bearer") {
      sendJson(response, 403, { error: "api_bearer_required" });
      return true;
    }
    if (!requireCsrf(request, response, session)) return true;
    const device = store.registerPushDevice(user.id, await readBody(request));
    sendJson(response, 200, { ...device, pushAvailable: push.configured });
    return true;
  }
  if (pathname === "/api/v1/push/devices/unregister" && request.method === "POST") {
    if (session.authType !== "bearer") {
      sendJson(response, 403, { error: "api_bearer_required" });
      return true;
    }
    if (!requireCsrf(request, response, session)) return true;
    const { token } = await readBody(request);
    store.unregisterPushDevice(user.id, token);
    sendJson(response, 204, null);
    return true;
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
    if (!consoleSession || !apiKeyHasResource(session, consoleSession.resourceId)
      || !resourceFor(user, consoleSession.resourceId, "console")) {
      sendJson(response, 404, { error: "console_session_not_found" }); return true;
    }
    sendConsoleSession(response, token, consoleSession);
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
    if (!enforceMaintenanceAction(response, user, resource, "iso_delete")) return true;
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
    let consoleType;
    if (isDemo(resource)) {
      consoleType = resource.type === "lxc" ? "terminal" : "graphical";
      consoleSession = store.createConsoleSession({
        userId: user.id,
        resourceId,
        ticket: "demo-console-ticket",
        port: 5900,
        consoleType,
        consoleUser: "nimbus-demo@pve",
      });
    } else {
      const ticket = await clientFor(resource).createConsoleTicket(resource);
      consoleType = ticket.consoleType;
      consoleSession = store.createConsoleSession({
        userId: user.id,
        resourceId,
        ticket: ticket.ticket,
        port: ticket.port,
        consoleType: ticket.consoleType,
        consoleUser: ticket.user,
      });
    }
    audit(request, session, "resource.console.ticket_created", {
      customerId: resource.customerId || user.customerId,
      resourceId,
      consoleType,
    });
    sendJson(response, 201, {
      launchUrl: `/console.html?token=${encodeURIComponent(consoleSession.token)}`,
      nativeLaunchUrl: `/api/v1/console/native-launch/${encodeURIComponent(consoleSession.token)}`,
      expiresAt: consoleSession.expiresAt,
      console: {
        type: consoleType,
        label: consoleType === "terminal" ? "Terminal console" : "Graphical console",
      },
    }); return true;
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
      const snapshots = canViewSnapshots(resource, user) && apiKeyHasGroup(session, "snapshot_management") ? demoSnapshotsFor(resource) : [];
      sendJson(response, 200, {
        instance: resource,
        config: { cores: resource.vcpu, memory: resource.memory * 1024, onboot: 1 },
        network: {
          status: "available",
          source: "demo",
          primaryIp: resource.ip,
          addresses: resource.ip ? [{ address: resource.ip, family: "ipv4", interface: "eth0", prefix: 24 }] : [],
          interfaces: resource.ip
            ? [{
              name: "eth0",
              mac: null,
              addresses: [{ address: resource.ip, family: "ipv4", interface: "eth0", prefix: 24 }],
            }]
            : [],
        },
        snapshots,
        snapshotPolicy: snapshotPolicy(resource, snapshots),
        tasks: store.listTasks(user, { resourceId, limit: 12 }),
      });
      return true;
    }
    const details = await clientFor(resource).getInstanceDetails(resource);
    if (!resource.permissions.includes("view_config") && user.role !== "admin") details.config = {};
    if (!canViewSnapshots(resource, user) || !apiKeyHasGroup(session, "snapshot_management")) details.snapshots = [];
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
    const tasks = store.listTasks(user, { resourceId, limit: search.get("limit") || 20 })
      .filter((task) => apiKeyHasResource(session, task.resourceId));
    sendJson(response, 200, { tasks });
    return true;
  }

  match = pathname.match(/^\/api\/v1\/tasks\/([^/]+)$/);
  if (match && request.method === "GET") {
    const task = store.getTask(decodeURIComponent(match[1]), user);
    if (!task || !apiKeyHasResource(session, task.resourceId)) { sendJson(response, 404, { error: "task_not_found" }); return true; }
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
    if (store.isMfaRequiredForUser(user)) {
      sendJson(response, 409, { error: "mfa_required_by_policy" });
      return true;
    }
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
    queueSecurityNotice(authUser, {
      title: "Your password was changed",
      message: "Your Nimbus Direct password was changed and every active session was signed out.",
      ipAddress: clientIp(request),
    });
    sendJson(response, 204, null, { "set-cookie": sessionCookie("", { secure: config.secureCookies, maxAge: 0, name: cookieName }) }); return true;
  }

  sendJson(response, 404, { error: "not_found" });
  return true;
}

async function routeApi(request, response, pathname) {
  if (pathname === "/api/health" && request.method === "GET") { sendJson(response, 200, { ok: true }); return; }
  if (pathname === "/api/ready" && request.method === "GET") { sendJson(response, store.hasUsers() ? 200 : 503, { ready: store.hasUsers() }); return; }
  if (pathname === "/api/v1" && request.method === "GET") {
    sendJson(response, 200, {
      name: "Nimbus Direct API",
      version: "v1",
      openapi: "/api/v1/openapi.json",
      authentication: {
        accessTokenType: "Bearer",
        accessTokenExpiresInSeconds: Math.floor(config.apiAccessTokenTtlMs / 1000),
        refreshTokenExpiresInSeconds: Math.floor(config.apiRefreshTokenTtlMs / 1000),
        refreshRotation: true,
        twoFactorAuthentication: true,
      },
      capabilities: {
        resources: true,
        actions: true,
        tasks: true,
        snapshots: true,
        isoMedia: true,
        notifications: true,
        pushNotifications: push.configured,
        maintenance: true,
        support: true,
        administration: true,
        integrationApiKeys: true,
      },
      demoReadOnly: config.demoReadOnly,
    });
    return;
  }
  if (pathname === "/api/v1/openapi.json" && request.method === "GET") {
    sendJson(response, 200, nimbusOpenApi);
    return;
  }
  if (routeNativeConsole(request, response, pathname)) return;
  if (config.demoReadOnly && !isDemoReadOnlyRequestAllowed(request.method, pathname)) {
    sendJson(response, 403, {
      error: "demo_read_only",
      message: "This public demo is read-only. No changes were made.",
    });
    return;
  }
  const integrationToken = bearerToken(request);
  if (integrationToken?.startsWith("nmb_key_")) {
    const integrationSession = currentSession(request);
    if (!integrationSession) {
      sendJson(response, 401, { error: "authentication_required" });
      return;
    }
    if (!authorizeIntegrationKeyRequest(request, response, pathname, integrationSession)) return;
  }
  if (pathname.startsWith("/api/auth/") && await routeAuth(request, response, pathname)) return;
  if (pathname.startsWith("/api/v1/auth/") && await routeApiAuth(request, response, pathname)) return;
  if (pathname.startsWith("/api/v1/admin/")) {
    await routeAdmin(request, response, pathname.replace(/^\/api\/v1\/admin/, "/api/admin"));
    return;
  }
  if (pathname.startsWith("/api/admin/")) { await routeAdmin(request, response, pathname); return; }
  await routeCustomer(request, response, pathname);
}

const mime = {
  ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
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
    const vendor = [
      { prefix: "/vendor/novnc/", root: noVncRoot },
      { prefix: "/vendor/xterm/", root: xtermRoot },
      { prefix: "/vendor/xterm-fit/", root: xtermFitRoot },
    ].find((entry) => url.pathname.startsWith(entry.prefix));
    const requested = url.pathname === "/" ? "index.html" : (vendor ? url.pathname.slice(vendor.prefix.length) : url.pathname.slice(1));
    const staticRoot = vendor?.root || root;
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
    if (config.demoReadOnly) return rejectUpgrade(socket, "403 Forbidden");
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    const match = url.pathname.match(/^\/api\/v1\/console\/ws\/([^/]+)$/);
    if (!match) return rejectUpgrade(socket, "404 Not Found");
    const token = decodeURIComponent(match[1]);
    let session = currentSession(request);
    const nativeContext = session ? null : nativeConsoleContext(request, token);
    if (!session && !nativeContext) return rejectUpgrade(socket);
    if (!session) session = { authType: "native_console", user: nativeContext.user };
    const pending = nativeContext?.pending || store.getConsoleSession(token, session.user.id);
    if (!pending || !apiKeyHasGroup(session, "console_access") || !apiKeyHasResource(session, pending.resourceId)
      || !resourceFor(session.user, pending.resourceId, "console")) return rejectUpgrade(socket, "404 Not Found");
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
  log("info", "server_started", {
    host: config.host,
    port: config.port,
    production: config.production,
    bootstrapped,
    demo: config.allowDemoData,
    demoReadOnly: config.demoReadOnly,
  });
});

if (!config.demoReadOnly) email.start();
const syncTimer = config.demoReadOnly ? null : setInterval(syncAllClusters, config.syncIntervalMs);
syncTimer?.unref();
const maintenanceTimer = config.demoReadOnly ? null : setInterval(() => store.advanceMaintenanceEvents(), 60_000);
maintenanceTimer?.unref();

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => {
    if (!config.demoReadOnly) email.stop();
    if (syncTimer) clearInterval(syncTimer);
    if (maintenanceTimer) clearInterval(maintenanceTimer);
    store.close();
    process.exit(0);
  }));
}
