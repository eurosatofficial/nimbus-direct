import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { connect as connectTls } from "node:tls";
import { loadEnv, readConfig } from "./server/config.mjs";
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
const actionLimiter = new RateLimiter({ limit: 30, windowMs: 60 * 1000 });
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

function log(level, message, detail = {}) {
  console[level === "error" ? "error" : "log"](JSON.stringify({ timestamp: new Date().toISOString(), level, message, ...detail }));
}

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

async function syncCluster(clusterId) {
  if (config.allowDemoData && clusterId === "demo-eu") return store.syncResources(clusterId, demoResources.map((resource) => {
    const current = store.getResource(`${clusterId}:${resource.type}:${resource.vmid}`);
    return current ? { ...resource, status: current.status } : resource;
  }));
  try {
    const resources = await proxmox.forCluster(clusterId).listVirtualMachines();
    return store.syncResources(clusterId, resources);
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
    if (!user || user.status !== "active" || !(await verifyPassword(String(password || ""), user.password_hash))) {
      sendJson(response, 401, { error: "invalid_credentials" }); return true;
    }
    loginLimiter.clear(ip);
    const session = store.createSession({ userId: user.id, ttlMs: config.sessionTtlMs });
    store.writeAudit({ customerId: user.customer_id, userId: user.id, actorRole: user.role, action: "auth.login", ipAddress: ip });
    sendJson(response, 200, { user: store.getSession(session.token).user, csrfToken: session.csrfToken, expiresAt: session.expiresAt }, {
      "set-cookie": sessionCookie(session.token, { secure: config.secureCookies, maxAge: config.sessionTtlMs, name: cookieName }),
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
      resources: store.listResources(), audit: store.listAudit(null, { all: true, limit: 50 }),
    });
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
  if (pathname === "/api/admin/clusters" && request.method === "POST") {
    const cluster = store.createCluster(await readBody(request));
    audit(request, session, "admin.cluster.created", { detail: { clusterId: cluster.id } });
    sendJson(response, 201, { cluster }); return true;
  }
  if (pathname === "/api/admin/assignments" && request.method === "POST") {
    const input = await readBody(request);
    const resource = store.assignResource(input);
    audit(request, session, "admin.resource.assigned", { customerId: input.customerId, resourceId: input.resourceId, detail: { permissions: resource.permissions } });
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
  match = pathname.match(/^\/api\/admin\/resources\/(.+)\/assignment$/);
  if (match && request.method === "PATCH") {
    const resourceId = decodeURIComponent(match[1]);
    const resource = store.updateAssignment(resourceId, await readBody(request));
    audit(request, session, "admin.assignment.updated", { customerId: resource.customerId, resourceId });
    sendJson(response, 200, { resource }); return true;
  }
  if (match && request.method === "DELETE") {
    const resourceId = decodeURIComponent(match[1]);
    const existing = store.getResource(resourceId);
    store.unassignResource(resourceId);
    audit(request, session, "admin.resource.unassigned", { customerId: existing?.customerId, resourceId });
    sendJson(response, 204, null); return true;
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
      capabilities: { directAssignments: true, proxmoxPools: false, consoleTickets: true },
    });
    return true;
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
    if (existing) { sendJson(response, 202, { task: existing, duplicate: true }); return true; }
    audit(request, session, `resource.${permission}.requested`, { customerId: resource.customerId || user.customerId, resourceId, detail: { clusterId: resource.clusterId, node: resource.node, vmid: resource.vmid } });
    if (isDemo(resource)) {
      const nextStatus = ["stop", "shutdown"].includes(permission) ? "stopped" : permission === "suspend" ? "suspended" : "running";
      sendJson(response, 200, { completed: true, resource: store.setResourceStatus(resourceId, nextStatus) }); return true;
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
    const resourceId = decodeURIComponent(match[1]);
    const resource = requireResource(response, user, resourceId, "snapshot_create");
    if (!resource) return true;
    const input = await readBody(request);
    if (!isDemo(resource)) await clientFor(resource).createSnapshot(resource, input);
    audit(request, session, "resource.snapshot.created", { customerId: resource.customerId || user.customerId, resourceId, detail: { name: input.name } });
    sendJson(response, 202, { accepted: true }); return true;
  }
  match = pathname.match(/^\/api\/v1\/resources\/(.+)\/snapshots\/([^/]+)\/(restore|delete)$/);
  if (match && request.method === "POST") {
    if (!requireCsrf(request, response, session)) return true;
    const resourceId = decodeURIComponent(match[1]);
    const snapshotName = decodeURIComponent(match[2]);
    const operation = match[3];
    const resource = requireResource(response, user, resourceId, operation === "restore" ? "snapshot_restore" : "snapshot_delete");
    if (!resource) return true;
    if (!isDemo(resource)) {
      if (operation === "restore") await clientFor(resource).restoreSnapshot(resource, snapshotName);
      else await clientFor(resource).deleteSnapshot(resource, snapshotName);
    }
    audit(request, session, `resource.snapshot.${operation}d`, { customerId: resource.customerId || user.customerId, resourceId, detail: { name: snapshotName } });
    sendJson(response, 202, { accepted: true }); return true;
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

  match = pathname.match(/^\/api\/v1\/resources\/(.+)$/);
  if (match && request.method === "GET") {
    const resourceId = decodeURIComponent(match[1]);
    const resource = requireResource(response, user, resourceId, "view_status");
    if (!resource) return true;
    if (isDemo(resource)) {
      sendJson(response, 200, { instance: resource, config: { cores: resource.vcpu, memory: resource.memory * 1024, onboot: 1 }, network: { status: "available", primaryIp: resource.ip, addresses: resource.ip ? [{ address: resource.ip, family: "ipv4", interface: "eth0" }] : [] }, snapshots: [{ name: "before-upgrade", description: "Known good state", createdAt: Date.now() - 86400000 * 4 }] });
      return true;
    }
    const details = await clientFor(resource).getInstanceDetails(resource);
    if (!resource.permissions.includes("view_config") && user.role !== "admin") details.config = {};
    sendJson(response, 200, details); return true;
  }

  match = pathname.match(/^\/api\/v1\/tasks\/([^/]+)$/);
  if (match && request.method === "GET") {
    const task = store.getTask(decodeURIComponent(match[1]), user);
    if (!task) { sendJson(response, 404, { error: "task_not_found" }); return true; }
    const remote = await proxmox.forCluster(task.cluster_id).getTaskStatus(task.node, task.upid);
    const completed = remote.status === "stopped";
    const updated = store.updateTask(task.id, { status: remote.status, exitStatus: remote.exitstatus || null, completedAt: completed ? Date.now() : null });
    sendJson(response, 200, { task: updated, completed }); return true;
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
    if (status >= 500) log("error", "request_failed", { requestId, method: request.method, path: request.url, error: error.message, code: error.code });
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

const syncTimer = setInterval(syncAllClusters, config.syncIntervalMs);
syncTimer.unref();

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => { clearInterval(syncTimer); store.close(); process.exit(0); }));
}
