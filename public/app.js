const state = {
  user: null,
  csrfToken: null,
  dashboard: null,
  admin: null,
  currentView: "overview",
  adminTab: "inventory",
  isoCandidates: {},
  isoClusterId: null,
  search: "",
  loading: false,
  lastUpdatedAt: 0,
  instance: {
    resourceId: null,
    details: null,
    history: null,
    timeframe: "day",
    loading: false,
    refreshing: false,
    historyLoading: false,
    media: null,
    mediaLoading: false,
    upload: null,
    error: null,
  },
};
const announcedTaskIds = new Set();
let taskPollTimer = null;
let taskPolling = false;
let mediaPollTimer = null;

const permissions = [
  ["view_status", "View status"], ["start", "Start"], ["stop", "Stop"], ["shutdown", "Shutdown"],
  ["reboot", "Reboot"], ["reset", "Reset"], ["suspend", "Suspend"], ["resume", "Resume"],
  ["console", "Console access"], ["view_config", "View configuration"], ["view_usage", "Usage statistics"],
  ["snapshot_create", "Create snapshots"], ["snapshot_restore", "Restore snapshots"], ["snapshot_delete", "Delete snapshots"],
  ["config_change", "Change selected configuration"],
  ["iso_view", "View installation media"], ["iso_upload", "Upload ISO images"],
  ["iso_mount", "Mount and eject ISO images"], ["iso_delete", "Delete uploaded ISO images"],
];

const views = {
  overview: ["Infrastructure overview", "Resources assigned directly to this account."],
  instances: ["Virtual machines & containers", "Power controls and detailed resource information."],
  instance: ["Instance details", "Live status, usage, networking, controls, and task progress."],
  network: ["Network", "Basic addresses for assigned guests."],
  activity: ["Activity", "Recent account actions and Proxmox task requests."],
  settings: ["Account settings", "Manage your profile and security."],
  admin: ["Control center", "Clusters, customers, direct assignments, and policy."],
};

const els = Object.fromEntries([
  "authView", "appShell", "loginForm", "authError", "viewRoot", "pageTitle", "pageDescription", "currentSection",
  "tenantPlan", "connectionHealth", "healthTitle", "healthDetail", "instanceCount", "profileName", "profileTenant",
  "profileAvatar", "globalSearch", "refreshButton", "logoutButton", "todayLabel", "lastUpdated",
  "actionDialog", "actionForm", "actionDialogTitle", "actionDialogDescription",
  "actionDialogResource", "confirmAction", "editDialog", "editForm", "editDialogTitle", "editDialogBody", "editDialogError",
  "toast", "toastIcon", "toastTitle", "toastMessage", "toastClose", "menuButton", "sidebar", "sidebarBackdrop",
].map((id) => [id, document.getElementById(id)]));

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
}

function initials(value) {
  return String(value || "ND").split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]).join("").toUpperCase();
}

function plural(value, word) { return `${value} ${word}${value === 1 ? "" : "s"}`; }
function pct(value) { return `${Math.max(0, Math.min(100, Number(value) || 0))}%`; }
function percent(value, total) { return total > 0 ? Math.max(0, Math.min(100, value / total * 100)) : 0; }
function formatUptime(seconds) {
  if (!seconds) return "—";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return days ? `${days}d ${hours}h` : `${hours}h`;
}
function formatDate(value, options = {}) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, options.dateOnly
    ? { dateStyle: "medium" }
    : { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}
function formatRate(bytes) {
  const value = Math.max(0, Number(bytes) || 0);
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(1)} MB/s`;
  if (value >= 1024) return `${Math.round(value / 1024)} KB/s`;
  return `${Math.round(value)} B/s`;
}
function formatBytes(bytes) {
  const value = Math.max(0, Number(bytes) || 0);
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(value >= 10 * 1024 ** 3 ? 0 : 1)} GB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(value >= 10 * 1024 ** 2 ? 0 : 1)} MB`;
  if (value >= 1024) return `${Math.round(value / 1024)} KB`;
  return `${Math.round(value)} B`;
}
function formatRelative(value) {
  if (!value) return "Just now";
  const seconds = Math.max(0, Math.round((Date.now() - Number(value)) / 1000));
  if (seconds < 60) return "Just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}
function actionLabel(action) {
  return ({ start: "Starting", stop: "Stopping", shutdown: "Shutting down", reboot: "Rebooting", reset: "Resetting", suspend: "Suspending", resume: "Resuming" })[action] || "Processing";
}
function actionName(action) {
  return ({ start: "Start", stop: "Force stop", shutdown: "Shutdown", reboot: "Reboot", reset: "Force reset", suspend: "Suspend", resume: "Resume" })[action] || "Power";
}

async function apiFetch(path, options = {}) {
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(options.body);
  }
  if (state.csrfToken && options.method && options.method !== "GET") headers["X-CSRF-Token"] = state.csrfToken;
  const timeoutController = new AbortController();
  const timeout = setTimeout(() => timeoutController.abort(), 20_000);
  let response;
  try {
    response = await fetch(path, { credentials: "same-origin", ...options, headers, signal: options.signal || timeoutController.signal });
  } catch (error) {
    if (error?.name === "AbortError") {
      throw Object.assign(new Error("The panel request timed out. Check the reverse proxy and container API logs."), { code: "request_timeout" });
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
  let payload = null;
  if (response.status !== 204) {
    try { payload = await response.json(); } catch { payload = {}; }
  }
  if (!response.ok) throw Object.assign(new Error(payload?.message || payload?.error || `Request failed (${response.status})`), { code: payload?.error, status: response.status, payload });
  return payload;
}

function friendlyError(error) {
  const messages = {
    invalid_credentials: "The email address or password is incorrect.",
    too_many_attempts: "Too many sign-in attempts. Please wait and try again.",
    invalid_csrf_token: "Your session changed. Refresh the page and try again.",
    request_timeout: "The panel request timed out. Check the reverse proxy and container API logs.",
    resource_not_found: "That resource is not assigned to your account or the permission is disabled.",
    resource_task_in_progress: "Another action is already running for this resource. Wait for it to finish.",
    task_not_found: "That task is no longer available to this account.",
    invalid_timeframe: "That usage-history range is not supported.",
    last_admin: "The final active administrator cannot be changed or deleted.",
    proxmox_unreachable: "The Proxmox cluster could not be reached.",
    iso_qemu_only: "Installation media is available only for virtual machines, not LXC containers.",
    iso_policy_not_found: "No enabled ISO storage policy is available for this VM.",
    iso_policy_disabled: "That ISO storage policy is currently disabled.",
    iso_storage_unavailable: "The ISO storage is not available on this VM's Proxmox node.",
    iso_not_on_node: "That ISO is on node-local storage on another node. Upload it from this VM or use shared ISO storage.",
    invalid_iso_filename: "Choose a file whose name ends in .iso.",
    invalid_iso_size: "Nimbus could not determine the selected ISO size.",
    iso_too_large: "That ISO is larger than the configured upload limit.",
    iso_quota_exceeded: "This upload would exceed your ISO storage quota.",
    iso_upload_size_mismatch: "The ISO upload ended with an unexpected size. Please retry.",
    iso_not_ready: "That ISO is still being processed and cannot be mounted yet.",
    cdrom_in_use: "An ISO is already mounted. Eject it before mounting another.",
    cdrom_state_changed: "The virtual CD/DVD drive changed outside Nimbus. Refresh before retrying.",
    iso_mounted: "Eject this ISO before deleting it.",
    iso_delete_disabled: "Customer ISO deletion is disabled for this storage.",
    iso_operation_in_progress: "That ISO operation is still in progress.",
    too_many_uploads: "Too many ISO uploads were started. Please wait before trying again.",
    iso_policy_in_use: "Disable this policy instead; customer ISO records still use it.",
    resource_iso_mounted: "Eject the customer ISO before changing this VM assignment.",
    customer_iso_images_exist: "Delete this customer's ISO images before deleting the customer account.",
  };
  return messages[error?.code] || error?.message || "Something went wrong.";
}

function showToast(type, title, message) {
  els.toast.classList.toggle("error", type === "error");
  els.toastIcon.textContent = type === "error" ? "!" : "✓";
  els.toastTitle.textContent = title;
  els.toastMessage.textContent = message;
  els.toast.classList.add("show");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => els.toast.classList.remove("show"), 4500);
}

function setConnection(mode) {
  els.connectionHealth.className = `connection-card ${mode === "demo" ? "demo" : ""}`;
  els.healthTitle.textContent = mode === "demo" ? "Interactive demo" : "Connected securely";
  els.healthDetail.textContent = mode === "demo" ? "Safe simulated Proxmox data" : "Official Proxmox API";
}

function setAuthenticated(authenticated) {
  document.body.classList.remove("auth-pending");
  document.body.classList.toggle("authenticated", authenticated);
  els.authView.hidden = authenticated;
  els.appShell.classList.toggle("visible", authenticated);
  els.appShell.setAttribute("aria-hidden", String(!authenticated));
}

function applyUser() {
  const user = state.user;
  els.profileName.textContent = user.displayName;
  els.profileTenant.textContent = user.role === "admin" ? "Platform administrator" : user.customerName;
  els.profileAvatar.textContent = initials(user.displayName);
  els.tenantPlan.textContent = user.role === "admin" ? "Global scope" : user.planName;
  document.querySelectorAll(".admin-nav").forEach((element) => { element.hidden = user.role !== "admin"; });
  if (user.role !== "admin" && state.currentView === "admin") location.hash = "#overview";
}

async function loadSession() {
  try {
    const result = await apiFetch("/api/auth/session");
    state.user = result.user;
    state.csrfToken = result.csrfToken;
    setAuthenticated(true);
    applyUser();
    await loadDashboard();
    route();
  } catch {
    setAuthenticated(false);
  }
}

async function loadDashboard() {
  state.dashboard = await apiFetch("/api/v1/dashboard");
  state.user = state.dashboard.user;
  state.lastUpdatedAt = Date.now();
  els.instanceCount.textContent = state.dashboard.resources.length;
  els.lastUpdated.textContent = `Updated ${formatDate(state.lastUpdatedAt)}`;
  setConnection(state.dashboard.mode);
  applyUser();
  scheduleTaskPolling();
}

async function loadAdmin() {
  state.admin = await apiFetch("/api/admin/state");
}

function filteredResources(resources = state.dashboard?.resources || []) {
  const query = state.search.trim().toLowerCase();
  return query ? resources.filter((resource) => [resource.name, resource.vmid, resource.node, resource.clusterName, resource.customerName, resource.type].some((value) => String(value || "").toLowerCase().includes(query))) : resources;
}

function statusMarkup(resource) {
  return `<span class="status ${escapeHtml(resource.status)}"><i></i>${escapeHtml(resource.status || "unknown")}</span>`;
}

function resourceIdentity(resource) {
  return `<div class="server-name"><span class="server-avatar resource-type ${resource.type}">${resource.type === "lxc" ? "CT" : "VM"}</span><span class="server-copy"><strong>${escapeHtml(resource.displayName || resource.name)}</strong><small>${escapeHtml(resource.clusterName)} · ${escapeHtml(resource.node)} · ${resource.type.toUpperCase()} ${resource.vmid}</small></span></div>`;
}

function can(resource, permission) { return state.user?.role === "admin" || resource.permissions?.includes(permission); }

function resourceTasks(resourceId) {
  const tasks = [
    ...(state.dashboard?.tasks || []),
    ...(state.instance.details?.tasks || []),
  ];
  return [...new Map(tasks.filter((task) => task.resourceId === resourceId).map((task) => [task.id, task])).values()]
    .sort((left, right) => Number(right.createdAt) - Number(left.createdAt));
}

function activeTask(resourceId) {
  return resourceTasks(resourceId).find((task) => !task.completed) || null;
}

function actionButtons(resource, compact = false) {
  const pending = activeTask(resource.id);
  if (pending) {
    return `<div class="row-buttons"><button class="row-button task-running" disabled><span class="button-spinner" aria-hidden="true"></span>${escapeHtml(actionLabel(pending.action))}…</button><button class="row-button" data-details="${escapeHtml(resource.id)}">View progress</button></div>`;
  }
  const main = resource.status === "running" ? [["shutdown", "Shutdown"], ["reboot", "Reboot"]] : resource.status === "suspended" ? [["resume", "Resume"]] : [["start", "Start"]];
  const controls = main.filter(([permission]) => can(resource, permission)).map(([action, label]) => `<button class="row-button ${action === "shutdown" ? "danger" : ""}" data-action="${action}" data-resource="${escapeHtml(resource.id)}">${label}</button>`).join("");
  return `<div class="row-buttons">${controls}${can(resource, "console") && !compact ? `<button class="row-button" data-console="${escapeHtml(resource.id)}">Console</button>` : ""}<button class="row-button" data-details="${escapeHtml(resource.id)}">Details</button></div>`;
}

function resourceTable(resources, { admin = false, compact = false } = {}) {
  if (!resources.length) return emptyState("▤", state.search ? "No matching resources" : "No resources assigned", state.search ? "Try another search." : "An administrator can assign an individual VM or container from the control center.");
  return `<div class="table-wrap"><table class="data-table"><thead><tr><th>Resource</th><th>Status</th><th>CPU</th><th>Memory</th>${admin ? "<th>Customer</th>" : ""}<th><span class="visually-hidden">Actions</span></th></tr></thead><tbody>${resources.map((resource) => `<tr><td>${resourceIdentity(resource)}</td><td>${statusMarkup(resource)}</td><td><div class="usage-cell"><div class="usage-values"><span>${pct(resource.cpu)}</span><span>${resource.vcpu} vCPU</span></div><div class="usage-bar"><span style="width:${pct(resource.cpu)}"></span></div></div></td><td><div class="resource-copy"><strong>${resource.memoryUsed} / ${resource.memory} GB</strong><small>${formatUptime(resource.uptime)} uptime</small></div></td>${admin ? `<td>${resource.customerName ? `<span class="assignment-chip">${escapeHtml(resource.customerName)}</span>` : `<span class="unassigned-chip">Unassigned</span>`}</td>` : ""}<td>${admin ? `<div class="row-buttons"><button class="row-button" data-assign="${escapeHtml(resource.id)}">${resource.customerId ? "Policy" : "Assign"}</button>${resource.customerId ? `<button class="row-button danger" data-unassign="${escapeHtml(resource.id)}">Remove</button>` : ""}</div>` : actionButtons(resource, compact)}</td></tr>`).join("")}</tbody></table></div>`;
}

function emptyState(icon, title, copy) {
  return `<div class="empty-state"><div><span class="empty-icon">${icon}</span><h3>${escapeHtml(title)}</h3><p>${escapeHtml(copy)}</p></div></div>`;
}

function metricCards() {
  const summary = state.dashboard.summary;
  return `<section class="metric-grid">
    <article class="metric-card accent-blue"><div class="metric-head"><span class="metric-icon">▤</span><span class="pill success">Assigned</span></div><p class="metric-label">Resources</p><div class="metric-value"><strong>${summary.total}</strong><span>${summary.active} running</span></div><div class="metric-foot">Across ${plural(summary.clusters, "cluster")}</div></article>
    <article class="metric-card accent-violet"><div class="metric-head"><span class="metric-icon">⌁</span><span class="pill">Live</span></div><p class="metric-label">Average CPU</p><div class="metric-value"><strong>${summary.cpuAverage}%</strong><span>running guests</span></div><div class="progress"><span style="width:${pct(summary.cpuAverage)}"></span></div></article>
    <article class="metric-card accent-orange"><div class="metric-head"><span class="metric-icon">◫</span><span class="pill">Allocated</span></div><p class="metric-label">Memory</p><div class="metric-value"><strong>${summary.memoryUsed}</strong><span>of ${summary.memoryTotal} GB</span></div><div class="progress"><span style="width:${pct(summary.memoryTotal ? summary.memoryUsed / summary.memoryTotal * 100 : 0)}"></span></div></article>
    <article class="metric-card accent-green"><div class="metric-head"><span class="metric-icon">✓</span><span class="pill success">Local policy</span></div><p class="metric-label">Isolation model</p><div class="metric-value"><strong>DIRECT</strong><span>assignment</span></div><div class="metric-foot">No Proxmox pools required</div></article>
  </section>`;
}

function activityMarkup(items = []) {
  if (!items.length) return emptyState("◷", "No activity yet", "Actions will appear here as they happen.");
  return `<div class="activity-list">${items.map((item) => `<div class="activity-item"><span class="activity-icon ${item.action.includes("failed") ? "warning" : ""}">${item.actorRole === "admin" ? "◇" : "✓"}</span><span class="activity-copy"><strong>${escapeHtml(activityLabel(item.action))}</strong><small>${escapeHtml(item.displayName || (item.actorRole === "system" ? "Nimbus" : "Account user"))}${item.resourceId ? ` · ${escapeHtml(item.resourceId)}` : ""}</small></span><span class="activity-time">${escapeHtml(formatDate(item.createdAt))}</span></div>`).join("")}</div>`;
}

function activityLabel(action) {
  return String(action || "activity").split(".").map((part) => part.replace(/_/g, " ")).join(" · ").replace(/^./, (value) => value.toUpperCase());
}

function renderOverview() {
  const resources = filteredResources().slice(0, 6);
  els.viewRoot.innerHTML = `${metricCards()}<section class="layout-grid overview-primary"><article class="panel"><header class="panel-header"><div><h2>${state.user.role === "admin" ? "Infrastructure inventory" : "Your infrastructure"}</h2><p>Individually assigned guests, resolved by the panel.</p></div><a class="text-link" href="#instances">View all →</a></header>${resourceTable(resources, { compact: true })}</article><aside class="panel"><header class="panel-header"><div><h2>Recent activity</h2><p>Audited account events.</p></div></header>${activityMarkup(state.dashboard.activity.items)}</aside></section>`;
}

function renderInstances() {
  const resources = filteredResources();
  els.viewRoot.innerHTML = resources.length ? `<section class="instance-grid">${resources.map((resource) => `<article class="instance-card"><div class="card-title">${resourceIdentity(resource)}${statusMarkup(resource)}</div><div class="instance-stats"><div class="mini-stat"><small>CPU</small><strong>${pct(resource.cpu)}</strong></div><div class="mini-stat"><small>Memory</small><strong>${resource.memoryUsed} / ${resource.memory} GB</strong></div><div class="mini-stat"><small>Storage</small><strong>${resource.storageUsed} / ${resource.storage} GB</strong></div><div class="mini-stat"><small>Address</small><strong>${escapeHtml(resource.ip || "Unavailable")}</strong></div></div><div class="instance-actions">${actionButtons(resource)}</div></article>`).join("")}</section>` : emptyState("▤", "No resources assigned", "Ask an administrator to assign a VM or container directly to your customer account.");
}

function detailSkeleton() {
  return `<div class="instance-detail-skeleton"><div class="skeleton detail-hero-skeleton"></div><div class="skeleton-grid metrics"><div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div></div><div class="skeleton detail-panel-skeleton"></div></div>`;
}

function detailActionButtons(resource) {
  const pending = activeTask(resource.id);
  if (pending) {
    return `<button class="button secondary task-running" disabled><span class="button-spinner" aria-hidden="true"></span>${escapeHtml(actionLabel(pending.action))}…</button>${can(resource, "console") ? `<button class="button secondary" data-console="${escapeHtml(resource.id)}">Open console</button>` : ""}`;
  }
  const actions = resource.status === "running"
    ? [["shutdown", "Shutdown", "secondary"], ["reboot", "Reboot", "primary"], ["suspend", "Suspend", "secondary"], ["stop", "Force stop", "danger"], ["reset", "Force reset", "danger"]]
    : resource.status === "suspended"
      ? [["resume", "Resume", "primary"], ["stop", "Force stop", "danger"]]
      : [["start", "Start", "primary"]];
  return `${actions.filter(([permission]) => can(resource, permission)).map(([action, label, style]) => `<button class="button ${style}" data-action="${action}" data-resource="${escapeHtml(resource.id)}">${label}</button>`).join("")}${can(resource, "console") ? `<button class="button secondary" data-console="${escapeHtml(resource.id)}">Open console</button>` : ""}`;
}

function instanceTasksMarkup(tasks = []) {
  if (!tasks.length) return `<div class="detail-empty"><span>◷</span><strong>No actions yet</strong><small>Power and maintenance tasks will appear here.</small></div>`;
  return `<div class="task-list">${tasks.slice(0, 10).map((task) => {
    const stateLabel = task.completed ? (task.success ? "Completed" : "Failed") : "In progress";
    const icon = task.completed ? (task.success ? "✓" : "!") : `<span class="button-spinner" aria-hidden="true"></span>`;
    return `<article class="task-item ${escapeHtml(task.state)}"><span class="task-state-icon">${icon}</span><span class="task-copy"><strong>${escapeHtml(actionName(task.action))}</strong><small>${escapeHtml(task.message || stateLabel)}</small></span><span class="task-meta"><strong>${escapeHtml(stateLabel)}</strong><small>${escapeHtml(formatRelative(task.completedAt || task.createdAt))}</small></span></article>`;
  }).join("")}</div>`;
}

function networkDetailsMarkup(network, resource) {
  const addresses = network?.addresses || [];
  if (!addresses.length) {
    const message = network?.status === "stopped"
      ? "Network addresses are unavailable while the guest is stopped."
      : network?.status === "permission_required"
        ? "The Proxmox token needs guest-agent audit permission to read addresses."
        : "No guest address was reported. QEMU guests need the QEMU Guest Agent for live network discovery.";
    return `<div class="detail-empty compact"><span>⌘</span><strong>Address unavailable</strong><small>${escapeHtml(message)}</small></div>`;
  }
  return `<div class="address-list">${addresses.map((address) => `<div class="address-row"><span><small>${escapeHtml(address.interface || "interface")} · ${escapeHtml(address.family || "IP")}</small><strong>${escapeHtml(address.address)}${address.prefix ? `/${address.prefix}` : ""}</strong></span><button class="copy-button" type="button" data-copy="${escapeHtml(address.address)}" aria-label="Copy ${escapeHtml(address.address)}">Copy</button></div>`).join("")}</div><div class="network-location"><span><small>Cluster</small><strong>${escapeHtml(resource.clusterName)}</strong></span><span><small>Node</small><strong>${escapeHtml(resource.node)}</strong></span></div>`;
}

function configurationMarkup(config = {}, resource) {
  const preferred = [
    ["cores", "CPU cores"],
    ["sockets", "Sockets"],
    ["memory", "Configured memory"],
    ["onboot", "Start at boot"],
    ["ostype", "Guest OS"],
    ["bios", "Firmware"],
    ["arch", "Architecture"],
    ["protection", "Protection"],
  ];
  const rows = preferred.filter(([key]) => config[key] !== undefined).map(([key, label]) => {
    let value = config[key];
    if (key === "memory") value = `${Math.round(Number(value) / 1024 * 10) / 10} GB`;
    if (["onboot", "protection"].includes(key)) value = Number(value) ? "Enabled" : "Disabled";
    return `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`;
  });
  rows.unshift(
    `<div><dt>Guest type</dt><dd>${escapeHtml(resource.type.toUpperCase())}</dd></div>`,
    `<div><dt>VMID</dt><dd>${resource.vmid}</dd></div>`,
  );
  return `<dl class="instance-facts">${rows.join("")}</dl>`;
}

function historyPanelMarkup(history, timeframe, loading) {
  const ranges = [["hour", "1 hour"], ["day", "24 hours"], ["week", "7 days"], ["month", "30 days"]];
  const controls = `<select class="history-range" data-history-timeframe aria-label="Usage history range" ${loading ? "disabled" : ""}>${ranges.map(([value, label]) => `<option value="${value}" ${value === timeframe ? "selected" : ""}>${label}</option>`).join("")}</select>`;
  if (loading) return `<header class="panel-header"><div><h2>Usage history</h2><p>Loading Proxmox RRD statistics.</p></div>${controls}</header><div class="chart-loading"><span class="spinner"></span>Loading history</div>`;
  if (!history?.available || !history.points?.length) {
    return `<header class="panel-header"><div><h2>Usage history</h2><p>CPU and memory over time.</p></div>${controls}</header><div class="detail-empty"><span>⌁</span><strong>History unavailable</strong><small>${history?.reason === "permission_not_enabled" ? "Usage statistics are not enabled for this assignment." : "Proxmox has not returned enough history points yet."}</small></div>`;
  }
  const latest = history.points.at(-1) || {};
  return `<header class="panel-header"><div><h2>Usage history</h2><p>Normalized Proxmox RRD statistics.</p></div>${controls}</header><div class="instance-chart-legend"><span><i class="legend-cpu"></i>CPU ${Math.round(Number(latest.cpu) || 0)}%</span><span><i class="legend-memory"></i>Memory ${Math.round(Number(latest.memory) || 0)}%</span></div><div class="instance-chart-wrap"><canvas id="instanceUsageChart" aria-label="CPU and memory usage history"></canvas><div class="chart-axis-labels"><span>${escapeHtml(formatDate(history.points[0]?.timestamp))}</span><span>${escapeHtml(formatDate(history.points.at(-1)?.timestamp))}</span></div></div>`;
}

function installationMediaMarkup(resource) {
  if (resource.type !== "qemu" || !resource.customerId || !can(resource, "iso_view")) return "";
  if (state.instance.mediaLoading && !state.instance.media) {
    return `<section class="panel installation-media-panel"><header class="panel-header"><div><h2>Installation media</h2><p>Loading your ISO library.</p></div></header><div class="chart-loading"><span class="spinner"></span>Loading media</div></section>`;
  }
  const media = state.instance.media;
  if (media?.error) {
    return `<section class="panel installation-media-panel"><header class="panel-header"><div><h2>Installation media</h2><p>Customer-owned ISO images.</p></div><button class="button secondary small" data-refresh-media>Retry</button></header><div class="notice warning"><span>!</span><span>${escapeHtml(friendlyError(media.error))}</span></div></section>`;
  }
  const policies = media?.policies || [];
  const images = media?.images || [];
  const mounted = media?.mounted || null;
  const upload = state.instance.upload;
  const processing = images.some((image) => ["uploading", "processing", "deleting"].includes(image.status));
  if (processing) scheduleMediaPolling();
  const uploadMarkup = can(resource, "iso_upload")
    ? (policies.length
      ? `<form class="iso-upload-form" id="isoUploadForm">
          <div class="field"><label for="isoFile">ISO image</label><input id="isoFile" name="isoFile" type="file" accept=".iso,application/x-iso9660-image" required ${upload ? "disabled" : ""}><small>The file streams directly to Proxmox; Nimbus does not keep a second copy.</small></div>
          <div class="field"><label for="isoPolicy">Destination</label><select id="isoPolicy" name="policyId" required ${upload ? "disabled" : ""}>${policies.map((policy) => `<option value="${escapeHtml(policy.id)}">${escapeHtml(policy.displayName)} · ${escapeHtml(formatBytes(policy.remainingBytes))} free</option>`).join("")}</select><small>Maximum per file: ${escapeHtml(formatBytes(Math.max(...policies.map((policy) => policy.maxUploadBytes))))}</small></div>
          <button class="button primary" type="submit" ${upload ? "disabled" : ""}>${upload ? "Uploading…" : "Upload ISO"}</button>
        </form>`
      : `<div class="notice warning"><span>!</span><span>An administrator must enable an ISO-capable Proxmox storage before uploads are available.</span></div>`)
    : "";
  const uploadProgress = upload ? `<div class="iso-upload-progress" aria-live="polite"><div><span><strong>${escapeHtml(upload.name)}</strong><small>${upload.status === "finishing" ? "Proxmox is finalizing the upload…" : `${upload.progress}% · ${escapeHtml(formatBytes(upload.loaded))} of ${escapeHtml(formatBytes(upload.total))}`}</small></span><b>${upload.progress}%</b></div><div class="usage-bar"><span id="isoUploadProgressBar" style="width:${pct(upload.progress)}"></span></div></div>` : "";
  const mountedMarkup = mounted
    ? `<div class="mounted-media"><span class="media-icon">◎</span><span><small>Mounted in ${escapeHtml(mounted.driveSlot)}</small><strong>${escapeHtml(mounted.originalName || mounted.fileName)}</strong><em>Mounted ${escapeHtml(formatRelative(mounted.mountedAt))}</em></span>${can(resource, "iso_mount") ? `<button class="button secondary small" data-eject-iso>Eject</button>` : ""}</div>`
    : `<div class="mounted-media empty"><span class="media-icon">○</span><span><small>Virtual CD/DVD drive</small><strong>No ISO mounted</strong><em>Select a ready image from the library below.</em></span></div>`;
  const library = images.length
    ? `<div class="iso-library">${images.map((image) => {
      const isMounted = mounted?.isoImageId === image.id;
      const busy = ["uploading", "processing", "deleting"].includes(image.status);
      const canRemove = image.status === "error" ? can(resource, "iso_upload") : can(resource, "iso_delete") && image.allowDelete;
      return `<article class="iso-library-item"><span class="media-icon">◉</span><span class="iso-copy"><strong>${escapeHtml(image.originalName)}</strong><small>${escapeHtml(formatBytes(image.sizeBytes))} · ${escapeHtml(image.storageId)} · ${escapeHtml(formatDate(image.createdAt))}</small></span><span class="iso-state ${escapeHtml(image.status)}">${busy ? `<i class="button-spinner"></i>` : ""}${escapeHtml(image.status)}</span><div class="row-buttons">${can(resource, "iso_mount") && image.status === "ready" && !isMounted ? `<button class="row-button" data-mount-iso="${escapeHtml(image.id)}" ${mounted ? "disabled" : ""}>Mount</button>` : ""}${isMounted ? `<span class="pill success">Mounted</span>` : ""}${canRemove && !isMounted && !busy ? `<button class="row-button danger" data-delete-iso="${escapeHtml(image.id)}" ${image.status === "error" ? "data-dismiss-iso" : ""}>${image.status === "error" ? "Dismiss" : "Delete"}</button>` : ""}</div></article>`;
    }).join("")}</div>`
    : `<div class="detail-empty compact"><span>◉</span><strong>No ISO images yet</strong><small>Upload installation media to this customer-owned library.</small></div>`;
  return `<section class="panel installation-media-panel">
    <header class="panel-header"><div><h2>Installation media</h2><p>Private ISO library for this customer and cluster.</p></div><span class="pill ${processing ? "warning" : ""}">${processing ? "Processing" : `${images.length} images`}</span></header>
    <div class="installation-media-body">${mountedMarkup}${uploadMarkup}${uploadProgress}${library}</div>
  </section>`;
}

function renderInstanceDetail(resourceId) {
  const resource = (state.dashboard?.resources || []).find((item) => item.id === resourceId)
    || state.admin?.resources?.find((item) => item.id === resourceId);
  if (!resource) {
    els.viewRoot.innerHTML = emptyState("!", "Instance unavailable", "This resource is not assigned to your account.");
    return;
  }
  if (state.instance.resourceId !== resourceId) {
    state.instance = { resourceId, details: null, history: null, timeframe: "day", loading: true, refreshing: false, historyLoading: false, media: null, mediaLoading: false, upload: null, error: null };
    els.viewRoot.innerHTML = detailSkeleton();
    queueMicrotask(() => loadInstanceDetails(resourceId));
    return;
  }
  if (state.instance.loading && !state.instance.details) {
    els.viewRoot.innerHTML = detailSkeleton();
    return;
  }
  if (state.instance.error && !state.instance.details) {
    els.viewRoot.innerHTML = `<section class="panel">${emptyState("!", "Instance details unavailable", friendlyError(state.instance.error))}<div class="detail-retry"><button class="button primary" data-retry-instance="${escapeHtml(resourceId)}">Try again</button></div></section>`;
    return;
  }

  const details = state.instance.details || {};
  const network = details.network || {};
  const tasks = resourceTasks(resourceId);
  const pending = activeTask(resourceId);
  const memoryPercent = percent(resource.memoryUsed, resource.memory);
  const storagePercent = percent(resource.storageUsed, resource.storage);
  const primaryIp = network.primaryIp || resource.ip;
  const networkLatest = state.instance.history?.points?.at(-1) || {};
  els.viewRoot.innerHTML = `<div class="instance-detail">
    <a class="detail-back" href="#instances">← All instances</a>
    <section class="instance-hero-card">
      <div class="instance-hero-main">
        ${resourceIdentity(resource)}
        <div class="instance-hero-status">${statusMarkup(resource)}${state.instance.refreshing ? `<span class="refreshing-label"><span class="button-spinner"></span>Refreshing</span>` : ""}</div>
      </div>
      <div class="instance-hero-actions">${detailActionButtons(resource)}</div>
      ${pending ? `<div class="task-progress-banner"><span class="button-spinner" aria-hidden="true"></span><span><strong>${escapeHtml(actionLabel(pending.action))} this instance</strong><small>Nimbus is following the Proxmox task automatically. Other power actions are paused until it finishes.</small></span><span>${escapeHtml(formatRelative(pending.createdAt))}</span></div>` : ""}
    </section>

    <section class="instance-metric-grid">
      <article><span class="detail-metric-icon cpu">⌁</span><span><small>CPU usage</small><strong>${Math.round(resource.cpu)}%</strong><em>${resource.vcpu} vCPU</em></span><div class="detail-meter"><i style="width:${pct(resource.cpu)}"></i></div></article>
      <article><span class="detail-metric-icon memory">◫</span><span><small>Memory</small><strong>${resource.memoryUsed} GB</strong><em>of ${resource.memory} GB</em></span><div class="detail-meter memory"><i style="width:${pct(memoryPercent)}"></i></div></article>
      <article><span class="detail-metric-icon storage">▰</span><span><small>Storage</small><strong>${resource.storageUsed} GB</strong><em>of ${resource.storage} GB</em></span><div class="detail-meter storage"><i style="width:${pct(storagePercent)}"></i></div></article>
      <article><span class="detail-metric-icon uptime">◷</span><span><small>Uptime</small><strong>${escapeHtml(formatUptime(resource.uptime))}</strong><em>${resource.status === "running" ? "Currently online" : escapeHtml(resource.status)}</em></span></article>
    </section>

    <section class="instance-detail-grid primary">
      <article class="panel usage-history-panel">${historyPanelMarkup(state.instance.history, state.instance.timeframe, state.instance.historyLoading)}</article>
      <article class="panel">
        <header class="panel-header"><div><h2>Instance information</h2><p>Safe, allowlisted configuration.</p></div><span class="pill">${escapeHtml(resource.type.toUpperCase())} ${resource.vmid}</span></header>
        ${configurationMarkup(details.config, resource)}
      </article>
    </section>

    <section class="instance-detail-grid secondary">
      <article class="panel">
        <header class="panel-header"><div><h2>Network</h2><p>${primaryIp ? `Primary address: ${escapeHtml(primaryIp)}` : "Guest-reported addresses."}</p></div>${primaryIp ? `<button class="copy-button" type="button" data-copy="${escapeHtml(primaryIp)}">Copy IP</button>` : ""}</header>
        ${networkDetailsMarkup(network, resource)}
        ${state.instance.history?.available ? `<div class="network-rate-strip"><span><small>Latest inbound</small><strong>${escapeHtml(formatRate(networkLatest.netIn))}</strong></span><span><small>Latest outbound</small><strong>${escapeHtml(formatRate(networkLatest.netOut))}</strong></span></div>` : ""}
      </article>
      <article class="panel">
        <header class="panel-header"><div><h2>Recent tasks</h2><p>Live status from Proxmox.</p></div><span class="pill ${pending ? "warning" : "success"}">${pending ? "Running" : "Up to date"}</span></header>
        ${instanceTasksMarkup(tasks)}
      </article>
    </section>
    ${installationMediaMarkup(resource)}
  </div>`;
  requestAnimationFrame(drawInstanceChart);
}

async function loadInstanceDetails(resourceId, { quiet = false } = {}) {
  const resource = (state.dashboard?.resources || []).find((item) => item.id === resourceId)
    || state.admin?.resources?.find((item) => item.id === resourceId);
  if (!resource) return;
  if (quiet) state.instance.refreshing = true;
  else state.instance.loading = true;
  state.instance.mediaLoading = resource.type === "qemu" && Boolean(resource.customerId) && can(resource, "iso_view");
  state.instance.error = null;
  try {
    const historyRequest = can(resource, "view_usage")
      ? apiFetch(`/api/v1/resources/${encodeURIComponent(resourceId)}/history?timeframe=${encodeURIComponent(state.instance.timeframe)}`)
          .then((result) => result.history)
          .catch((error) => ({ available: false, reason: error.code || "history_unavailable", points: [] }))
      : Promise.resolve({ available: false, reason: "permission_not_enabled", points: [] });
    const mediaRequest = resource.type === "qemu" && resource.customerId && can(resource, "iso_view")
      ? apiFetch(`/api/v1/resources/${encodeURIComponent(resourceId)}/media`)
          .catch((error) => ({ error }))
      : Promise.resolve(null);
    const [details, history, media] = await Promise.all([
      apiFetch(`/api/v1/resources/${encodeURIComponent(resourceId)}`),
      historyRequest,
      mediaRequest,
    ]);
    if (state.instance.resourceId !== resourceId) return;
    state.instance.details = details;
    state.instance.history = history;
    state.instance.media = media;
    state.instance.error = null;
    if (details.tasks?.length) {
      for (const task of details.tasks) mergeTask(task);
    }
  } catch (error) {
    if (state.instance.resourceId === resourceId) state.instance.error = error;
  } finally {
    if (state.instance.resourceId === resourceId) {
      state.instance.loading = false;
      state.instance.refreshing = false;
      state.instance.mediaLoading = false;
      if (state.currentView === "instance") renderInstanceDetail(resourceId);
      scheduleTaskPolling();
    }
  }
}

async function loadInstanceMedia({ quiet = false } = {}) {
  const resourceId = state.instance.resourceId;
  const resource = state.dashboard?.resources.find((item) => item.id === resourceId)
    || state.admin?.resources?.find((item) => item.id === resourceId);
  if (!resource || resource.type !== "qemu" || !resource.customerId || !can(resource, "iso_view")) return;
  if (!quiet) {
    state.instance.mediaLoading = true;
    renderInstanceDetail(resourceId);
  }
  try {
    state.instance.media = await apiFetch(`/api/v1/resources/${encodeURIComponent(resourceId)}/media`);
  } catch (error) {
    state.instance.media = { error };
  } finally {
    state.instance.mediaLoading = false;
    if (state.currentView === "instance" && state.instance.resourceId === resourceId) renderInstanceDetail(resourceId);
  }
}

function scheduleMediaPolling() {
  if (mediaPollTimer || state.instance.upload || state.currentView !== "instance") return;
  mediaPollTimer = setTimeout(async () => {
    mediaPollTimer = null;
    if (state.currentView !== "instance") return;
    await loadInstanceMedia({ quiet: true });
    const pending = state.instance.media?.images?.some((image) => ["uploading", "processing", "deleting"].includes(image.status));
    if (pending) scheduleMediaPolling();
  }, document.visibilityState === "visible" ? 2500 : 7000);
}

async function loadInstanceHistory(timeframe) {
  const resourceId = state.instance.resourceId;
  const resource = state.dashboard?.resources.find((item) => item.id === resourceId);
  if (!resource || !can(resource, "view_usage") || state.instance.historyLoading) return;
  state.instance.timeframe = timeframe;
  state.instance.historyLoading = true;
  renderInstanceDetail(resourceId);
  try {
    const result = await apiFetch(`/api/v1/resources/${encodeURIComponent(resourceId)}/history?timeframe=${encodeURIComponent(timeframe)}`);
    if (state.instance.resourceId === resourceId && state.instance.timeframe === timeframe) state.instance.history = result.history;
  } catch (error) {
    if (state.instance.resourceId === resourceId) state.instance.history = { available: false, reason: error.code || "history_unavailable", points: [] };
  } finally {
    if (state.instance.resourceId === resourceId) {
      state.instance.historyLoading = false;
      renderInstanceDetail(resourceId);
    }
  }
}

function drawInstanceChart() {
  const canvas = document.getElementById("instanceUsageChart");
  const points = state.instance.history?.points || [];
  if (!canvas || points.length < 2) return;
  const rect = canvas.getBoundingClientRect();
  const ratio = Math.min(2, window.devicePixelRatio || 1);
  canvas.width = Math.max(1, Math.round(rect.width * ratio));
  canvas.height = Math.round(220 * ratio);
  const context = canvas.getContext("2d");
  context.scale(ratio, ratio);
  const width = rect.width;
  const height = 220;
  const padding = { top: 12, right: 8, bottom: 10, left: 30 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;
  context.clearRect(0, 0, width, height);
  context.lineWidth = 1;
  context.font = "10px Inter, sans-serif";
  context.textAlign = "right";
  context.textBaseline = "middle";
  for (const value of [0, 25, 50, 75, 100]) {
    const y = padding.top + chartHeight - chartHeight * value / 100;
    context.strokeStyle = "#e8ebf2";
    context.beginPath();
    context.moveTo(padding.left, y);
    context.lineTo(width - padding.right, y);
    context.stroke();
    context.fillStyle = "#969eb0";
    context.fillText(`${value}%`, padding.left - 6, y);
  }
  const drawLine = (key, color) => {
    context.strokeStyle = color;
    context.lineWidth = 2.5;
    context.lineJoin = "round";
    context.lineCap = "round";
    context.beginPath();
    points.forEach((point, index) => {
      const x = padding.left + chartWidth * index / (points.length - 1);
      const value = Math.max(0, Math.min(100, Number(point[key]) || 0));
      const y = padding.top + chartHeight - chartHeight * value / 100;
      if (index === 0) context.moveTo(x, y); else context.lineTo(x, y);
    });
    context.stroke();
  };
  drawLine("cpu", "#5d68ec");
  drawLine("memory", "#36aa82");
}

function renderNetwork() {
  const resources = filteredResources();
  els.viewRoot.innerHTML = resources.length ? `<section class="network-grid">${resources.map((resource) => `<article class="network-card"><div class="card-title">${resourceIdentity(resource)}${statusMarkup(resource)}</div><ul class="network-addresses"><li><small>Primary address</small><span>${escapeHtml(resource.ip || "Unavailable")}</span></li><li><small>Cluster / node</small><span>${escapeHtml(resource.clusterId)} / ${escapeHtml(resource.node)}</span></li><li><small>Guest identity</small><span>${resource.type.toUpperCase()} ${resource.vmid}</span></li></ul></article>`).join("")}</section>` : emptyState("⌘", "No network information", "Assigned resources will appear here.");
}

function renderActivity() {
  els.viewRoot.innerHTML = `<section class="panel"><header class="panel-header"><div><h2>Audit trail</h2><p>Recent actions visible to this account.</p></div><span class="pill">Append-only</span></header>${activityMarkup(state.dashboard.activity.items)}</section>`;
}

function renderSettings() {
  els.viewRoot.innerHTML = `<section class="layout-grid equal"><form class="panel form-panel" id="profileForm"><h2>Profile</h2><p>Update your display name.</p><div class="form-grid"><div class="field full"><label for="settingsName">Display name</label><input id="settingsName" name="displayName" maxlength="100" required value="${escapeHtml(state.user.displayName)}"></div><div class="field full"><label>Email address</label><input disabled value="${escapeHtml(state.user.email)}"></div></div><div class="form-actions"><button class="button primary">Save profile</button><p class="form-message"></p></div></form><form class="panel form-panel" id="passwordForm"><h2>Password</h2><p>Changing your password revokes all active sessions.</p><div class="form-grid"><div class="field full"><label for="currentPassword">Current password</label><input id="currentPassword" type="password" name="currentPassword" required autocomplete="current-password"></div><div class="field full"><label for="newPassword">New password</label><input id="newPassword" type="password" name="password" minlength="12" required autocomplete="new-password"></div></div><div class="form-actions"><button class="button primary">Change password</button><p class="form-message"></p></div></form></section>`;
}

function adminTabs() {
  const tabs = [["inventory", "Inventory"], ["customers", "Customers"], ["clusters", "Clusters"], ["media", "ISO storage"], ["users", "Users"], ["audit", "Audit log"]];
  return `<section class="panel admin-tab-shell"><div class="admin-tabs" role="tablist">${tabs.map(([id, label]) => `<button class="admin-tab ${state.adminTab === id ? "active" : ""}" data-admin-tab="${id}">${label}</button>`).join("")}</div></section>`;
}

function renderAdminInventory() {
  const resources = filteredResources(state.admin.resources);
  return `<section class="admin-summary-grid"><article><strong>${state.admin.resources.length}</strong><span>discovered guests</span></article><article><strong>${state.admin.resources.filter((resource) => resource.customerId).length}</strong><span>direct assignments</span></article><article><strong>${state.admin.clusters.length}</strong><span>Proxmox clusters</span></article><article class="safe"><strong>0</strong><span>customer pools</span></article></section><section class="panel"><header class="panel-header"><div><h2>Resource inventory</h2><p>Assign any QEMU VM or LXC container directly—across nodes and clusters.</p></div><button class="button secondary" data-sync-all>Sync clusters</button></header>${resourceTable(resources, { admin: true })}</section>`;
}

function renderAdminCustomers() {
  const customers = state.admin.customers;
  return `<section class="layout-grid"><form class="panel form-panel" id="createCustomerForm"><h2>Create customer</h2><p>Customer records live in Nimbus, not in Proxmox pools.</p><div class="form-grid"><div class="field"><label for="customerId">Customer ID</label><input id="customerId" name="id" required pattern="[a-z0-9][a-z0-9_-]{1,63}" placeholder="acme"></div><div class="field"><label for="customerName">Company name</label><input id="customerName" name="name" maxlength="100" required></div><div class="field"><label for="customerPlan">Plan</label><input id="customerPlan" name="planName" value="Managed infrastructure"></div><div class="field"><label for="customerSupport">Support email</label><input id="customerSupport" type="email" name="supportEmail"></div></div><div class="form-actions"><button class="button primary">Create customer</button><p class="form-message"></p></div></form><article class="panel policy-card"><header class="panel-header"><div><h2>Isolation boundary</h2><p>Enforced on every backend request.</p></div></header><div class="policy-flow"><span>Signed-in user</span><i>→</i><span>Local assignment</span><i>→</i><span>Permission check</span><i>→</i><span>Proxmox API</span></div><div class="notice"><span>✓</span><span>Changing a VMID in the browser cannot bypass the local assignment and permission lookup.</span></div></article></section><section class="panel" style="margin-top:18px"><header class="panel-header"><div><h2>Customer accounts</h2><p>${plural(customers.length, "customer")}</p></div></header>${customers.length ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Customer</th><th>Resources</th><th>Users</th><th>Plan</th><th>Status</th><th><span class="visually-hidden">Actions</span></th></tr></thead><tbody>${customers.map((customer) => `<tr><td><div class="server-copy"><strong>${escapeHtml(customer.name)}</strong><small>${escapeHtml(customer.id)}</small></div></td><td>${customer.resourceCount}</td><td>${customer.userCount}</td><td>${escapeHtml(customer.planName)}</td><td><span class="status-badge ${customer.status === "disabled" ? "disabled" : ""}">${escapeHtml(customer.status)}</span></td><td><div class="row-buttons"><button class="row-button" data-edit-customer="${escapeHtml(customer.id)}">Edit</button><button class="row-button danger" data-delete-customer="${escapeHtml(customer.id)}">Delete</button></div></td></tr>`).join("")}</tbody></table></div>` : emptyState("◇", "No customers yet", "Create the first customer account above.")}</section>`;
}

function renderAdminClusters() {
  const clusters = state.admin.clusters;
  return `<section class="layout-grid"><form class="panel form-panel" id="createClusterForm" data-admin-create="cluster"><h2>Add Proxmox cluster</h2><p>Nimbus stores one central API token encrypted at rest.</p><div class="form-grid"><div class="field"><label for="clusterId">Cluster ID</label><input id="clusterId" name="id" required pattern="[a-z0-9][a-z0-9_-]{1,63}" placeholder="production-eu"></div><div class="field"><label for="clusterName">Display name</label><input id="clusterName" name="name" required></div><div class="field full"><label for="clusterUrl">API URL</label><input id="clusterUrl" name="apiUrl" type="url" required placeholder="https://pve.example.com:8006"></div><div class="field"><label for="clusterTokenId">Token ID</label><input id="clusterTokenId" name="tokenId" required placeholder="nimbus@pve!panel"></div><div class="field"><label for="clusterTokenSecret">Token secret</label><input id="clusterTokenSecret" name="tokenSecret" type="password" required autocomplete="new-password"></div></div><div class="form-actions"><button class="button primary" type="submit">Add cluster</button><p class="form-message" role="status" aria-live="polite"></p></div></form><article class="panel policy-card"><header class="panel-header"><div><h2>Least privilege</h2><p>Recommended service-account access.</p></div></header><div class="permission-code">VM.Audit · VM.PowerMgmt<br>VM.Console · VM.Snapshot<br>VM.Config.* (selected only)</div><div class="notice warning"><span>!</span><span>Grant only the operations enabled in your Nimbus assignment policies. Never grant Administrator.</span></div></article></section><section class="cluster-grid">${clusters.map((cluster) => `<article class="cluster-card"><div class="cluster-head"><span class="cluster-icon">◇</span><span><strong>${escapeHtml(cluster.name)}</strong><small>${escapeHtml(cluster.apiUrl)}</small></span>${cluster.status === "active" ? `<span class="pill success">Healthy</span>` : `<span class="pill warning">${escapeHtml(cluster.status)}</span>`}</div><div class="cluster-facts"><span><small>Resources</small><strong>${cluster.resourceCount}</strong></span><span><small>Nodes</small><strong>${cluster.nodeCount}</strong></span><span><small>Last sync</small><strong>${cluster.lastSyncAt ? formatDate(cluster.lastSyncAt) : "Never"}</strong></span></div><div class="cluster-actions"><button class="button secondary small" data-edit-cluster="${escapeHtml(cluster.id)}">Edit</button><button class="button secondary small" data-test-cluster="${escapeHtml(cluster.id)}">Test</button><button class="button secondary small" data-sync-cluster="${escapeHtml(cluster.id)}">Sync now</button></div></article>`).join("")}</section>`;
}

function renderAdminMedia() {
  const clusters = state.admin.clusters.filter((cluster) => cluster.status !== "disabled");
  if (!state.isoClusterId || !clusters.some((cluster) => cluster.id === state.isoClusterId)) state.isoClusterId = clusters[0]?.id || null;
  const candidates = state.isoCandidates[state.isoClusterId] || [];
  const policies = state.admin.isoPolicies || [];
  const clusterOptions = clusters.map((cluster) => `<option value="${escapeHtml(cluster.id)}" ${cluster.id === state.isoClusterId ? "selected" : ""}>${escapeHtml(cluster.name)}</option>`).join("");
  const storageOptions = candidates.length
    ? candidates.map((candidate) => `<option value="${escapeHtml(candidate.storageId)}">${escapeHtml(candidate.storageId)} · ${candidate.shared ? "shared" : "node-local"} · ${escapeHtml(formatBytes(candidate.availableBytes))} free</option>`).join("")
    : `<option value="">Discover storage first</option>`;
  const form = clusters.length
    ? `<form class="panel form-panel iso-policy-form" id="createIsoPolicyForm" data-admin-create="iso-policy">
        <h2>Enable ISO uploads</h2><p>Choose an existing Proxmox storage that advertises ISO content.</p>
        <div class="form-grid">
          <div class="field"><label for="isoPolicyCluster">Cluster</label><select id="isoPolicyCluster" name="clusterId" data-iso-cluster>${clusterOptions}</select></div>
          <div class="field"><label>Storage discovery</label><button class="button secondary" type="button" data-discover-iso="${escapeHtml(state.isoClusterId)}">Discover ISO storage</button><small>Nimbus asks Proxmox which storage is active on each node.</small></div>
          <div class="field"><label for="isoPolicyStorage">Proxmox storage</label><select id="isoPolicyStorage" name="storageId" required ${candidates.length ? "" : "disabled"}>${storageOptions}</select></div>
          <div class="field"><label for="isoPolicyName">Customer-facing name</label><input id="isoPolicyName" name="displayName" required maxlength="100" value="Installation media"></div>
          <div class="field"><label for="isoMaxUpload">Maximum file size (GB)</label><input id="isoMaxUpload" name="maxUploadGb" type="number" min="1" step="1" value="8" required></div>
          <div class="field"><label for="isoQuota">Quota per customer (GB)</label><input id="isoQuota" name="quotaGb" type="number" min="1" step="1" value="25" required></div>
          <label class="policy-checkbox full"><input name="allowDelete" type="checkbox"><span><strong>Allow customers to delete their ISO files</strong><small>Optional. Proxmox requires the broader Datastore.Allocate privilege for deletion.</small></span></label>
        </div>
        <div class="form-actions"><button class="button primary" type="submit" ${candidates.length ? "" : "disabled"}>Enable storage</button><p class="form-message" role="status"></p></div>
      </form>`
    : `<section class="panel">${emptyState("◇", "Add a Proxmox cluster first", "ISO policies are attached to an existing cluster and storage.")}</section>`;
  const guidance = `<article class="panel policy-card"><header class="panel-header"><div><h2>Service-account access</h2><p>Keep deletion disabled unless it is needed.</p></div></header><div class="permission-code">Datastore.Audit<br>Datastore.AllocateTemplate<br>VM.Config.CDROM<br><span>Optional: Datastore.Allocate</span></div><div class="notice"><span>✓</span><span>Uploads stream from the browser through Nimbus to Proxmox. Nimbus stores ownership metadata, not a duplicate ISO file.</span></div></article>`;
  const policyList = policies.length
    ? `<section class="iso-policy-grid">${policies.map((policy) => `<article class="cluster-card iso-policy-card"><div class="cluster-head"><span class="cluster-icon">◉</span><span><strong>${escapeHtml(policy.displayName)}</strong><small>${escapeHtml(policy.clusterName)} · ${escapeHtml(policy.storageId)}</small></span><span class="pill ${policy.status === "active" ? "success" : "warning"}">${escapeHtml(policy.status)}</span></div><div class="cluster-facts"><span><small>Per file</small><strong>${escapeHtml(formatBytes(policy.maxUploadBytes))}</strong></span><span><small>Per customer</small><strong>${escapeHtml(formatBytes(policy.customerQuotaBytes))}</strong></span><span><small>Images</small><strong>${policy.imageCount}</strong></span></div><div class="policy-delete-state ${policy.allowDelete ? "enabled" : ""}"><span>${policy.allowDelete ? "Customer deletion enabled" : "Customer deletion disabled"}</span></div><div class="cluster-actions"><button class="button secondary small" data-edit-iso-policy="${escapeHtml(policy.id)}">Edit</button><button class="button secondary small" data-delete-iso-policy="${escapeHtml(policy.id)}">Delete policy</button></div></article>`).join("")}</section>`
    : `<section class="panel">${emptyState("◉", "No ISO storage enabled", "Discover ISO-capable Proxmox storage and create the first policy above.")}</section>`;
  return `<section class="layout-grid">${form}${guidance}</section>${policyList}`;
}

function customerOptions(selected = "") {
  return `<option value="">No customer</option>${state.admin.customers.map((customer) => `<option value="${escapeHtml(customer.id)}" ${customer.id === selected ? "selected" : ""}>${escapeHtml(customer.name)}</option>`).join("")}`;
}

function renderAdminUsers() {
  const users = state.admin.users;
  return `<section class="layout-grid"><form class="panel form-panel" id="createUserForm"><h2>Create user</h2><p>Customers receive Nimbus credentials only.</p><div class="form-grid"><div class="field"><label for="userName">Display name</label><input id="userName" name="displayName" required></div><div class="field"><label for="userEmail">Email</label><input id="userEmail" name="email" type="email" required></div><div class="field"><label for="userRole">Role</label><select id="userRole" name="role"><option value="customer">Customer</option><option value="admin">Administrator</option></select></div><div class="field"><label for="userCustomer">Customer</label><select id="userCustomer" name="customerId">${customerOptions()}</select></div><div class="field full"><label for="userPassword">Temporary password</label><input id="userPassword" name="password" type="password" minlength="12" required autocomplete="new-password"></div></div><div class="form-actions"><button class="button primary">Create user</button><p class="form-message"></p></div></form><article class="panel policy-card"><header class="panel-header"><div><h2>Role boundary</h2><p>Server-enforced access levels.</p></div></header><div class="notice"><span>♙</span><span><strong>Customer:</strong> assigned resources and allowed operations only.</span></div><div class="notice warning"><span>◇</span><span><strong>Administrator:</strong> cluster, customer, user, assignment, and audit control.</span></div></article></section><section class="panel" style="margin-top:18px"><header class="panel-header"><div><h2>Users</h2><p>${plural(users.length, "account")}</p></div></header><div class="table-wrap"><table class="data-table"><thead><tr><th>User</th><th>Customer</th><th>Role</th><th>Status</th><th><span class="visually-hidden">Actions</span></th></tr></thead><tbody>${users.map((user) => `<tr><td><div class="server-name"><span class="server-avatar">${escapeHtml(initials(user.displayName))}</span><span class="server-copy"><strong>${escapeHtml(user.displayName)}</strong><small>${escapeHtml(user.email)}</small></span></div></td><td>${escapeHtml(user.customerName || "Global")}</td><td><span class="role-badge ${user.role === "admin" ? "platform" : ""}">${escapeHtml(user.role)}</span></td><td><span class="status-badge ${user.status === "disabled" ? "disabled" : ""}">${escapeHtml(user.status)}</span></td><td><div class="row-buttons"><button class="row-button" data-edit-user="${escapeHtml(user.id)}">Edit</button><button class="row-button danger" data-delete-user="${escapeHtml(user.id)}">Delete</button></div></td></tr>`).join("")}</tbody></table></div></section>`;
}

function renderAdminAudit() {
  const items = state.admin.audit.items;
  return `<section class="panel"><header class="panel-header"><div><h2>Platform audit log</h2><p>Administrator and customer actions across all accounts.</p></div><span class="pill">${state.admin.audit.total} events</span></header><div class="table-wrap"><table class="data-table"><thead><tr><th>Time</th><th>Actor</th><th>Customer</th><th>Action</th><th>Resource</th></tr></thead><tbody>${items.map((item) => `<tr><td>${escapeHtml(formatDate(item.createdAt))}</td><td>${escapeHtml(item.displayName || item.actorRole)}</td><td>${escapeHtml(item.customerName || "Platform")}</td><td>${escapeHtml(activityLabel(item.action))}</td><td>${escapeHtml(item.resourceId || "—")}</td></tr>`).join("")}</tbody></table></div></section>`;
}

function renderAdmin() {
  const renderers = { inventory: renderAdminInventory, customers: renderAdminCustomers, clusters: renderAdminClusters, media: renderAdminMedia, users: renderAdminUsers, audit: renderAdminAudit };
  els.viewRoot.innerHTML = `${adminTabs()}<div class="admin-section">${renderers[state.adminTab]()}</div>`;
}

const renderers = { overview: renderOverview, instances: renderInstances, network: renderNetwork, activity: renderActivity, settings: renderSettings, admin: renderAdmin };

function route() {
  if (!state.user || !state.dashboard) return;
  const rawRoute = location.hash.replace(/^#/, "") || "overview";
  const instanceMatch = rawRoute.match(/^instance\/(.+)$/);
  let resourceId = null;
  if (instanceMatch) {
    try { resourceId = decodeURIComponent(instanceMatch[1]); } catch { resourceId = null; }
  }
  let view = resourceId ? "instance" : rawRoute;
  if (!views[view]) view = "overview";
  if (view === "admin" && state.user.role !== "admin") view = "overview";
  state.currentView = view;
  if (view !== "instance" && mediaPollTimer) {
    clearTimeout(mediaPollTimer);
    mediaPollTimer = null;
  }
  const resource = resourceId
    ? (state.dashboard.resources || []).find((item) => item.id === resourceId) || state.admin?.resources?.find((item) => item.id === resourceId)
    : null;
  const [defaultTitle, description] = views[view];
  const title = resource ? (resource.displayName || resource.name) : defaultTitle;
  els.pageTitle.textContent = title;
  els.pageDescription.textContent = description;
  els.currentSection.textContent = view === "instance" ? "Instance details" : title;
  els.todayLabel.textContent = new Intl.DateTimeFormat(undefined, { weekday: "long", month: "long", day: "numeric" }).format(new Date());
  document.querySelectorAll(".nav-item").forEach((link) => link.classList.toggle("active", link.dataset.view === (view === "instance" ? "instances" : view)));
  if (view === "admin" && !state.admin) {
    els.viewRoot.innerHTML = `<div class="loading-inline"><span class="spinner"></span>Loading control center</div>`;
    loadAdmin().then(renderAdmin).catch((error) => showToast("error", "Could not load", friendlyError(error)));
  } else if (view === "instance") renderInstanceDetail(resourceId);
  else renderers[view]();
  closeSidebar();
}

function formPayload(form) {
  return Object.fromEntries(new FormData(form).entries());
}

function openAssignment(resourceId) {
  const resource = state.admin.resources.find((item) => item.id === resourceId);
  if (!resource) return;
  els.editForm.dataset.kind = "assignment";
  els.editForm.dataset.id = resource.id;
  els.editDialogTitle.textContent = resource.customerId ? "Edit assignment policy" : "Assign resource";
  els.editDialogBody.innerHTML = `<div class="assignment-resource">${resourceIdentity(resource)}${statusMarkup(resource)}</div><div class="field"><label for="assignmentCustomer">Customer</label><select id="assignmentCustomer" name="customerId" required>${customerOptions(resource.customerId || "")}</select></div><div class="field"><label for="assignmentName">Optional display name</label><input id="assignmentName" name="displayName" value="${escapeHtml(resource.displayName || "")}" placeholder="Customer-facing name"></div><fieldset class="permission-grid"><legend>Allowed operations</legend>${permissions.map(([id, label]) => `<label><input type="checkbox" name="permissions" value="${id}" ${resource.permissions?.includes(id) || (!resource.customerId && DEFAULT_UI_PERMISSIONS.has(id)) ? "checked" : ""}><span>${escapeHtml(label)}</span></label>`).join("")}</fieldset><div class="ownership-proof"><strong>Server-side ownership key</strong><code>${escapeHtml(resource.clusterId)} / ${escapeHtml(resource.node)} / ${resource.type} / ${resource.vmid}</code><small>Nimbus resolves this key from its database; it never trusts customer-supplied coordinates.</small></div>`;
  els.editDialogError.textContent = "";
  els.editDialog.showModal();
}

function openCustomerEditor(customerId) {
  const customer = state.admin.customers.find((item) => item.id === customerId);
  if (!customer) return;
  els.editForm.dataset.kind = "customer";
  els.editForm.dataset.id = customer.id;
  els.editDialogTitle.textContent = "Edit customer";
  els.editDialogBody.innerHTML = `<div class="form-grid"><div class="field"><label for="editCustomerName">Company name</label><input id="editCustomerName" name="name" maxlength="100" required value="${escapeHtml(customer.name)}"></div><div class="field"><label for="editCustomerStatus">Status</label><select id="editCustomerStatus" name="status"><option value="active" ${customer.status === "active" ? "selected" : ""}>Active</option><option value="disabled" ${customer.status === "disabled" ? "selected" : ""}>Disabled</option></select></div><div class="field"><label for="editCustomerPlan">Plan</label><input id="editCustomerPlan" name="planName" value="${escapeHtml(customer.planName || "")}"></div><div class="field"><label for="editCustomerSupport">Support email</label><input id="editCustomerSupport" type="email" name="supportEmail" value="${escapeHtml(customer.supportEmail || "")}"></div></div><div class="notice warning"><span>!</span><span>Disabling a customer immediately revokes every active session for its users. Existing assignments remain intact.</span></div>`;
  els.editDialogError.textContent = "";
  els.editDialog.showModal();
}

function openUserEditor(userId) {
  const user = state.admin.users.find((item) => item.id === userId);
  if (!user) return;
  els.editForm.dataset.kind = "user";
  els.editForm.dataset.id = user.id;
  els.editDialogTitle.textContent = "Edit user";
  els.editDialogBody.innerHTML = `<div class="form-grid"><div class="field full"><label>Email address</label><input disabled value="${escapeHtml(user.email)}"></div><div class="field"><label for="editUserName">Display name</label><input id="editUserName" name="displayName" maxlength="100" required value="${escapeHtml(user.displayName)}"></div><div class="field"><label for="editUserStatus">Status</label><select id="editUserStatus" name="status"><option value="active" ${user.status === "active" ? "selected" : ""}>Active</option><option value="disabled" ${user.status === "disabled" ? "selected" : ""}>Disabled</option></select></div><div class="field"><label for="editUserRole">Role</label><select id="editUserRole" name="role"><option value="customer" ${user.role === "customer" ? "selected" : ""}>Customer</option><option value="admin" ${user.role === "admin" ? "selected" : ""}>Administrator</option></select></div><div class="field"><label for="editUserCustomer">Customer</label><select id="editUserCustomer" name="customerId">${customerOptions(user.customerId || "")}</select></div><div class="field full"><label for="editUserPassword">New password <span class="optional">(optional)</span></label><input id="editUserPassword" name="password" type="password" minlength="12" autocomplete="new-password" placeholder="Leave blank to keep the current password"></div></div>`;
  els.editDialogError.textContent = "";
  els.editDialog.showModal();
}

function openClusterEditor(clusterId) {
  const cluster = state.admin.clusters.find((item) => item.id === clusterId);
  if (!cluster) return;
  els.editForm.dataset.kind = "cluster";
  els.editForm.dataset.id = cluster.id;
  els.editDialogTitle.textContent = "Edit Proxmox cluster";
  els.editDialogBody.innerHTML = `<div class="form-grid"><div class="field"><label for="editClusterName">Display name</label><input id="editClusterName" name="name" required value="${escapeHtml(cluster.name)}"></div><div class="field"><label for="editClusterStatus">Status</label><select id="editClusterStatus" name="status"><option value="active" ${cluster.status === "active" ? "selected" : ""}>Active</option><option value="disabled" ${cluster.status === "disabled" ? "selected" : ""}>Disabled</option><option value="error" ${cluster.status === "error" ? "selected" : ""}>Error</option></select></div><div class="field full"><label for="editClusterUrl">API URL</label><input id="editClusterUrl" name="apiUrl" type="url" required value="${escapeHtml(cluster.apiUrl)}"></div><div class="field"><label for="editClusterTokenId">Replacement token ID <span class="optional">(optional)</span></label><input id="editClusterTokenId" name="tokenId" placeholder="Keep the encrypted token ID"></div><div class="field"><label for="editClusterSecret">Replacement secret <span class="optional">(optional)</span></label><input id="editClusterSecret" name="tokenSecret" type="password" autocomplete="new-password" placeholder="Keep the encrypted secret"></div></div><div class="notice"><span>✓</span><span>Stored credentials are never read back into the browser. Enter a value only when rotating the service token.</span></div>`;
  els.editDialogError.textContent = "";
  els.editDialog.showModal();
}

function openIsoPolicyEditor(policyId) {
  const policy = state.admin.isoPolicies.find((item) => item.id === policyId);
  if (!policy) return;
  els.editForm.dataset.kind = "iso-policy";
  els.editForm.dataset.id = policy.id;
  els.editDialogTitle.textContent = "Edit ISO storage policy";
  els.editDialogBody.innerHTML = `<div class="form-grid">
    <div class="field full"><label>Proxmox destination</label><input disabled value="${escapeHtml(policy.clusterName)} · ${escapeHtml(policy.storageId)}"></div>
    <div class="field"><label for="editIsoPolicyName">Customer-facing name</label><input id="editIsoPolicyName" name="displayName" required maxlength="100" value="${escapeHtml(policy.displayName)}"></div>
    <div class="field"><label for="editIsoPolicyStatus">Status</label><select id="editIsoPolicyStatus" name="status"><option value="active" ${policy.status === "active" ? "selected" : ""}>Active</option><option value="disabled" ${policy.status === "disabled" ? "selected" : ""}>Disabled</option></select></div>
    <div class="field"><label for="editIsoMaxUpload">Maximum file size (GB)</label><input id="editIsoMaxUpload" name="maxUploadGb" type="number" min="1" step="1" required value="${Math.round(policy.maxUploadBytes / 1024 ** 3)}"></div>
    <div class="field"><label for="editIsoQuota">Quota per customer (GB)</label><input id="editIsoQuota" name="quotaGb" type="number" min="1" step="1" required value="${Math.round(policy.customerQuotaBytes / 1024 ** 3)}"></div>
    <label class="policy-checkbox full"><input name="allowDelete" type="checkbox" ${policy.allowDelete ? "checked" : ""}><span><strong>Allow customer deletion</strong><small>Requires Datastore.Allocate on this storage in Proxmox.</small></span></label>
  </div><div class="notice warning"><span>!</span><span>Disabling the policy blocks new uploads, mounts, and deletions but preserves every ownership record.</span></div>`;
  els.editDialogError.textContent = "";
  els.editDialog.showModal();
}

const DEFAULT_UI_PERMISSIONS = new Set(["view_status", "start", "stop", "shutdown", "reboot", "suspend", "resume", "console", "view_config", "view_usage"]);

function showDetails(resourceId) {
  location.hash = `#instance/${encodeURIComponent(resourceId)}`;
}

function confirmAction(resourceId, action) {
  const resource = state.dashboard.resources.find((item) => item.id === resourceId);
  if (!resource) return;
  els.actionDialogTitle.textContent = `${action[0].toUpperCase()}${action.slice(1)} this resource?`;
  els.actionDialogDescription.textContent = action === "reset" || action === "stop" ? "This is a forceful operation and may cause data loss." : "Nimbus will validate your assignment and permission before contacting Proxmox.";
  els.actionDialogResource.innerHTML = resourceIdentity(resource);
  els.confirmAction.className = `button ${["stop", "reset"].includes(action) ? "danger" : "primary"}`;
  els.confirmAction.textContent = action[0].toUpperCase() + action.slice(1);
  els.actionForm.dataset.resource = resourceId;
  els.actionForm.dataset.action = action;
  els.actionDialog.showModal();
}

async function runAction(resourceId, action) {
  try {
    const result = await apiFetch(`/api/v1/resources/${encodeURIComponent(resourceId)}/actions`, { method: "POST", headers: { "Idempotency-Key": `${state.user.id}-${resourceId}-${action}-${Date.now()}` }, body: { action } });
    if (result.task) mergeTask(result.task);
    showToast("success", result.completed ? "Action complete" : `${actionLabel(action)} started`, result.completed ? "The resource status was updated." : "Nimbus will follow the Proxmox task automatically.");
    if (result.completed) await loadDashboard();
    route();
    scheduleTaskPolling();
  } catch (error) {
    if (error.payload?.task) {
      mergeTask(error.payload.task);
      scheduleTaskPolling();
      route();
    }
    showToast("error", "Action blocked", friendlyError(error));
  }
}

async function uploadIso(resourceId, file, policyId) {
  state.instance.upload = { name: file.name, progress: 0, loaded: 0, total: file.size, status: "uploading" };
  renderInstanceDetail(resourceId);
  try {
    const result = await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `/api/v1/resources/${encodeURIComponent(resourceId)}/media/upload?policyId=${encodeURIComponent(policyId)}`);
      xhr.responseType = "json";
      xhr.withCredentials = true;
      xhr.setRequestHeader("Accept", "application/json");
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.setRequestHeader("X-CSRF-Token", state.csrfToken);
      xhr.setRequestHeader("X-Nimbus-Filename", encodeURIComponent(file.name));
      xhr.setRequestHeader("X-Nimbus-Size", String(file.size));
      xhr.upload.onprogress = (event) => {
        if (!state.instance.upload) return;
        const total = event.lengthComputable ? event.total : file.size;
        const progress = total ? Math.min(99, Math.round(event.loaded / total * 100)) : 0;
        Object.assign(state.instance.upload, { progress, loaded: event.loaded, total });
        const bar = document.getElementById("isoUploadProgressBar");
        if (bar) bar.style.width = `${progress}%`;
        const copy = document.querySelector(".iso-upload-progress small");
        const value = document.querySelector(".iso-upload-progress b");
        if (copy) copy.textContent = `${progress}% · ${formatBytes(event.loaded)} of ${formatBytes(total)}`;
        if (value) value.textContent = `${progress}%`;
      };
      xhr.upload.onload = () => {
        if (!state.instance.upload) return;
        Object.assign(state.instance.upload, { progress: 100, loaded: file.size, status: "finishing" });
        renderInstanceDetail(resourceId);
      };
      xhr.onerror = () => reject(Object.assign(new Error("The network connection interrupted the ISO upload."), { code: "iso_upload_interrupted" }));
      xhr.onabort = () => reject(Object.assign(new Error("The ISO upload was cancelled."), { code: "iso_upload_cancelled" }));
      xhr.onload = () => {
        let payload = xhr.response;
        if (!payload && xhr.responseText) {
          try { payload = JSON.parse(xhr.responseText); } catch { payload = {}; }
        }
        if (xhr.status >= 200 && xhr.status < 300) resolve(payload || {});
        else reject(Object.assign(new Error(payload?.message || payload?.error || `Upload failed (${xhr.status})`), { code: payload?.error, status: xhr.status, payload }));
      };
      xhr.send(file);
    });
    showToast("success", result.image?.status === "processing" ? "ISO received" : "ISO uploaded", result.image?.status === "processing" ? "Proxmox is finalizing the image. Nimbus will follow its task." : "The image is ready to mount.");
  } catch (error) {
    showToast("error", "ISO upload failed", friendlyError(error));
  } finally {
    state.instance.upload = null;
    await loadInstanceMedia({ quiet: true });
  }
}

async function mountIso(resourceId, isoImageId) {
  try {
    await apiFetch(`/api/v1/resources/${encodeURIComponent(resourceId)}/media/mount`, { method: "POST", body: { isoImageId } });
    await loadInstanceMedia({ quiet: true });
    showToast("success", "ISO mounted", "The virtual CD/DVD drive is ready.");
  } catch (error) { showToast("error", "Could not mount ISO", friendlyError(error)); }
}

async function ejectIso(resourceId) {
  try {
    await apiFetch(`/api/v1/resources/${encodeURIComponent(resourceId)}/media/eject`, { method: "POST", body: {} });
    await loadInstanceMedia({ quiet: true });
    showToast("success", "ISO ejected", "The virtual CD/DVD drive is now empty.");
  } catch (error) { showToast("error", "Could not eject ISO", friendlyError(error)); }
}

async function deleteIso(resourceId, isoImageId, { dismiss = false } = {}) {
  try {
    await apiFetch(`/api/v1/resources/${encodeURIComponent(resourceId)}/media/${encodeURIComponent(isoImageId)}`, { method: "DELETE", body: {} });
    await loadInstanceMedia({ quiet: true });
    showToast("success", dismiss ? "Failed upload dismissed" : "ISO deletion started", dismiss ? "The failed local upload record was removed." : "Nimbus removed the ownership record or is following the Proxmox deletion task.");
  } catch (error) { showToast("error", "Could not delete ISO", friendlyError(error)); }
}

function mergeTask(task) {
  if (!task?.id) return;
  if (state.dashboard) {
    const tasks = state.dashboard.tasks || (state.dashboard.tasks = []);
    const index = tasks.findIndex((item) => item.id === task.id);
    if (index >= 0) tasks[index] = task; else tasks.unshift(task);
  }
  if (state.instance.details) {
    const tasks = state.instance.details.tasks || (state.instance.details.tasks = []);
    const index = tasks.findIndex((item) => item.id === task.id);
    if (index >= 0) tasks[index] = task; else tasks.unshift(task);
  }
}

function scheduleTaskPolling() {
  if (taskPollTimer || taskPolling || !state.user) return;
  const pending = (state.dashboard?.tasks || []).some((task) => !task.completed);
  if (!pending) return;
  taskPollTimer = setTimeout(() => {
    taskPollTimer = null;
    pollActiveTasks();
  }, document.visibilityState === "visible" ? 1500 : 5000);
}

async function pollActiveTasks() {
  if (taskPolling || !state.user) return;
  const pending = (state.dashboard?.tasks || []).filter((task) => !task.completed).slice(0, 6);
  if (!pending.length) return;
  taskPolling = true;
  try {
    const results = await Promise.all(pending.map(async (task) => {
      try { return await apiFetch(`/api/v1/tasks/${encodeURIComponent(task.id)}`); }
      catch { return null; }
    }));
    let completedAny = false;
    for (const result of results.filter(Boolean)) {
      mergeTask(result.task);
      if (result.completed) {
        completedAny = true;
        if (!announcedTaskIds.has(result.task.id)) {
          announcedTaskIds.add(result.task.id);
          showToast(result.task.success ? "success" : "error", result.task.success ? "Action completed" : "Action failed", result.task.success ? "Proxmox completed the requested operation." : result.task.message);
        }
      }
    }
    if (completedAny) await loadDashboard();
    route();
  } finally {
    taskPolling = false;
    scheduleTaskPolling();
  }
}

async function openConsole(resourceId) {
  const popup = window.open("about:blank", "nimbus-console", "popup,width=1180,height=760");
  try {
    const result = await apiFetch(`/api/v1/resources/${encodeURIComponent(resourceId)}/console`, { method: "POST", body: {} });
    if (popup) popup.location.href = result.launchUrl;
    else location.href = result.launchUrl;
    showToast("success", "Console ticket created", "A short-lived, single-use console session was opened.");
  } catch (error) { if (popup) popup.close(); showToast("error", "Console unavailable", friendlyError(error)); }
}

async function refresh({ quiet = false } = {}) {
  if (state.loading) return;
  state.loading = true;
  els.refreshButton.disabled = true;
  try {
    await loadDashboard();
    if (state.currentView === "admin") await loadAdmin();
    if (state.currentView === "instance" && state.instance.resourceId) await loadInstanceDetails(state.instance.resourceId, { quiet: true });
    else route();
    if (!quiet) showToast("success", "Refreshed", "Latest panel data loaded.");
  } catch (error) { if (!quiet) showToast("error", "Refresh failed", friendlyError(error)); }
  finally { state.loading = false; els.refreshButton.disabled = false; }
}

function closeSidebar() {
  els.sidebar.classList.remove("open");
  els.sidebarBackdrop.hidden = true;
  els.menuButton.setAttribute("aria-expanded", "false");
}

els.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  els.authError.textContent = "";
  const button = event.currentTarget.querySelector("button");
  button.disabled = true;
  try {
    const result = await apiFetch("/api/auth/login", { method: "POST", body: formPayload(event.currentTarget) });
    state.user = result.user;
    state.csrfToken = result.csrfToken;
    setAuthenticated(true);
    applyUser();
    await loadDashboard();
    location.hash = "#overview";
    route();
  } catch (error) { els.authError.textContent = friendlyError(error); }
  finally { button.disabled = false; }
});

els.logoutButton.addEventListener("click", async () => {
  try { await apiFetch("/api/auth/logout", { method: "POST", body: {} }); } catch { /* clear local view regardless */ }
  location.reload();
});
els.refreshButton.addEventListener("click", () => refresh());
els.toastClose.addEventListener("click", () => els.toast.classList.remove("show"));
els.globalSearch.addEventListener("input", (event) => { state.search = event.target.value; route(); });
window.addEventListener("hashchange", route);
document.querySelectorAll("[data-close-dialog]").forEach((button) => button.addEventListener("click", () => button.closest("dialog").close()));
els.menuButton.addEventListener("click", () => { const open = els.sidebar.classList.toggle("open"); els.sidebarBackdrop.hidden = !open; els.menuButton.setAttribute("aria-expanded", String(open)); });
els.sidebarBackdrop.addEventListener("click", closeSidebar);

els.actionForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const { resource, action } = event.currentTarget.dataset;
  els.actionDialog.close();
  runAction(resource, action);
});

els.editForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const { kind, id } = form.dataset;
  const data = new FormData(form);
  try {
    if (kind === "assignment") {
      const payload = { customerId: data.get("customerId"), displayName: data.get("displayName"), permissions: data.getAll("permissions") };
      if (!payload.customerId) { els.editDialogError.textContent = "Choose a customer account."; return; }
      const current = state.admin.resources.find((item) => item.id === id);
      if (current.customerId) {
        if (current.customerId !== payload.customerId) await apiFetch("/api/admin/assignments", { method: "POST", body: { ...payload, resourceId: id } });
        else await apiFetch(`/api/admin/resources/${encodeURIComponent(id)}/assignment`, { method: "PATCH", body: payload });
      } else await apiFetch("/api/admin/assignments", { method: "POST", body: { ...payload, resourceId: id } });
    } else if (kind === "customer") {
      await apiFetch(`/api/admin/customers/${encodeURIComponent(id)}`, { method: "PATCH", body: formPayload(form) });
    } else if (kind === "user") {
      const payload = formPayload(form);
      const password = payload.password;
      delete payload.password;
      if (payload.role === "admin") payload.customerId = null;
      await apiFetch(`/api/admin/users/${encodeURIComponent(id)}`, { method: "PATCH", body: payload });
      if (password) await apiFetch(`/api/admin/users/${encodeURIComponent(id)}/password`, { method: "POST", body: { password } });
    } else if (kind === "cluster") {
      const payload = formPayload(form);
      if (!payload.tokenId) delete payload.tokenId;
      if (!payload.tokenSecret) delete payload.tokenSecret;
      await apiFetch(`/api/admin/clusters/${encodeURIComponent(id)}`, { method: "PATCH", body: payload });
    } else if (kind === "iso-policy") {
      const payload = formPayload(form);
      payload.maxUploadBytes = Math.round(Number(payload.maxUploadGb) * 1024 ** 3);
      payload.customerQuotaBytes = Math.round(Number(payload.quotaGb) * 1024 ** 3);
      payload.allowDelete = new FormData(form).has("allowDelete");
      delete payload.maxUploadGb;
      delete payload.quotaGb;
      await apiFetch(`/api/admin/iso-policies/${encodeURIComponent(id)}`, { method: "PATCH", body: payload });
    } else return;
    els.editDialog.close();
    await refresh({ quiet: true });
    showToast("success", kind === "assignment" ? "Assignment saved" : "Changes saved", kind === "assignment" ? "The customer policy is active immediately." : "The control-center record has been updated.");
  } catch (error) { els.editDialogError.textContent = friendlyError(error); }
});

els.viewRoot.addEventListener("click", async (event) => {
  const target = event.target.closest("button, a");
  if (!target) return;
  if (target.dataset.copy !== undefined) {
    try {
      await navigator.clipboard.writeText(target.dataset.copy);
      showToast("success", "Copied", `${target.dataset.copy} is on your clipboard.`);
    } catch {
      showToast("error", "Could not copy", "Select and copy the value manually.");
    }
    return;
  }
  if (target.dataset.retryInstance) {
    state.instance.error = null;
    state.instance.loading = true;
    renderInstanceDetail(target.dataset.retryInstance);
    loadInstanceDetails(target.dataset.retryInstance);
    return;
  }
  if (target.dataset.refreshMedia !== undefined) { await loadInstanceMedia(); return; }
  if (target.dataset.mountIso) { await mountIso(state.instance.resourceId, target.dataset.mountIso); return; }
  if (target.dataset.ejectIso !== undefined) { await ejectIso(state.instance.resourceId); return; }
  if (target.dataset.deleteIso) {
    const dismiss = target.dataset.dismissIso !== undefined;
    if (!dismiss && !confirm("Delete this ISO from Proxmox storage? This cannot be undone.")) return;
    await deleteIso(state.instance.resourceId, target.dataset.deleteIso, { dismiss });
    return;
  }
  if (target.dataset.action) { confirmAction(target.dataset.resource, target.dataset.action); return; }
  if (target.dataset.details) { showDetails(target.dataset.details); return; }
  if (target.dataset.console) { openConsole(target.dataset.console); return; }
  if (target.dataset.assign) { openAssignment(target.dataset.assign); return; }
  if (target.dataset.editCustomer) { openCustomerEditor(target.dataset.editCustomer); return; }
  if (target.dataset.editUser) { openUserEditor(target.dataset.editUser); return; }
  if (target.dataset.editCluster) { openClusterEditor(target.dataset.editCluster); return; }
  if (target.dataset.editIsoPolicy) { openIsoPolicyEditor(target.dataset.editIsoPolicy); return; }
  if (target.dataset.discoverIso) {
    const clusterId = target.dataset.discoverIso;
    target.disabled = true;
    try {
      const result = await apiFetch(`/api/admin/clusters/${encodeURIComponent(clusterId)}/iso-storage-candidates`);
      state.isoCandidates[clusterId] = result.candidates || [];
      renderAdmin();
      showToast(result.candidates?.length ? "success" : "error", result.candidates?.length ? "ISO storage discovered" : "No ISO storage found", result.candidates?.length ? `${result.candidates.length} storage destination${result.candidates.length === 1 ? "" : "s"} available.` : "Enable ISO content on a Proxmox storage and verify Datastore.Audit.");
    } catch (error) {
      target.disabled = false;
      showToast("error", "Discovery failed", friendlyError(error));
    }
    return;
  }
  if (target.dataset.deleteIsoPolicy) {
    if (!confirm("Delete this ISO storage policy? Policies with customer ISO records can only be disabled.")) return;
    try {
      await apiFetch(`/api/admin/iso-policies/${encodeURIComponent(target.dataset.deleteIsoPolicy)}`, { method: "DELETE", body: {} });
      await refresh({ quiet: true });
      showToast("success", "ISO policy deleted", "The local policy was removed. Proxmox storage was not changed.");
    } catch (error) { showToast("error", "Could not delete policy", friendlyError(error)); }
    return;
  }
  if (target.dataset.deleteCustomer) {
    if (!confirm("Delete this customer? Its users and assignments will be removed, but Proxmox resources will not be deleted.")) return;
    try { await apiFetch(`/api/admin/customers/${encodeURIComponent(target.dataset.deleteCustomer)}`, { method: "DELETE", body: {} }); await refresh({ quiet: true }); showToast("success", "Customer deleted", "Local users and assignments were removed; Proxmox guests were untouched."); }
    catch (error) { showToast("error", "Could not delete customer", friendlyError(error)); }
    return;
  }
  if (target.dataset.deleteUser) {
    if (!confirm("Delete this user account? This action immediately revokes its sessions.")) return;
    try { await apiFetch(`/api/admin/users/${encodeURIComponent(target.dataset.deleteUser)}`, { method: "DELETE", body: {} }); await refresh({ quiet: true }); showToast("success", "User deleted", "The account and its sessions have been removed."); }
    catch (error) { showToast("error", "Could not delete user", friendlyError(error)); }
    return;
  }
  if (target.dataset.unassign) {
    if (!confirm("Remove this resource assignment? The customer will immediately lose access.")) return;
    try { await apiFetch(`/api/admin/resources/${encodeURIComponent(target.dataset.unassign)}/assignment`, { method: "DELETE", body: {} }); await refresh({ quiet: true }); showToast("success", "Assignment removed", "Customer access has been revoked."); }
    catch (error) { showToast("error", "Could not remove assignment", friendlyError(error)); }
    return;
  }
  if (target.dataset.adminTab) { state.adminTab = target.dataset.adminTab; renderAdmin(); return; }
  if (target.dataset.testCluster) {
    try { await apiFetch(`/api/admin/clusters/${encodeURIComponent(target.dataset.testCluster)}/test`, { method: "POST", body: {} }); showToast("success", "Connection verified", "The service account and API endpoint are working."); }
    catch (error) { showToast("error", "Connection failed", friendlyError(error)); }
    return;
  }
  if (target.dataset.syncCluster) {
    try { await apiFetch(`/api/admin/clusters/${encodeURIComponent(target.dataset.syncCluster)}/sync`, { method: "POST", body: {} }); await refresh({ quiet: true }); showToast("success", "Cluster synchronized", "Resource metadata is current; assignments were preserved."); }
    catch (error) { showToast("error", "Sync failed", friendlyError(error)); }
    return;
  }
  if (target.dataset.syncAll !== undefined) {
    for (const cluster of state.admin.clusters) {
      try { await apiFetch(`/api/admin/clusters/${encodeURIComponent(cluster.id)}/sync`, { method: "POST", body: {} }); } catch { /* report combined result after refresh */ }
    }
    await refresh({ quiet: true });
    showToast("success", "Synchronization complete", "Available cluster metadata has been refreshed.");
  }
});

els.viewRoot.addEventListener("change", (event) => {
  const target = event.target;
  if (target.matches("[data-history-timeframe]")) loadInstanceHistory(target.value);
  if (target.matches("[data-iso-cluster]")) {
    state.isoClusterId = target.value;
    renderAdmin();
  }
});

els.viewRoot.addEventListener("invalid", (event) => {
  const form = event.target.closest("form");
  if (!form) return;
  const message = form.querySelector(".form-message");
  if (message) {
    message.className = "form-message error";
    message.textContent = event.target.validity.patternMismatch
      ? "Use a lowercase ID with letters, numbers, underscores, or hyphens."
      : "Complete the highlighted field before saving.";
  }
}, true);

els.viewRoot.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  if (form.id === "isoUploadForm") {
    const file = form.elements.isoFile?.files?.[0];
    const policyId = form.elements.policyId?.value;
    if (!file || !policyId) { form.reportValidity(); return; }
    if (!file.name.toLowerCase().endsWith(".iso")) {
      showToast("error", "Choose an ISO image", "The selected filename must end in .iso.");
      return;
    }
    await uploadIso(state.instance.resourceId, file, policyId);
    return;
  }
  const createKind = form.dataset.adminCreate
    || (form.elements.apiUrl && form.elements.tokenId && form.elements.tokenSecret ? "cluster" : null)
    || (form.elements.email && form.elements.role ? "user" : null)
    || (form.elements.planName && form.elements.supportEmail ? "customer" : null);
  const message = form.querySelector(".form-message");
  const button = form.querySelector("button[type='submit'], button:not([type])");
  if (!form.checkValidity()) {
    form.reportValidity();
    return;
  }
  if (message) {
    message.className = "form-message";
    message.textContent = createKind === "cluster" ? "Saving encrypted cluster credentials…" : "Saving…";
  }
  if (button) button.disabled = true;
  try {
    if (createKind === "customer" || form.id === "createCustomerForm") await apiFetch("/api/admin/customers", { method: "POST", body: formPayload(form) });
    else if (createKind === "cluster" || form.id === "createClusterForm") await apiFetch("/api/admin/clusters", { method: "POST", body: formPayload(form) });
    else if (createKind === "user" || form.id === "createUserForm") {
      const payload = formPayload(form);
      if (payload.role === "admin") payload.customerId = null;
      await apiFetch("/api/admin/users", { method: "POST", body: payload });
    } else if (createKind === "iso-policy" || form.id === "createIsoPolicyForm") {
      const payload = formPayload(form);
      payload.maxUploadBytes = Math.round(Number(payload.maxUploadGb) * 1024 ** 3);
      payload.customerQuotaBytes = Math.round(Number(payload.quotaGb) * 1024 ** 3);
      payload.allowDelete = new FormData(form).has("allowDelete");
      delete payload.maxUploadGb;
      delete payload.quotaGb;
      await apiFetch("/api/admin/iso-policies", { method: "POST", body: payload });
    } else if (form.id === "profileForm") {
      const result = await apiFetch("/api/v1/profile", { method: "PATCH", body: formPayload(form) });
      state.user = result.user; applyUser(); showToast("success", "Profile updated", "Your display name has been saved."); return;
    } else if (form.id === "passwordForm") {
      await apiFetch("/api/v1/password", { method: "POST", body: formPayload(form) });
      showToast("success", "Password changed", "Sign in again with your new password.");
      setTimeout(() => location.reload(), 1200); return;
    } else throw Object.assign(new Error(`Nimbus could not identify form '${form.id || "unnamed"}'. Reload the current application build.`), { code: "unknown_form" });
    await refresh({ quiet: true });
    showToast("success", "Saved", "The control-center record is ready.");
  } catch (error) {
    const detail = friendlyError(error);
    if (message) { message.className = "form-message error"; message.textContent = detail; }
    showToast("error", "Could not save", detail);
  }
  finally { if (button) button.disabled = false; }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "/" && !/input|textarea|select/i.test(document.activeElement?.tagName)) { event.preventDefault(); els.globalSearch.focus(); }
});

setInterval(() => {
  if (document.visibilityState === "visible" && state.user && Date.now() - state.lastUpdatedAt > 45_000 && state.currentView !== "admin") refresh({ quiet: true });
}, 15_000);

window.addEventListener("resize", () => {
  clearTimeout(drawInstanceChart.resizeTimer);
  drawInstanceChart.resizeTimer = setTimeout(drawInstanceChart, 120);
});
document.addEventListener("visibilitychange", scheduleTaskPolling);

loadSession();
