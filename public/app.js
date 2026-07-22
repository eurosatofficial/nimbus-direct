const state = {
  user: null,
  csrfToken: null,
  dashboard: null,
  admin: null,
  currentView: "overview",
  adminTab: "inventory",
  search: "",
  loading: false,
  lastUpdatedAt: 0,
};

const permissions = [
  ["view_status", "View status"], ["start", "Start"], ["stop", "Stop"], ["shutdown", "Shutdown"],
  ["reboot", "Reboot"], ["reset", "Reset"], ["suspend", "Suspend"], ["resume", "Resume"],
  ["console", "Console access"], ["view_config", "View configuration"], ["view_usage", "Usage statistics"],
  ["snapshot_create", "Create snapshots"], ["snapshot_restore", "Restore snapshots"], ["snapshot_delete", "Delete snapshots"],
  ["config_change", "Change selected configuration"],
];

const views = {
  overview: ["Infrastructure overview", "Resources assigned directly to this account."],
  instances: ["Virtual machines & containers", "Power controls and detailed resource information."],
  network: ["Network", "Basic addresses for assigned guests."],
  activity: ["Activity", "Recent account actions and Proxmox task requests."],
  settings: ["Account settings", "Manage your profile and security."],
  admin: ["Control center", "Clusters, customers, direct assignments, and policy."],
};

const els = Object.fromEntries([
  "authView", "appShell", "loginForm", "authError", "viewRoot", "pageTitle", "pageDescription", "currentSection",
  "tenantPlan", "connectionHealth", "healthTitle", "healthDetail", "instanceCount", "profileName", "profileTenant",
  "profileAvatar", "globalSearch", "refreshButton", "logoutButton", "todayLabel", "lastUpdated", "instanceDialog",
  "instanceDialogTitle", "instanceDialogBody", "actionDialog", "actionForm", "actionDialogTitle", "actionDialogDescription",
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
  if (!response.ok) throw Object.assign(new Error(payload?.message || payload?.error || `Request failed (${response.status})`), { code: payload?.error, status: response.status });
  return payload;
}

function friendlyError(error) {
  const messages = {
    invalid_credentials: "The email address or password is incorrect.",
    too_many_attempts: "Too many sign-in attempts. Please wait and try again.",
    invalid_csrf_token: "Your session changed. Refresh the page and try again.",
    request_timeout: "The panel request timed out. Check the reverse proxy and container API logs.",
    resource_not_found: "That resource is not assigned to your account or the permission is disabled.",
    last_admin: "The final active administrator cannot be changed or deleted.",
    proxmox_unreachable: "The Proxmox cluster could not be reached.",
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

function actionButtons(resource, compact = false) {
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
  const tabs = [["inventory", "Inventory"], ["customers", "Customers"], ["clusters", "Clusters"], ["users", "Users"], ["audit", "Audit log"]];
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
  const renderers = { inventory: renderAdminInventory, customers: renderAdminCustomers, clusters: renderAdminClusters, users: renderAdminUsers, audit: renderAdminAudit };
  els.viewRoot.innerHTML = `${adminTabs()}<div class="admin-section">${renderers[state.adminTab]()}</div>`;
}

const renderers = { overview: renderOverview, instances: renderInstances, network: renderNetwork, activity: renderActivity, settings: renderSettings, admin: renderAdmin };

function route() {
  if (!state.user || !state.dashboard) return;
  let view = location.hash.replace(/^#/, "") || "overview";
  if (!views[view]) view = "overview";
  if (view === "admin" && state.user.role !== "admin") view = "overview";
  state.currentView = view;
  const [title, description] = views[view];
  els.pageTitle.textContent = title;
  els.pageDescription.textContent = description;
  els.currentSection.textContent = title;
  els.todayLabel.textContent = new Intl.DateTimeFormat(undefined, { weekday: "long", month: "long", day: "numeric" }).format(new Date());
  document.querySelectorAll(".nav-item").forEach((link) => link.classList.toggle("active", link.dataset.view === view));
  if (view === "admin" && !state.admin) {
    els.viewRoot.innerHTML = `<div class="loading-inline"><span class="spinner"></span>Loading control center</div>`;
    loadAdmin().then(renderAdmin).catch((error) => showToast("error", "Could not load", friendlyError(error)));
  } else renderers[view]();
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

const DEFAULT_UI_PERMISSIONS = new Set(["view_status", "start", "stop", "shutdown", "reboot", "suspend", "resume", "console", "view_config", "view_usage"]);

async function showDetails(resourceId) {
  const resource = (state.dashboard.resources || []).find((item) => item.id === resourceId) || state.admin?.resources.find((item) => item.id === resourceId);
  if (!resource) return;
  els.instanceDialogTitle.textContent = resource.displayName || resource.name;
  els.instanceDialogBody.innerHTML = `<div class="loading-inline"><span class="spinner"></span>Loading resource</div>`;
  els.instanceDialog.showModal();
  try {
    const details = await apiFetch(`/api/v1/resources/${encodeURIComponent(resource.id)}`);
    els.instanceDialogBody.innerHTML = `<div class="detail-sections"><section class="detail-hero">${resourceIdentity(resource)}${statusMarkup(resource)}</section><section class="detail-section"><h3>Resource</h3><dl class="detail-list"><div><dt>Cluster</dt><dd>${escapeHtml(resource.clusterName)}</dd></div><div><dt>Node</dt><dd>${escapeHtml(resource.node)}</dd></div><div><dt>Identity</dt><dd>${resource.type.toUpperCase()} ${resource.vmid}</dd></div><div><dt>Primary IP</dt><dd>${escapeHtml(details.network?.primaryIp || resource.ip || "Unavailable")}</dd></div><div><dt>vCPU</dt><dd>${resource.vcpu}</dd></div><div><dt>Memory</dt><dd>${resource.memory} GB</dd></div></dl></section>${Object.keys(details.config || {}).length ? `<section class="detail-section"><h3>Allowlisted configuration</h3><dl class="detail-list">${Object.entries(details.config).map(([key, value]) => `<div><dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd></div>`).join("")}</dl></section>` : ""}<section class="detail-section"><h3>Allowed operations</h3><div class="permission-badges">${(resource.permissions || []).map((permission) => `<span>${escapeHtml(permissions.find(([id]) => id === permission)?.[1] || permission)}</span>`).join("")}</div></section></div>`;
  } catch (error) {
    els.instanceDialogBody.innerHTML = emptyState("!", "Details unavailable", friendlyError(error));
  }
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
    showToast("success", `${action[0].toUpperCase()}${action.slice(1)} requested`, result.completed ? "The resource status was updated." : "Proxmox accepted the task.");
    await loadDashboard();
    route();
  } catch (error) { showToast("error", "Action blocked", friendlyError(error)); }
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
    route();
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
    } else return;
    els.editDialog.close();
    await refresh({ quiet: true });
    showToast("success", kind === "assignment" ? "Assignment saved" : "Changes saved", kind === "assignment" ? "The customer policy is active immediately." : "The control-center record has been updated.");
  } catch (error) { els.editDialogError.textContent = friendlyError(error); }
});

els.viewRoot.addEventListener("click", async (event) => {
  const target = event.target.closest("button, a");
  if (!target) return;
  if (target.dataset.action) { confirmAction(target.dataset.resource, target.dataset.action); return; }
  if (target.dataset.details) { showDetails(target.dataset.details); return; }
  if (target.dataset.console) { openConsole(target.dataset.console); return; }
  if (target.dataset.assign) { openAssignment(target.dataset.assign); return; }
  if (target.dataset.editCustomer) { openCustomerEditor(target.dataset.editCustomer); return; }
  if (target.dataset.editUser) { openUserEditor(target.dataset.editUser); return; }
  if (target.dataset.editCluster) { openClusterEditor(target.dataset.editCluster); return; }
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

loadSession();
