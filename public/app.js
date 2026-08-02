import { mergeNetworkAddresses } from "./network-state.js";

const state = {
  user: null,
  csrfToken: null,
  demoReadOnly: false,
  dashboard: null,
  network: null,
  notifications: null,
  maintenance: null,
  support: null,
  apiKeys: null,
  apiKeyDraft: null,
  apiKeySecret: null,
  apiAccessEditor: null,
  admin: null,
  currentView: "overview",
  adminTab: "operations",
  mfaChallenge: null,
  accountFlow: null,
  mfaEnrollment: null,
  recoveryCodes: null,
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
let networkLoadPromise = null;
let networkLoadedAt = 0;
let networkLoading = false;
const networkRefreshMs = 30_000;

const permissions = [
  ["view_status", "View status"], ["start", "Start"], ["stop", "Stop"], ["shutdown", "Shutdown"],
  ["reboot", "Reboot"], ["reset", "Reset"], ["suspend", "Suspend"], ["resume", "Resume"],
  ["console", "Console access"], ["view_config", "View configuration"], ["view_usage", "Usage statistics"],
  ["snapshot_create", "Create snapshots"], ["snapshot_restore", "Restore snapshots"], ["snapshot_delete", "Delete snapshots"],
  ["config_change", "Change selected configuration"],
  ["iso_view", "View installation media"], ["iso_upload", "Upload ISO images"],
  ["iso_mount", "Mount and eject ISO images"], ["iso_boot", "Boot from mounted ISO once"],
  ["iso_delete", "Delete uploaded ISO images"],
];

const views = {
  overview: ["Infrastructure overview", "Resources assigned directly to this account."],
  instances: ["Virtual machines & containers", "Power controls and detailed resource information."],
  instance: ["Instance details", "Live status, usage, networking, controls, and task progress."],
  network: ["Network", "Basic addresses for assigned guests."],
  activity: ["Activity", "Recent account actions and Proxmox task requests."],
  notifications: ["Notifications", "Infrastructure alerts, recoveries, and completed actions."],
  maintenance: ["Maintenance", "Planned work and service incidents affecting your infrastructure."],
  support: ["Support tickets", "Private conversations with your infrastructure support team."],
  settings: ["Account settings", "Manage your profile and security."],
  admin: ["Control center", "Clusters, customers, direct assignments, and policy."],
};

const els = Object.fromEntries([
  "authView", "appShell", "loginForm", "authError", "mfaForm", "mfaLoginCode", "mfaAuthError", "mfaBackButton",
  "authDescription", "demoLoginNotice", "demoReadOnlyBanner", "forgotPasswordButton", "forgotPasswordForm", "forgotPasswordEmail", "forgotPasswordMessage",
  "forgotPasswordBackButton", "accountCompletionForm", "accountFlowRecipient", "accountPassword",
  "accountConfirmPassword", "accountCompletionMessage", "accountCompletionBackButton",
  "viewRoot", "pageTitle", "pageDescription", "currentSection",
  "tenantPlan", "connectionHealth", "healthTitle", "healthDetail", "instanceCount", "profileName", "profileTenant",
  "profileAvatar", "globalSearch", "refreshButton", "logoutButton", "todayLabel", "lastUpdated", "notificationCount", "maintenanceCount", "supportCount",
  "appearanceButton", "authAppearanceButton",
  "actionDialog", "actionForm", "actionDialogTitle", "actionDialogDescription",
  "actionDialogResource", "confirmAction", "editDialog", "editForm", "editDialogTitle", "editDialogBody", "editDialogError",
  "snapshotDialog", "snapshotForm", "snapshotDialogEyebrow", "snapshotDialogTitle", "snapshotDialogBody", "snapshotDialogError", "confirmSnapshot",
  "toast", "toastIcon", "toastTitle", "toastMessage", "toastClose", "menuButton", "sidebar", "sidebarBackdrop",
].map((id) => [id, document.getElementById(id)]));

const readOnlyBrowsingControls = [
  "[data-admin-tab]",
  "[data-appearance]",
  "[data-details]",
  "[data-open-support]",
  "[data-copy]",
  "[data-copy-mfa-secret]",
  "[data-copy-recovery]",
  "[data-dismiss-recovery]",
  "[data-retry-instance]",
  "[data-refresh-media]",
].join(",");

const appearanceOptions = {
  system: { label: "System", icon: "◐", description: "Match this device" },
  light: { label: "Light", icon: "☀", description: "Always use light" },
  dark: { label: "Dark", icon: "☾", description: "Always use dark" },
};

function currentAppearance() {
  return window.NimbusAppearance?.get?.() || "system";
}

function refreshAppearanceControls() {
  const mode = currentAppearance();
  const option = appearanceOptions[mode] || appearanceOptions.system;
  [els.appearanceButton, els.authAppearanceButton].filter(Boolean).forEach((button) => {
    const icon = button.querySelector("[aria-hidden='true']");
    if (icon) icon.textContent = option.icon;
    button.setAttribute("aria-label", `Appearance: ${option.label}`);
    button.title = `Appearance: ${option.label}`;
  });
  document.querySelectorAll("button[data-appearance]").forEach((button) => {
    const active = button.dataset.appearance === mode;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  document.querySelectorAll("[data-appearance-label]").forEach((label) => {
    label.textContent = option.label;
  });
}

function setAppearance(mode) {
  window.NimbusAppearance?.set?.(mode);
  refreshAppearanceControls();
}

function cycleAppearance() {
  const modes = ["system", "light", "dark"];
  const next = modes[(modes.indexOf(currentAppearance()) + 1) % modes.length];
  setAppearance(next);
}

function appearancePanelMarkup() {
  const selected = currentAppearance();
  return `<section class="panel form-panel appearance-panel">
    <div class="appearance-heading"><span><p class="eyebrow">Personal preference</p><h2>Appearance</h2><p>Nimbus can follow this device or keep the interface light or dark.</p></span><span class="pill" data-appearance-label>${escapeHtml(appearanceOptions[selected]?.label || "System")}</span></div>
    <div class="appearance-options" role="group" aria-label="Color appearance">
      ${Object.entries(appearanceOptions).map(([mode, option]) => `<button class="appearance-option ${selected === mode ? "active" : ""}" type="button" data-appearance="${mode}" aria-pressed="${selected === mode}">
        <span class="appearance-option-icon" aria-hidden="true">${option.icon}</span>
        <span><strong>${option.label}</strong><small>${option.description}</small></span>
        <span class="appearance-check" aria-hidden="true">✓</span>
      </button>`).join("")}
    </div>
  </section>`;
}

function applyDemoReadOnlyUi(root = els.viewRoot) {
  if (!state.demoReadOnly || !root) return;
  root.querySelectorAll("form").forEach((form) => {
    form.classList.add("demo-form-disabled");
    form.setAttribute("aria-disabled", "true");
    form.querySelectorAll("input, textarea, select, button").forEach((control) => {
      control.disabled = true;
      control.title ||= "Changes are disabled in the public read-only demo.";
    });
  });
  root.querySelectorAll("button").forEach((button) => {
    if (button.matches(readOnlyBrowsingControls)) return;
    button.disabled = true;
    button.title ||= "Changes are disabled in the public read-only demo.";
  });
}

function setDemoReadOnly(enabled) {
  state.demoReadOnly = Boolean(enabled);
  document.body.classList.toggle("demo-read-only", state.demoReadOnly);
  els.demoLoginNotice.hidden = !state.demoReadOnly;
  els.demoReadOnlyBanner.hidden = !state.demoReadOnly;
  els.forgotPasswordButton.hidden = state.demoReadOnly;
  applyDemoReadOnlyUi();
}

new MutationObserver(() => applyDemoReadOnlyUi())
  .observe(els.viewRoot, { childList: true, subtree: true });

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
}

function initials(value) {
  return String(value || "ND").split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]).join("").toUpperCase();
}

function plural(value, word) { return `${value} ${word}${value === 1 ? "" : "s"}`; }
function pct(value) { return `${Math.max(0, Math.min(100, Number(value) || 0))}%`; }
function percent(value, total) { return total > 0 ? Math.max(0, Math.min(100, value / total * 100)) : 0; }
function storageUsageKnown(resource) { return resource?.storageUsageAvailable !== false; }
function storageSummary(resource) {
  return storageUsageKnown(resource)
    ? `${resource.storageUsed} / ${resource.storage} GB`
    : `Unavailable / ${resource.storage} GB`;
}
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
function formatDuration(milliseconds) {
  const seconds = Math.max(0, Math.round(Number(milliseconds || 0) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${minutes % 60}m`;
  return `${Math.floor(hours / 24)}d ${hours % 24}h`;
}
function actionLabel(action) {
  return ({
    start: "Starting", stop: "Stopping", shutdown: "Shutting down", reboot: "Rebooting", reset: "Resetting",
    suspend: "Suspending", resume: "Resuming", snapshot_create: "Creating snapshot",
    snapshot_restore: "Restoring snapshot", snapshot_delete: "Deleting snapshot",
  })[action] || "Processing";
}
function actionName(action) {
  return ({
    start: "Start", stop: "Force stop", shutdown: "Shutdown", reboot: "Reboot", reset: "Force reset",
    suspend: "Suspend", resume: "Resume", snapshot_create: "Create snapshot",
    snapshot_restore: "Restore snapshot", snapshot_delete: "Delete snapshot",
  })[action] || "Power";
}
function actionProgressTitle(action) {
  return String(action || "").startsWith("snapshot_") ? actionLabel(action) : `${actionLabel(action)} this instance`;
}

async function apiFetch(path, options = {}) {
  const timeoutMs = Math.max(1_000, Number(options.timeoutMs) || 20_000);
  delete options.timeoutMs;
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(options.body);
  }
  if (state.csrfToken && options.method && options.method !== "GET") headers["X-CSRF-Token"] = state.csrfToken;
  const timeoutController = new AbortController();
  const timeout = setTimeout(() => timeoutController.abort(), timeoutMs);
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
    demo_read_only: "This public demo is read-only. No changes were made.",
    invalid_credentials: "The email address or password is incorrect.",
    invalid_password: "Passwords must contain between 12 and 256 characters.",
    too_many_attempts: "Too many sign-in attempts. Please wait and try again.",
    too_many_mfa_attempts: "Too many verification attempts. Wait a few minutes and try again.",
    too_many_security_actions: "Too many account-security changes were requested. Wait a few minutes and try again.",
    invalid_mfa_challenge: "This verification request expired. Sign in again.",
    invalid_mfa_code: "That authenticator or recovery code is not valid.",
    invalid_mfa_secret: "Nimbus could not read the stored authenticator secret.",
    mfa_already_enabled: "Two-factor authentication is already enabled.",
    mfa_not_enabled: "Two-factor authentication is not enabled for this account.",
    mfa_enrollment_required: "Two-factor authentication must be configured before this account can continue.",
    mfa_required_by_policy: "Two-factor authentication is required by the platform security policy and cannot be disabled.",
    invalid_security_policy: "Choose valid Security Center policy settings.",
    mfa_setup_expired: "The setup window expired. Start two-factor setup again.",
    mfa_self_reset_forbidden: "Use your own account settings to disable two-factor authentication.",
    session_not_found: "That session has already ended.",
    current_password_invalid: "Your current password is incorrect.",
    api_access_disabled: "An administrator has not enabled API access for this account.",
    invalid_api_key_name: "Enter a name between 1 and 100 characters for this API key.",
    invalid_api_key_groups: "Choose only permission groups enabled for your account.",
    invalid_api_key_resources: "One of the selected resources is no longer available to this API policy.",
    api_key_resources_required: "Choose at least one VM or container for resource permissions.",
    invalid_api_key_expiry: "Choose an API key expiry date in the future.",
    api_key_expiry_required: "Your administrator requires every API key to expire.",
    api_key_expiry_too_long: "The expiry date exceeds the maximum lifetime set by your administrator.",
    api_key_limit_reached: "The maximum number of active API keys has been reached.",
    api_key_not_found: "That API key is no longer available.",
    invalid_api_policy_groups: "Choose valid maximum permission groups for this user.",
    invalid_api_policy_resources: "One of the selected resources is not visible to this user.",
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
    iso_mount_not_found: "Mount one of your ISO images before scheduling an ISO boot.",
    iso_boot_already_armed: "A one-time ISO boot is already scheduled for this VM.",
    iso_boot_not_found: "No one-time ISO boot is currently scheduled.",
    boot_order_changed: "The VM boot order changed outside Nimbus. An administrator must review it before Nimbus can restore it.",
    invalid_boot_order: "Nimbus could not create a safe boot order for this VM.",
    iso_mounted: "Eject this ISO before deleting it.",
    iso_delete_disabled: "Customer ISO deletion is disabled for this storage.",
    iso_operation_in_progress: "That ISO operation is still in progress.",
    too_many_uploads: "Too many ISO uploads were started. Please wait before trying again.",
    iso_policy_in_use: "Disable this policy instead; customer ISO records still use it.",
    resource_iso_mounted: "Eject the customer ISO before changing this VM assignment.",
    resource_iso_boot_active: "Restore the VM's normal boot order before changing this assignment.",
    customer_iso_images_exist: "Delete this customer's ISO images before deleting the customer account.",
    invalid_snapshot_name: "Use 1-80 letters, numbers, dots, underscores, or hyphens for the snapshot name.",
    invalid_snapshot_limit: "The snapshot limit must be a whole number between 1 and 50.",
    snapshot_exists: "A snapshot with that name already exists.",
    snapshot_not_found: "That snapshot no longer exists. Refresh the instance and try again.",
    snapshot_limit_reached: "This server has reached its configured snapshot limit.",
    snapshot_confirmation_mismatch: "Type the exact snapshot name to confirm this operation.",
    snapshot_memory_qemu_only: "Saving memory state is available only for QEMU virtual machines.",
    snapshot_memory_requires_running: "The VM must be running to include its memory state.",
    snapshot_media_conflict: "Restore the normal boot order and eject the ISO before creating or restoring snapshots.",
    email_not_configured: "Save the SMTP settings before testing email delivery.",
    email_disabled: "Email delivery is currently disabled.",
    invalid_email_address: "Enter a valid email address.",
    email_in_use: "A Nimbus account already uses that email address.",
    customer_disabled: "Activate the customer account before sending an invitation.",
    invalid_smtp_host: "Enter an SMTP hostname without a protocol or path.",
    invalid_smtp_port: "The SMTP port must be between 1 and 65535.",
    invalid_smtp_security: "Choose TLS or STARTTLS encryption.",
    invalid_smtp_username: "The SMTP username is invalid.",
    invalid_smtp_password: "The SMTP password is invalid.",
    smtp_password_required: "Enter the SMTP password for this authenticated account.",
    invalid_sender_name: "The sender name must contain between 1 and 100 characters.",
    invalid_email_message: "The test email details are invalid.",
    email_too_large: "The generated email is too large.",
    too_many_email_tests: "Too many email tests were requested. Wait a few minutes and try again.",
    too_many_email_connection_tests: "Too many SMTP connection checks were requested. Save the settings after correcting them, or wait a few minutes.",
    too_many_test_emails: "Too many test messages were sent. Wait a few minutes before sending another.",
    smtp_dns_failed: "The SMTP hostname could not be resolved.",
    smtp_connection_failed: "Nimbus could not connect to the SMTP server.",
    smtp_connection_closed: "The SMTP server closed the connection unexpectedly.",
    smtp_timeout: "The SMTP server did not respond before the timeout.",
    smtp_tls_failed: "The SMTP certificate could not be verified.",
    smtp_starttls_unavailable: "This server does not offer STARTTLS. Check the port and encryption mode.",
    smtp_auth_failed: "The SMTP server rejected the username or password.",
    smtp_auth_unsupported: "The SMTP server does not support AUTH PLAIN or AUTH LOGIN.",
    smtp_sender_rejected: "The SMTP server rejected the configured sender address.",
    smtp_recipient_rejected: "The SMTP server rejected the test recipient.",
    smtp_temporary_failure: "The SMTP server is temporarily unavailable. Nimbus will retry queued messages.",
    smtp_protocol_failed: "The SMTP server returned an unexpected response.",
    smtp_delivery_failed: "The SMTP server rejected the message.",
    email_payload_unavailable: "The queued email content is no longer available.",
    email_job_not_found: "That email delivery record no longer exists.",
    email_job_not_retryable: "That email can no longer be retried.",
    invalid_app_url: "Enter the public HTTPS URL customers use to open this panel.",
    account_link_url_missing: "Configure the public panel URL in Email Center before sending account links.",
    too_many_invitations: "Too many invitations were requested. Wait a few minutes and try again.",
    account_token_invalid: "This account link is invalid, expired, revoked, or already used.",
    too_many_account_token_attempts: "Too many account-link attempts were made. Wait a few minutes and try again.",
    password_confirmation_mismatch: "The two passwords do not match.",
    invitation_not_pending: "This account has already completed its invitation.",
    password_not_set: "This account must complete its invitation before password recovery can be used.",
    operations_refresh_rate_limited: "Too many full health refreshes were requested. Wait a few minutes and try again.",
    operations_incident_not_found: "That operations incident no longer exists.",
    operations_incident_resolved: "That incident was automatically resolved before it could be acknowledged.",
    invalid_maintenance_kind: "Choose planned maintenance or a service incident.",
    invalid_maintenance_severity: "Choose a valid notice severity.",
    invalid_maintenance_title: "Enter a maintenance title with no more than 160 characters.",
    invalid_maintenance_message: "Enter a maintenance message with no more than 4,000 characters.",
    invalid_maintenance_schedule: "Choose a valid start time and an optional later end time.",
    invalid_maintenance_targets: "Choose one audience type and at least one target.",
    maintenance_target_not_found: "One of the selected maintenance targets no longer exists.",
    maintenance_not_found: "That maintenance notice no longer exists.",
    maintenance_not_editable: "Only unpublished drafts can be edited.",
    maintenance_already_published: "That maintenance notice has already been published.",
    maintenance_ended: "This maintenance window has already ended.",
    maintenance_no_recipients: "No active customer users are affected by that audience. Check assignments and customer users.",
    maintenance_not_resolvable: "Only active or scheduled maintenance can be resolved.",
    maintenance_not_cancellable: "Only a draft or scheduled notice can be cancelled.",
    maintenance_not_deletable: "Only unpublished drafts can be deleted.",
    maintenance_publish_rate_limited: "Too many maintenance notices were published. Wait before trying again.",
    customer_required: "Only customer accounts can create support tickets.",
    invalid_ticket_subject: "Enter a clear ticket subject containing 3-160 characters.",
    invalid_ticket_category: "Choose a valid support category.",
    invalid_ticket_priority: "Choose a valid support priority.",
    invalid_ticket_resource: "That server is not assigned to this customer account.",
    invalid_ticket_message: "Enter a support message containing no more than 8,000 characters.",
    invalid_ticket_status: "Choose a valid support status.",
    invalid_ticket_assignee: "Choose an active administrator.",
    support_ticket_not_found: "That support ticket does not exist or is outside your customer account.",
    support_ticket_not_replyable: "Reopen this ticket before adding another reply.",
    support_ticket_not_reopenable: "Only resolved or closed tickets can be reopened.",
    support_ticket_rate_limited: "Too many support tickets were opened. Wait before creating another.",
    support_message_rate_limited: "Too many support replies were sent. Wait before trying again.",
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
  const demo = mode === "demo" || mode === "demo_read_only";
  els.connectionHealth.className = `connection-card ${demo ? "demo" : ""}`;
  els.healthTitle.textContent = mode === "demo_read_only" ? "Public read-only demo" : mode === "demo" ? "Interactive demo" : "Connected securely";
  els.healthDetail.textContent = mode === "demo_read_only" ? "Safe fictional infrastructure" : mode === "demo" ? "Safe simulated Proxmox data" : "Official Proxmox API";
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
    setDemoReadOnly(result.demoReadOnly);
    state.user = result.user;
    state.csrfToken = result.csrfToken;
    setAuthenticated(true);
    applyUser();
    await loadDashboard();
    route();
  } catch (error) {
    setDemoReadOnly(error.payload?.demoReadOnly);
    setAuthenticated(false);
  }
}

async function loadDashboard() {
  state.dashboard = await apiFetch("/api/v1/dashboard");
  setDemoReadOnly(state.dashboard.demoReadOnly);
  if (state.currentView !== "notifications") state.notifications = null;
  if (state.currentView !== "maintenance") state.maintenance = null;
  if (state.currentView !== "support") state.support = null;
  state.user = state.dashboard.user;
  mergeNetworkAddresses(state.dashboard.resources, state.network);
  state.lastUpdatedAt = Date.now();
  els.instanceCount.textContent = state.dashboard.resources.length;
  const unread = Number(state.dashboard.notifications?.unread || 0);
  els.notificationCount.textContent = unread > 99 ? "99+" : String(unread);
  els.notificationCount.hidden = unread === 0;
  const maintenanceUnread = Number(state.dashboard.maintenance?.unread || 0);
  els.maintenanceCount.textContent = maintenanceUnread > 99 ? "99+" : String(maintenanceUnread);
  els.maintenanceCount.hidden = maintenanceUnread === 0;
  const supportUnread = Number(state.dashboard.support?.unread || 0);
  els.supportCount.textContent = supportUnread > 99 ? "99+" : String(supportUnread);
  els.supportCount.hidden = supportUnread === 0;
  els.lastUpdated.textContent = `Updated ${formatDate(state.lastUpdatedAt)}`;
  setConnection(state.dashboard.mode);
  applyUser();
  scheduleTaskPolling();
  scheduleNetworkDiscovery();
}

async function loadNotifications() {
  state.notifications = await apiFetch("/api/v1/notifications?limit=50");
  return state.notifications;
}

async function loadNetwork({ force = false } = {}) {
  if (networkLoadPromise) return networkLoadPromise;
  if (!force && state.network && Date.now() - networkLoadedAt < networkRefreshMs) {
    mergeNetworkAddresses(state.dashboard?.resources, state.network);
    return state.network;
  }
  networkLoading = true;
  networkLoadPromise = apiFetch("/api/v1/network")
    .then((result) => {
      state.network = result;
      networkLoadedAt = Date.now();
      mergeNetworkAddresses(state.dashboard?.resources, result);
      return result;
    })
    .finally(() => {
      networkLoading = false;
      networkLoadPromise = null;
    });
  return networkLoadPromise;
}

function scheduleNetworkDiscovery() {
  if (!state.user || state.dashboard?.security?.mfa?.enrollmentRequired) return;
  if (state.network && Date.now() - networkLoadedAt < networkRefreshMs) return;
  void loadNetwork({ force: true }).then(() => {
    if (["overview", "instances", "network"].includes(state.currentView)) route();
  }).catch(() => {
    // Preserve the last successful discovery. The Network page exposes details
    // when a guest agent or Proxmox permission is unavailable.
  });
}

function resourceAddressLabel(resource) {
  if (resource.ip) return resource.ip;
  const known = Boolean(state.network?.networks && Object.hasOwn(state.network.networks, resource.id));
  return networkLoading && !known ? "Discovering…" : "Unavailable";
}

async function loadMaintenance() {
  state.maintenance = await apiFetch("/api/v1/maintenance?limit=100");
  return state.maintenance;
}

function supportTicketIdFromHash() {
  const match = location.hash.replace(/^#/, "").match(/^support\/(.+)$/);
  if (!match) return null;
  try { return decodeURIComponent(match[1]); } catch { return null; }
}

async function loadSupport(ticketId = supportTicketIdFromHash()) {
  const listing = await apiFetch("/api/v1/support/tickets?limit=100");
  let selected = null;
  if (ticketId) {
    selected = await apiFetch(`/api/v1/support/tickets/${encodeURIComponent(ticketId)}`);
    if (selected.ticket?.unread && !state.demoReadOnly) {
      await apiFetch(`/api/v1/support/tickets/${encodeURIComponent(ticketId)}/read`, { method: "POST", body: {} });
      selected.ticket.unread = false;
      const listed = listing.tickets?.items?.find((ticket) => ticket.id === ticketId);
      if (listed) listed.unread = false;
      listing.tickets.unread = Math.max(0, Number(listing.tickets.unread || 0) - 1);
    }
  }
  state.support = { ...listing, selected };
  els.supportCount.textContent = Number(listing.tickets?.unread || 0) > 99 ? "99+" : String(listing.tickets?.unread || 0);
  els.supportCount.hidden = !Number(listing.tickets?.unread || 0);
  return state.support;
}

async function loadAdmin() {
  state.admin = await apiFetch("/api/admin/state");
  setDemoReadOnly(state.admin.demoReadOnly);
}

async function loadApiKeys() {
  state.apiKeys = await apiFetch("/api/v1/api-keys");
  return state.apiKeys;
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

function maintenanceStatusLabel(status) {
  return ({
    draft: "Draft",
    scheduled: "Scheduled",
    active: "In progress",
    resolved: "Resolved",
    cancelled: "Cancelled",
  })[status] || status;
}

function maintenanceSchedule(item) {
  const start = formatDate(item.startsAt);
  if (item.status === "resolved") return item.resolvedAt ? `Resolved ${formatDate(item.resolvedAt)}` : `Completed after ${start}`;
  if (item.status === "cancelled") return `Cancelled · originally ${start}`;
  if (item.endsAt) return `${start} — ${formatDate(item.endsAt)}`;
  return `${start} — until further notice`;
}

function maintenanceBanner() {
  const items = (state.dashboard.maintenance?.items || [])
    .filter((item) => ["active", "scheduled"].includes(item.status))
    .slice(0, 3);
  if (!items.length) return "";
  const highest = items.some((item) => item.severity === "critical") ? "critical"
    : items.some((item) => item.severity === "warning") ? "warning"
      : "info";
  return `<section class="maintenance-overview-banner ${highest}">
    <span class="maintenance-banner-icon">${highest === "critical" ? "!" : "△"}</span>
    <div>
      <p class="eyebrow">${items.some((item) => item.status === "active") ? "Active service notice" : "Upcoming maintenance"}</p>
      <h2>${escapeHtml(items[0].title)}</h2>
      <p>${escapeHtml(items[0].message)}</p>
      <small>${escapeHtml(maintenanceSchedule(items[0]))}${items.length > 1 ? ` · ${items.length - 1} more notice${items.length === 2 ? "" : "s"}` : ""}</small>
    </div>
    <a class="button secondary small" href="#maintenance">View details</a>
  </section>`;
}

function renderOverview() {
  const resources = filteredResources().slice(0, 6);
  els.viewRoot.innerHTML = `${maintenanceBanner()}${metricCards()}<section class="layout-grid overview-primary"><article class="panel"><header class="panel-header"><div><h2>${state.user.role === "admin" ? "Infrastructure inventory" : "Your infrastructure"}</h2><p>Individually assigned guests, resolved by the panel.</p></div><a class="text-link" href="#instances">View all →</a></header>${resourceTable(resources, { compact: true })}</article><aside class="panel"><header class="panel-header"><div><h2>Recent activity</h2><p>Audited account events.</p></div></header>${activityMarkup(state.dashboard.activity.items)}</aside></section>`;
}

function renderInstances() {
  const resources = filteredResources();
  els.viewRoot.innerHTML = resources.length ? `<section class="instance-grid">${resources.map((resource) => `<article class="instance-card"><div class="card-title">${resourceIdentity(resource)}${statusMarkup(resource)}</div><div class="instance-stats"><div class="mini-stat"><small>CPU</small><strong>${pct(resource.cpu)}</strong></div><div class="mini-stat"><small>Memory</small><strong>${resource.memoryUsed} / ${resource.memory} GB</strong></div><div class="mini-stat"><small>Storage</small><strong>${escapeHtml(storageSummary(resource))}</strong></div><div class="mini-stat"><small>Address</small><strong>${escapeHtml(resourceAddressLabel(resource))}</strong></div></div><div class="instance-actions">${actionButtons(resource)}</div></article>`).join("")}</section>` : emptyState("▤", "No resources assigned", "Ask an administrator to assign a VM or container directly to your customer account.");
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
  const boot = media?.boot || null;
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
  const bootButton = mounted && can(resource, "iso_boot") && !boot
    ? `<button class="button primary small" data-arm-iso-boot>Boot ISO once</button>`
    : "";
  const ejectButton = mounted && can(resource, "iso_mount")
    ? `<button class="button secondary small" data-eject-iso>${boot ? "Restore & eject" : "Eject"}</button>`
    : "";
  const mountedMarkup = mounted
    ? `<div class="mounted-media"><span class="media-icon">◎</span><span><small>Mounted in ${escapeHtml(mounted.driveSlot)}</small><strong>${escapeHtml(mounted.originalName || mounted.fileName)}</strong><em>Mounted ${escapeHtml(formatRelative(mounted.mountedAt))}</em></span><div class="media-actions">${bootButton}${ejectButton}</div></div>`
    : `<div class="mounted-media empty"><span class="media-icon">○</span><span><small>Virtual CD/DVD drive</small><strong>No ISO mounted</strong><em>Select a ready image from the library below.</em></span></div>`;
  const bootMarkup = boot
    ? `<div class="iso-boot-state ${boot.status === "error" ? "error" : ""}">
        <span class="media-icon">${boot.status === "error" ? "!" : "↥"}</span>
        <span><small>${boot.status === "error" ? "Restoration needs attention" : "One-time boot ready"}</small><strong>${boot.status === "error" ? "Nimbus could not verify the original boot order" : `The mounted ISO will boot first on the next ${resource.status === "running" ? "reboot" : "start"}.`}</strong><em>${boot.status === "error" ? "The boot order may have changed outside Nimbus." : "Nimbus restores the previous order after the power task completes."}</em></span>
        ${can(resource, "iso_boot") ? `<button class="button secondary small" data-cancel-iso-boot>${boot.status === "error" ? "Retry restore" : "Cancel"}</button>` : ""}
      </div>`
    : "";
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
    <div class="installation-media-body">${mountedMarkup}${bootMarkup}${uploadMarkup}${uploadProgress}${library}</div>
  </section>`;
}

function snapshotCenterMarkup(resource, details, pending) {
  const snapshotPermissions = ["snapshot_create", "snapshot_restore", "snapshot_delete"];
  if (!snapshotPermissions.some((permission) => can(resource, permission))) return "";
  const snapshots = details.snapshots || [];
  const policy = details.snapshotPolicy || { limit: resource.snapshotLimit || 3, count: snapshots.length, remaining: Math.max(0, (resource.snapshotLimit || 3) - snapshots.length) };
  const mediaConflict = Boolean(state.instance.media?.mounted || state.instance.media?.boot);
  const snapshotBusy = Boolean(pending);
  const createDisabled = snapshotBusy || mediaConflict || policy.remaining < 1;
  const createReason = mediaConflict
    ? "Restore the normal boot order and eject the mounted ISO first."
    : policy.remaining < 1
      ? `The ${policy.limit}-snapshot limit has been reached.`
      : snapshotBusy
        ? "Wait for the current Proxmox task to finish."
        : "";
  const createButton = can(resource, "snapshot_create")
    ? `<button class="button primary small" data-create-snapshot ${createDisabled ? "disabled" : ""} ${createReason ? `title="${escapeHtml(createReason)}"` : ""}>Create snapshot</button>`
    : "";
  const items = snapshots.length
    ? `<div class="snapshot-list">${snapshots.map((snapshot, index) => {
      const restoreDisabled = snapshotBusy || mediaConflict;
      return `<article class="snapshot-item">
        <span class="snapshot-icon">↶</span>
        <span class="snapshot-copy">
          <strong>${escapeHtml(snapshot.name)}</strong>
          <small>${escapeHtml(snapshot.description || "No description")}</small>
          <em>${escapeHtml(formatDate(snapshot.createdAt))}${snapshot.includesMemory ? " · includes memory" : ""}${snapshot.parent ? ` · parent ${escapeHtml(snapshot.parent)}` : index === snapshots.length - 1 ? " · base snapshot" : ""}</em>
        </span>
        <div class="snapshot-actions">
          ${snapshot.includesMemory ? `<span class="pill">Memory</span>` : ""}
          ${can(resource, "snapshot_restore") ? `<button class="row-button" data-restore-snapshot="${escapeHtml(snapshot.name)}" ${restoreDisabled ? "disabled" : ""}>Restore</button>` : ""}
          ${can(resource, "snapshot_delete") ? `<button class="row-button danger" data-delete-snapshot="${escapeHtml(snapshot.name)}" ${snapshotBusy ? "disabled" : ""}>Delete</button>` : ""}
        </div>
      </article>`;
    }).join("")}</div>`
    : `<div class="detail-empty compact"><span>↶</span><strong>No snapshots yet</strong><small>Create a short-term recovery point before an upgrade or configuration change.</small></div>`;
  const warning = mediaConflict
    ? `<div class="notice warning snapshot-notice"><span>!</span><span>Snapshot creation and restoration are paused while customer ISO media is mounted or a one-time boot is armed.</span></div>`
    : `<div class="notice snapshot-notice"><span>i</span><span>Snapshots live with the server's disks and are not a replacement for an independent Proxmox backup.</span></div>`;
  return `<section class="panel snapshot-center-panel">
    <header class="panel-header">
      <div><h2>Snapshot Center</h2><p>Short-term recovery points managed through Proxmox.</p></div>
      <div class="snapshot-header-actions"><span class="pill ${policy.remaining < 1 ? "warning" : ""}">${policy.count} / ${policy.limit} used</span>${createButton}</div>
    </header>
    <div class="snapshot-center-body">${warning}${items}</div>
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
  const storageKnown = storageUsageKnown(resource);
  const storagePercent = storageKnown ? percent(resource.storageUsed, resource.storage) : 0;
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
      ${pending ? `<div class="task-progress-banner"><span class="button-spinner" aria-hidden="true"></span><span><strong>${escapeHtml(actionProgressTitle(pending.action))}</strong><small>Nimbus is following the Proxmox task automatically. Other operations are paused until it finishes.</small></span><span>${escapeHtml(formatRelative(pending.createdAt))}</span></div>` : ""}
    </section>

    <section class="instance-metric-grid">
      <article><span class="detail-metric-icon cpu">⌁</span><span><small>CPU usage</small><strong>${Math.round(resource.cpu)}%</strong><em>${resource.vcpu} vCPU</em></span><div class="detail-meter"><i style="width:${pct(resource.cpu)}"></i></div></article>
      <article><span class="detail-metric-icon memory">◫</span><span><small>Memory</small><strong>${resource.memoryUsed} GB</strong><em>of ${resource.memory} GB</em></span><div class="detail-meter memory"><i style="width:${pct(memoryPercent)}"></i></div></article>
      <article><span class="detail-metric-icon storage">▰</span><span><small>Storage</small><strong>${storageKnown ? `${resource.storageUsed} GB` : "Unavailable"}</strong><em>${storageKnown ? `of ${resource.storage} GB${resource.storageUsageStale ? " · last known" : ""}` : `${resource.storage} GB assigned · Guest Agent access required`}</em></span><div class="detail-meter storage"><i style="width:${pct(storagePercent)}"></i></div></article>
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
    ${snapshotCenterMarkup(resource, details, pending)}
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
  const theme = getComputedStyle(document.documentElement);
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
    context.strokeStyle = theme.getPropertyValue("--chart-grid").trim() || "#e8ebf2";
    context.beginPath();
    context.moveTo(padding.left, y);
    context.lineTo(width - padding.right, y);
    context.stroke();
    context.fillStyle = theme.getPropertyValue("--chart-label").trim() || "#969eb0";
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
  drawLine("cpu", theme.getPropertyValue("--chart-cpu").trim() || "#5d68ec");
  drawLine("memory", theme.getPropertyValue("--chart-memory").trim() || "#36aa82");
}

function networkDiscoveryMessage(network, resource) {
  if (network?.source === "guest_agent") return { tone: "success", text: "Live address reported by QEMU Guest Agent." };
  if (network?.source === "guest") return { tone: "success", text: "Live address reported by the container." };
  if (network?.source === "configuration" && network.status === "stopped") return { tone: "neutral", text: "Configured static address; the guest is currently stopped." };
  if (network?.source === "configuration") return { tone: "neutral", text: "Configured static address; live guest discovery is unavailable." };
  if (network?.status === "stopped") return { tone: "neutral", text: "The guest is stopped and has no configured static address." };
  if (network?.status === "permission_required") return {
    tone: "warning",
    text: resource.type === "qemu"
      ? "The Proxmox API token needs VM.GuestAgent.Audit for live QEMU network information."
      : "The Proxmox API token cannot read this container's network information.",
  };
  if (network?.status === "guest_agent_unavailable" && resource.type === "qemu") return { tone: "warning", text: "QEMU Guest Agent did not report an address. Static Cloud-Init addresses are used as a fallback." };
  if (network?.status === "network_unavailable") return { tone: "warning", text: "The container did not report an address and has no configured static address." };
  if (network?.status === "unavailable") return { tone: "warning", text: "Network discovery is temporarily unavailable." };
  return { tone: "neutral", text: "No usable guest address was reported." };
}

function renderNetwork() {
  const resources = filteredResources();
  els.viewRoot.innerHTML = resources.length ? `<section class="network-grid">${resources.map((resource) => {
    const network = state.network?.networks?.[resource.id] || {};
    const primaryIp = network.primaryIp || resource.ip;
    const discovery = networkDiscoveryMessage(network, resource);
    const additional = Math.max(0, Number(network.addresses?.length || 0) - (primaryIp ? 1 : 0));
    return `<article class="network-card"><div class="card-title">${resourceIdentity(resource)}${statusMarkup(resource)}</div><ul class="network-addresses"><li><small>Primary address</small><span>${escapeHtml(primaryIp || "Not reported")}${additional ? `<em>+${additional} more</em>` : ""}</span></li><li><small>Cluster / node</small><span>${escapeHtml(resource.clusterId)} / ${escapeHtml(resource.node)}</span></li><li><small>Guest identity</small><span>${resource.type.toUpperCase()} ${resource.vmid}</span></li></ul><p class="network-discovery ${discovery.tone}"><span aria-hidden="true"></span>${escapeHtml(discovery.text)}</p></article>`;
  }).join("")}</section>` : emptyState("⌘", "No network information", "Assigned resources will appear here.");
}

function renderActivity() {
  els.viewRoot.innerHTML = `<section class="panel"><header class="panel-header"><div><h2>Audit trail</h2><p>Recent actions visible to this account.</p></div><span class="pill">Append-only</span></header>${activityMarkup(state.dashboard.activity.items)}</section>`;
}

function notificationMarkup(items = []) {
  if (!items.length) return emptyState("✦", "All quiet", "Infrastructure alerts, recoveries, and completed actions will appear here.");
  return `<div class="notification-list">${items.map((item) => {
    const resource = item.resourceId && state.dashboard.resources.find((entry) => entry.id === item.resourceId);
    const icon = item.severity === "critical" ? "!" : item.severity === "warning" ? "△" : item.severity === "success" ? "✓" : "✦";
    return `<article class="notification-item ${item.readAt ? "" : "unread"} ${escapeHtml(item.severity)}">
      <span class="notification-icon">${icon}</span>
      <span class="notification-copy">
        <span class="notification-heading"><strong>${escapeHtml(item.title)}</strong>${item.readAt ? "" : `<i>New</i>`}</span>
        <p>${escapeHtml(item.message)}</p>
        <small>${item.resourceName ? `${escapeHtml(item.resourceName)} · ` : ""}${escapeHtml(formatDate(item.createdAt))}</small>
      </span>
      <span class="notification-actions">
        ${resource ? `<button class="row-button" data-details="${escapeHtml(resource.id)}">View server</button>` : ""}
        ${item.readAt ? "" : `<button class="row-button" data-read-notification="${escapeHtml(item.id)}">Mark read</button>`}
      </span>
    </article>`;
  }).join("")}</div>`;
}

function renderNotifications() {
  const result = state.notifications || {
    notifications: state.dashboard.notifications,
    preferences: state.dashboard.notificationPreferences,
    emailDeliveryAvailable: state.dashboard.emailDeliveryAvailable,
  };
  if (!result?.notifications) {
    els.viewRoot.innerHTML = `<div class="loading-inline"><span class="spinner"></span>Loading notifications</div>`;
    loadNotifications().then(renderNotifications).catch((error) => showToast("error", "Could not load notifications", friendlyError(error)));
    return;
  }
  const preferences = result.preferences || {};
  const emailAvailable = Boolean(result.emailDeliveryAvailable);
  els.viewRoot.innerHTML = `<section class="notification-layout">
    <article class="panel notification-center-panel">
      <header class="panel-header"><div><h2>Notification center</h2><p>Private to this login and never shared across customers.</p></div><div class="panel-actions"><span class="pill ${result.notifications.unread ? "warning" : "success"}">${plural(result.notifications.unread || 0, "unread")}</span>${result.notifications.unread ? `<button class="button secondary small" data-read-all-notifications>Mark all read</button>` : ""}</div></header>
      ${notificationMarkup(result.notifications.items)}
    </article>
    <form class="panel form-panel notification-preferences" id="notificationPreferencesForm">
      <h2>Delivery preferences</h2><p>Choose what this login receives. Email is opt-in.</p>
      <div class="preference-list">
        <label class="policy-checkbox"><input name="inAppEnabled" type="checkbox" ${preferences.inAppEnabled ? "checked" : ""}><span><strong>In-panel notifications</strong><small>Show events in this private notification center.</small></span></label>
        <label class="policy-checkbox"><input name="emailEnabled" type="checkbox" ${preferences.emailEnabled ? "checked" : ""}><span><strong>Email notifications</strong><small>${emailAvailable ? `Send to ${escapeHtml(state.user.email)}.` : "You can opt in now; delivery begins after an administrator enables SMTP."}</small></span></label>
        <label class="policy-checkbox"><input name="actionSuccess" type="checkbox" ${preferences.actionSuccess ? "checked" : ""}><span><strong>Successful actions</strong><small>Power and snapshot tasks that complete successfully.</small></span></label>
        <label class="policy-checkbox"><input name="actionFailure" type="checkbox" ${preferences.actionFailure ? "checked" : ""}><span><strong>Failed actions</strong><small>Proxmox tasks that finish with an error.</small></span></label>
        <label class="policy-checkbox"><input name="infrastructureAlerts" type="checkbox" ${preferences.infrastructureAlerts ? "checked" : ""}><span><strong>Infrastructure alerts</strong><small>Offline, CPU, memory, and storage conditions enabled by your administrator.</small></span></label>
        <label class="policy-checkbox"><input name="resolutionAlerts" type="checkbox" ${preferences.resolutionAlerts ? "checked" : ""}><span><strong>Recovery notices</strong><small>Confirmation when an active alert returns to normal.</small></span></label>
      </div>
      <div class="form-actions"><button class="button primary">Save preferences</button><p class="form-message"></p></div>
    </form>
  </section>`;
}

function maintenanceItemMarkup(item, { admin = false } = {}) {
  const targets = (item.targets || []).map((target) => target.label).join(", ");
  const icon = item.status === "resolved" ? "✓"
    : item.status === "cancelled" ? "×"
      : item.severity === "critical" ? "!"
        : "△";
  const actions = admin
    ? `<div class="maintenance-admin-actions">
        ${item.status === "draft" ? `<button class="row-button" data-edit-maintenance="${escapeHtml(item.id)}">Edit</button><button class="row-button" data-publish-maintenance="${escapeHtml(item.id)}">Publish</button><button class="row-button danger" data-delete-maintenance="${escapeHtml(item.id)}">Delete</button>` : ""}
        ${item.status === "scheduled" ? `<button class="row-button" data-resolve-maintenance="${escapeHtml(item.id)}">Resolve now</button><button class="row-button danger" data-cancel-maintenance="${escapeHtml(item.id)}">Cancel</button>` : ""}
        ${item.status === "active" ? `<button class="row-button" data-resolve-maintenance="${escapeHtml(item.id)}">Mark resolved</button>` : ""}
      </div>`
    : item.readAt
      ? ""
      : `<button class="row-button" data-read-maintenance="${escapeHtml(item.deliveryId)}">Mark read</button>`;
  return `<article class="maintenance-item ${escapeHtml(item.status)} ${escapeHtml(item.severity)} ${item.readAt || admin ? "" : "unread"}">
    <span class="maintenance-item-icon">${icon}</span>
    <div class="maintenance-item-copy">
      <div class="maintenance-item-heading">
        <span class="pill ${item.status === "resolved" ? "success" : ["critical", "warning"].includes(item.severity) ? "warning" : ""}">${escapeHtml(maintenanceStatusLabel(item.status))}</span>
        <span class="maintenance-kind">${item.kind === "incident" ? "Service incident" : "Planned maintenance"}</span>
        ${!admin && !item.readAt ? `<i>New</i>` : ""}
      </div>
      <h3>${escapeHtml(item.title)}</h3>
      <p>${escapeHtml(item.message).replace(/\r?\n/g, "<br>")}</p>
      <div class="maintenance-item-meta">
        <span><strong>Window</strong>${escapeHtml(maintenanceSchedule(item))}</span>
        ${admin ? `<span><strong>Audience</strong>${escapeHtml(targets || "No target")}</span><span><strong>Recipients</strong>${plural(item.recipientCount || 0, "user")}${item.notifyEmail ? " · email enabled" : " · in-panel only"}</span>` : ""}
      </div>
    </div>
    ${actions}
  </article>`;
}

function renderMaintenance() {
  const result = state.maintenance || { maintenance: state.dashboard.maintenance };
  if (!result?.maintenance) {
    els.viewRoot.innerHTML = `<div class="loading-inline"><span class="spinner"></span>Loading maintenance notices</div>`;
    loadMaintenance().then(renderMaintenance).catch((error) => showToast("error", "Could not load maintenance", friendlyError(error)));
    return;
  }
  const notices = result.maintenance;
  const active = notices.items.filter((item) => ["active", "scheduled"].includes(item.status));
  const history = notices.items.filter((item) => !["active", "scheduled"].includes(item.status));
  els.viewRoot.innerHTML = `<section class="maintenance-status-hero ${notices.activeCount ? "active" : ""}">
      <span>${notices.activeCount ? "!" : "✓"}</span>
      <div><p class="eyebrow">Service status</p><h2>${notices.activeCount ? plural(notices.activeCount, "active notice") : notices.upcomingCount ? plural(notices.upcomingCount, "scheduled window") : "All systems available"}</h2><p>${notices.activeCount ? "Review the active work or incident below." : notices.upcomingCount ? "Your affected maintenance windows are shown below." : "There is no active or upcoming maintenance for your assigned infrastructure."}</p></div>
      <span class="pill ${notices.unread ? "warning" : "success"}">${plural(notices.unread || 0, "unread")}</span>
    </section>
    <section class="panel maintenance-center-panel">
      <header class="panel-header"><div><h2>Active & upcoming</h2><p>Only notices mapped to your customer account are visible here.</p></div><span class="pill">${active.length}</span></header>
      <div class="maintenance-list">${active.length ? active.map((item) => maintenanceItemMarkup(item)).join("") : emptyState("✓", "No affected maintenance", "Nimbus will show scheduled work and active incidents here.")}</div>
    </section>
    <section class="panel maintenance-center-panel">
      <header class="panel-header"><div><h2>Maintenance history</h2><p>Resolved and cancelled notices that were previously published to this login.</p></div><span class="pill">${history.length}</span></header>
      <div class="maintenance-list">${history.length ? history.map((item) => maintenanceItemMarkup(item)).join("") : emptyState("△", "No maintenance history", "Completed notices will remain available here.")}</div>
    </section>`;
}

function supportStatusLabel(status) {
  return ({
    open: "Open",
    waiting_support: "Waiting for support",
    waiting_customer: "Waiting for customer",
    resolved: "Resolved",
    closed: "Closed",
  })[status] || status;
}

function supportPriorityLabel(priority) {
  return priority === "urgent" ? "Urgent" : priority === "high" ? "High" : priority === "low" ? "Low" : "Normal";
}

function supportTicketListMarkup(tickets) {
  if (!tickets.length) return emptyState("?", "No support tickets", state.user.role === "admin"
    ? "New customer requests will appear in this queue."
    : "Open a ticket when you need help with your managed infrastructure.");
  return `<div class="support-ticket-list">${tickets.map((ticket) => `
    <button class="support-ticket-row ${ticket.unread ? "unread" : ""} ${state.support?.selected?.ticket?.id === ticket.id ? "active" : ""}" type="button" data-open-support="${escapeHtml(ticket.id)}">
      <span class="support-ticket-row-top"><strong>${escapeHtml(ticket.subject)}</strong>${ticket.unread ? "<i>New</i>" : ""}</span>
      <span class="support-ticket-row-reference">${escapeHtml(ticket.reference)}${state.user.role === "admin" ? ` · ${escapeHtml(ticket.customerName)}` : ""}</span>
      <span class="support-ticket-row-bottom">
        <span class="support-status ${escapeHtml(ticket.status)}">${escapeHtml(supportStatusLabel(ticket.status))}</span>
        <span class="support-priority ${escapeHtml(ticket.priority)}">${escapeHtml(supportPriorityLabel(ticket.priority))}</span>
        <small>${escapeHtml(formatRelative(ticket.lastMessageAt))}</small>
      </span>
    </button>`).join("")}</div>`;
}

function supportCreateMarkup() {
  if (state.user.role === "admin") return "";
  const resources = state.dashboard.resources || [];
  return `<details class="panel support-create-panel" ${state.support?.tickets?.total ? "" : "open"}>
    <summary><span><strong>Open a support ticket</strong><small>Describe the problem once; Nimbus keeps the complete conversation together.</small></span><span class="button primary small">New ticket</span></summary>
    <form class="support-create-form" id="supportTicketForm">
      <div class="form-grid">
        <div class="field full"><label for="supportSubject">Subject</label><input id="supportSubject" name="subject" minlength="3" maxlength="160" required placeholder="Example: VM cannot reach the internet"></div>
        <div class="field"><label for="supportCategory">Category</label><select id="supportCategory" name="category"><option value="technical">Technical</option><option value="network">Network</option><option value="account">Account</option><option value="billing">Billing</option><option value="other">Other</option></select></div>
        <div class="field"><label for="supportPriority">Priority</label><select id="supportPriority" name="priority"><option value="normal">Normal</option><option value="low">Low</option><option value="high">High</option><option value="urgent">Urgent</option></select></div>
        <div class="field full"><label for="supportResource">Related server <span>optional</span></label><select id="supportResource" name="resourceId"><option value="">General account question</option>${resources.map((resource) => `<option value="${escapeHtml(resource.id)}">${escapeHtml(resource.displayName || resource.name)} · ${resource.type.toUpperCase()} ${resource.vmid}</option>`).join("")}</select><small>Only servers assigned to this customer account are accepted by the backend.</small></div>
        <div class="field full"><label for="supportMessage">What can we help with?</label><textarea id="supportMessage" name="message" maxlength="8000" rows="6" required placeholder="Include what you expected, what happened, and when you first noticed it."></textarea></div>
      </div>
      <div class="notice warning"><span>!</span><span>Never include passwords, Proxmox tokens, private keys, or recovery codes.</span></div>
      <div class="form-actions"><button class="button primary" type="submit">Create support ticket</button><p class="form-message"></p></div>
    </form>
  </details>`;
}

function supportConversationMarkup(selected) {
  if (!selected?.ticket) {
    return `<section class="panel support-thread-panel">${emptyState("?", "Choose a ticket", state.user.role === "admin"
      ? "Select a customer request to review its conversation and ownership."
      : "Select a ticket to view replies or continue the conversation.")}</section>`;
  }
  const ticket = selected.ticket;
  const active = !["resolved", "closed"].includes(ticket.status);
  const admin = state.user.role === "admin";
  const assignees = selected.assignees || state.support.assignees || [];
  const management = admin ? `<form class="support-management" id="supportManageForm" data-ticket-id="${escapeHtml(ticket.id)}">
    <div class="field"><label>Status</label><select name="status">${["open", "waiting_support", "waiting_customer", "resolved", "closed"].map((status) => `<option value="${status}" ${ticket.status === status ? "selected" : ""}>${escapeHtml(supportStatusLabel(status))}</option>`).join("")}</select></div>
    <div class="field"><label>Priority</label><select name="priority">${["low", "normal", "high", "urgent"].map((priority) => `<option value="${priority}" ${ticket.priority === priority ? "selected" : ""}>${escapeHtml(supportPriorityLabel(priority))}</option>`).join("")}</select></div>
    <div class="field"><label>Assigned administrator</label><select name="assignedTo"><option value="">Unassigned</option>${assignees.map((assignee) => `<option value="${escapeHtml(assignee.id)}" ${ticket.assignedTo === assignee.id ? "selected" : ""}>${escapeHtml(assignee.displayName)}</option>`).join("")}</select></div>
    <button class="button secondary" type="submit">Save ticket</button>
    <p class="form-message"></p>
  </form>` : "";
  const messages = selected.messages || [];
  const conversation = messages.map((message) => `<article class="support-message ${message.authorRole} ${message.internal ? "internal" : ""}">
    <span class="support-message-avatar">${message.internal ? "•" : initials(message.authorName)}</span>
    <div class="support-message-body">
      <header><span><strong>${escapeHtml(message.authorName)}</strong><small>${message.internal ? "Internal administrator note" : message.authorRole === "admin" ? "Support team" : "Customer"}</small></span><time>${escapeHtml(formatDate(message.createdAt))}</time></header>
      <p>${escapeHtml(message.body).replace(/\r?\n/g, "<br>")}</p>
    </div>
  </article>`).join("");
  const reply = active ? `<form class="support-reply-form" id="supportReplyForm" data-ticket-id="${escapeHtml(ticket.id)}">
    <div class="field"><label for="supportReply">${admin ? "Add reply or internal note" : "Reply to support"}</label><textarea id="supportReply" name="message" maxlength="8000" rows="5" required placeholder="${admin ? "Write a customer-facing reply…" : "Add any new details here…"}"></textarea></div>
    ${admin ? `<label class="policy-checkbox support-internal-toggle"><input type="checkbox" name="internal"><span><strong>Internal note</strong><small>Visible only to administrators and never emailed to the customer.</small></span></label>` : ""}
    <div class="form-actions"><button class="button primary" type="submit">Send ${admin ? "message" : "reply"}</button>${!admin ? `<button class="button secondary" type="button" data-close-support="${escapeHtml(ticket.id)}">Close ticket</button>` : ""}<p class="form-message"></p></div>
  </form>` : `<div class="support-thread-closed"><span>✓</span><div><strong>${ticket.status === "resolved" ? "This ticket is resolved" : "This ticket is closed"}</strong><p>Reopen it if more help is required.</p></div><button class="button secondary" type="button" data-reopen-support="${escapeHtml(ticket.id)}">Reopen ticket</button></div>`;
  return `<section class="panel support-thread-panel">
    <header class="support-thread-header">
      <div><p class="eyebrow">${escapeHtml(ticket.reference)}</p><h2>${escapeHtml(ticket.subject)}</h2><p>${admin ? `${escapeHtml(ticket.customerName)} · ` : ""}${ticket.resourceName ? `${escapeHtml(ticket.resourceName)} · ${ticket.resourceType.toUpperCase()} ${ticket.vmid}` : "General support request"}</p></div>
      <div class="support-thread-badges"><span class="support-status ${escapeHtml(ticket.status)}">${escapeHtml(supportStatusLabel(ticket.status))}</span><span class="support-priority ${escapeHtml(ticket.priority)}">${escapeHtml(supportPriorityLabel(ticket.priority))}</span></div>
    </header>
    ${management}
    <div class="support-conversation">${conversation}</div>
    ${reply}
  </section>`;
}

function renderSupport() {
  const result = state.support;
  if (!result?.tickets) {
    els.viewRoot.innerHTML = `<div class="loading-inline"><span class="spinner"></span>Loading support tickets</div>`;
    loadSupport().then(renderSupport).catch((error) => showToast("error", "Could not load support tickets", friendlyError(error)));
    return;
  }
  const query = state.search.trim().toLowerCase();
  const tickets = query
    ? result.tickets.items.filter((ticket) => [ticket.reference, ticket.subject, ticket.customerName, ticket.resourceName, ticket.status, ticket.priority].some((value) => String(value || "").toLowerCase().includes(query)))
    : result.tickets.items;
  const heroTitle = state.user.role === "admin"
    ? result.tickets.waitingSupport ? `${plural(result.tickets.waitingSupport, "request")} waiting for support` : "Customer support queue is clear"
    : result.tickets.active ? `${plural(result.tickets.active, "active support ticket")}` : "Your support inbox is clear";
  els.viewRoot.innerHTML = `<section class="support-hero">
      <span class="support-hero-icon">?</span>
      <div><p class="eyebrow">${state.user.role === "admin" ? "Administrator queue" : "Private customer support"}</p><h2>${heroTitle}</h2><p>${state.user.role === "admin" ? "Every ticket is tenant-scoped, auditable, and assignable to one administrator." : "Only users in your customer account and Nimbus administrators can view these conversations."}</p></div>
      <div class="support-summary"><span><strong>${result.tickets.active}</strong><small>Active</small></span><span><strong>${result.tickets.unread}</strong><small>Unread</small></span><span><strong>${result.tickets.resolved}</strong><small>Resolved</small></span></div>
    </section>
    ${supportCreateMarkup()}
    <section class="support-workspace">
      <article class="panel support-queue-panel">
        <header class="panel-header"><div><h2>${state.user.role === "admin" ? "Ticket queue" : "Your tickets"}</h2><p>${plural(result.tickets.total, "conversation")} · newest activity first</p></div><span class="pill ${result.tickets.waitingSupport ? "warning" : "success"}">${state.user.role === "admin" ? `${result.tickets.waitingSupport} waiting` : `${result.tickets.unread} unread`}</span></header>
        ${supportTicketListMarkup(tickets)}
      </article>
      ${supportConversationMarkup(result.selected)}
    </section>`;
}

function sessionDevice(userAgent) {
  const value = String(userAgent || "");
  const browser = value.includes("Firefox/") ? "Firefox"
    : value.includes("Edg/") ? "Microsoft Edge"
      : value.includes("Chrome/") ? "Chrome"
        : value.includes("Safari/") ? "Safari"
          : "Browser";
  const platform = value.includes("Mac OS X") ? "macOS"
    : value.includes("Windows") ? "Windows"
      : value.includes("Android") ? "Android"
        : /iPhone|iPad/.test(value) ? "iOS"
          : value.includes("Linux") ? "Linux"
            : "Unknown platform";
  return `${browser} on ${platform}`;
}

function apiKeySummaryMarkup(summary, { secret = null, compact = false } = {}) {
  const selectedGroups = (summary?.permissionGroups || []).filter((group) => group.selected);
  const resources = summary?.resources || [];
  const actions = summary?.actions || [];
  const actionRows = actions.map((action) => {
    const icon = action.state === "allowed" ? "✓" : action.state === "partial" ? "◐" : "✕";
    const detail = action.state === "partial" ? ` <small>${action.allowedCount}/${action.resourceCount} resources</small>` : "";
    return `<li class="${escapeHtml(action.state)}"><span>${icon}</span><span>${escapeHtml(action.label)}${detail}</span></li>`;
  }).join("");
  return `<div class="api-key-summary ${compact ? "compact" : ""}">
    <div class="api-summary-heading"><span class="api-key-icon">⌁</span><span><small>Integration key</small><strong>${escapeHtml(summary?.name || "Untitled key")}</strong></span></div>
    ${secret ? `<div class="api-secret-once"><small>Copy this secret now — Nimbus cannot show it again</small><code>${escapeHtml(secret)}</code><button class="button secondary small" type="button" data-copy-api-secret>Copy secret</button></div>` : ""}
    <div class="api-summary-grid">
      <section><h4>Permissions</h4><ul>${selectedGroups.map((group) => `<li><span>✓</span><span>${escapeHtml(group.label)}</span></li>`).join("") || "<li><span>✕</span><span>None</span></li>"}</ul></section>
      <section><h4>Resources</h4><ul>${resources.map((resource) => `<li class="${resource.effective ? "" : "denied"}"><span>${resource.effective ? "✓" : "✕"}</span><span>${escapeHtml(resource.name)} <small>${resource.type.toUpperCase()} ${resource.vmid}</small></span></li>`).join("") || "<li><span>—</span><span>Account-wide permissions only</span></li>"}</ul></section>
      <section><h4>Expires</h4><p>${summary?.expiresAt ? escapeHtml(formatDate(summary.expiresAt, { dateOnly: true })) : "Never"}</p></section>
    </div>
    ${compact ? "" : `<section class="api-actions-summary"><h4>Allowed actions</h4><ul>${actionRows}</ul><p><span>◐</span> means the action is available on only some selected resources because assignment permissions still apply.</p></section>`}
  </div>`;
}

function apiKeyCenterMarkup(mfa) {
  const center = state.apiKeys;
  if (!center) return "";
  const policy = center.policy || {};
  if (!policy.enabled) {
    return `<section class="panel api-key-center disabled">
      <header class="panel-header"><div><p class="eyebrow">Integrations</p><h2>API keys</h2><p>Connect Home Assistant, scripts, monitoring, and other private tools without sharing your password.</p></div><span class="pill warning">Not enabled</span></header>
      <div class="notice"><span>⌁</span><span>An administrator must enable API access and choose the maximum permission groups for this account.</span></div>
    </section>`;
  }
  const resourceGroups = new Set((center.groups || []).filter((group) => group.resourceScoped).map((group) => group.id));
  const defaultDays = Math.min(90, Number(policy.maxLifetimeDays || 365));
  const defaultExpiry = new Date(Date.now() + defaultDays * 86_400_000).toISOString().slice(0, 10);
  const keyCards = (center.keys || []).map((key) => `<article class="api-key-card">
    <div class="api-key-card-head"><span class="api-key-icon">⌁</span><span><strong>${escapeHtml(key.name)}</strong><small>${escapeHtml(key.tokenHint)} · Created ${formatDate(key.createdAt, { dateOnly: true })}</small></span><span class="status-badge ${key.active ? "" : "disabled"}">${escapeHtml(key.status)}</span></div>
    <div class="api-key-meta"><span><small>Last used</small><strong>${key.lastUsedAt ? formatRelative(key.lastUsedAt) : "Never"}</strong></span><span><small>Expires</small><strong>${key.expiresAt ? formatDate(key.expiresAt, { dateOnly: true }) : "Never"}</strong></span><span><small>Resources</small><strong>${key.resourceIds.length}</strong></span></div>
    <details><summary>View permission summary</summary>${apiKeySummaryMarkup(key.summary, { compact: false })}</details>
    ${key.active ? `<button class="button danger small" type="button" data-revoke-api-key="${escapeHtml(key.id)}">Revoke key</button>` : ""}
  </article>`).join("");
  return `<section class="panel api-key-center">
    <header class="panel-header"><div><p class="eyebrow">Integrations</p><h2>API keys</h2><p>Create narrowly scoped keys for Home Assistant, scripts, monitoring, and future Nimbus apps.</p></div><span class="pill success">${Number((center.keys || []).filter((key) => key.active).length)} / ${Number(policy.maxActiveKeys)} active</span></header>
    <div class="api-policy-strip"><span><small>Maximum lifetime</small><strong>${Number(policy.maxLifetimeDays)} days</strong></span><span><small>No-expiry keys</small><strong>${policy.allowNoExpiry ? "Allowed" : "Blocked"}</strong></span><span><small>Enforcement</small><strong>Live assignment policy</strong></span></div>
    <form id="apiKeyCreateForm" class="api-key-create-form">
      <div class="form-grid">
        <div class="field"><label for="apiKeyName">Key name</label><input id="apiKeyName" name="name" maxlength="100" required placeholder="Home Assistant"></div>
        <div class="field"><label for="apiKeyExpiry">Expiry date</label><input id="apiKeyExpiry" name="expiresAt" type="date" value="${defaultExpiry}" ${policy.allowNoExpiry ? "" : "required"} max="${new Date(Date.now() + Number(policy.maxLifetimeDays) * 86_400_000).toISOString().slice(0, 10)}"><small>${policy.allowNoExpiry ? "Leave blank only when a permanent key is truly necessary." : "Expiry is required by your administrator."}</small></div>
      </div>
      <fieldset class="api-group-grid"><legend>Permission groups</legend>${(center.groups || []).map((group) => `<label><input type="checkbox" name="groups" value="${escapeHtml(group.id)}" data-resource-group="${resourceGroups.has(group.id) ? "true" : "false"}"><span><strong>${escapeHtml(group.label)}</strong><small>${escapeHtml(group.description)}</small></span></label>`).join("")}</fieldset>
      <fieldset class="api-resource-grid"><legend>Resources</legend>${(center.resources || []).map((resource) => `<label><input type="checkbox" name="resourceIds" value="${escapeHtml(resource.id)}"><span class="resource-type ${resource.type}">${resource.type === "lxc" ? "CT" : "VM"}</span><span><strong>${escapeHtml(resource.name)}</strong><small>${escapeHtml(resource.clusterName)} · ${escapeHtml(resource.node)} · ${resource.type.toUpperCase()} ${resource.vmid}</small></span></label>`).join("") || `<p>No resources are currently available under this API policy.</p>`}</fieldset>
      <div class="notice"><span>✓</span><span>Nimbus will show the final effective actions before creating the key. Assignment permissions remain the last authorization layer.</span></div>
      <div class="form-actions"><button class="button primary" type="submit">Review API key</button><p class="form-message"></p></div>
    </form>
    <div class="api-key-list"><h3>Your API keys</h3>${keyCards || `<div class="empty-state compact"><div><span class="empty-icon">⌁</span><h3>No API keys yet</h3><p>Create one above when an integration needs access.</p></div></div>`}</div>
  </section>`;
}

function renderSettings() {
  const security = state.dashboard.security || { mfa: {}, sessions: [] };
  const mfa = security.mfa || {};
  const sessions = security.sessions || [];
  const enrollment = state.mfaEnrollment;
  const enrollmentRequired = Boolean(mfa.enrollmentRequired);
  const policyBanner = enrollmentRequired ? `<section class="security-requirement-banner">
    <span class="security-requirement-icon">◎</span>
    <div><p class="eyebrow">Action required</p><h2>Protect this account with two-factor authentication</h2><p>Your platform security policy requires an authenticator before infrastructure, customer, or administrator data can be accessed.</p></div>
    <span class="pill warning">Access restricted</span>
  </section>` : "";
  const recoveryPanel = state.recoveryCodes?.length ? `<section class="panel recovery-panel">
    <header class="panel-header"><div><p class="eyebrow">Save these now</p><h2>Recovery codes</h2><p>Each code works once. They will not be shown again.</p></div><button class="button secondary small" type="button" data-copy-recovery>Copy all</button></header>
    <div class="recovery-code-grid">${state.recoveryCodes.map((code) => `<code>${escapeHtml(code)}</code>`).join("")}</div>
    <div class="notice warning"><span>!</span><span>Store these outside Nimbus in a password manager or another secure location.</span></div>
    <div class="form-actions"><button class="button primary" type="button" data-dismiss-recovery>I saved these codes</button></div>
  </section>` : "";
  const mfaPanel = enrollment ? `<section class="panel form-panel security-panel mfa-enrollment">
    <div class="security-heading"><span class="security-icon">◎</span><span><h2>Connect your authenticator</h2><p>Scan this code, then enter the current six-digit number.</p></span></div>
    <div class="mfa-setup-grid">
      <div class="qr-shell"><img src="${escapeHtml(enrollment.qrCode)}" alt="Authenticator enrollment QR code"></div>
      <div class="mfa-manual"><small>Manual setup key</small><code>${escapeHtml(enrollment.secret)}</code><button class="button quiet small" type="button" data-copy-mfa-secret>Copy setup key</button><p>Compatible with 1Password, Bitwarden, Google Authenticator, Microsoft Authenticator, and other TOTP apps.</p></div>
    </div>
    <form id="mfaConfirmForm">
      <div class="field"><label for="mfaConfirmCode">Six-digit code</label><input id="mfaConfirmCode" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required placeholder="123456"></div>
      <div class="form-actions"><button class="button primary" type="submit">Enable 2FA</button>${enrollmentRequired ? "" : `<button class="button secondary" type="button" data-cancel-mfa-setup>Cancel</button>`}<p class="form-message"></p></div>
    </form>
  </section>` : mfa.enabled ? `<section class="panel form-panel security-panel">
    <div class="security-heading"><span class="security-icon enabled">✓</span><span><h2>Two-factor authentication</h2><p>Authenticator protection is enabled for this account.</p></span><span class="pill success">Enabled</span></div>
    <div class="security-facts"><span><small>Recovery codes remaining</small><strong>${Number(mfa.recoveryCodesRemaining || 0)}</strong></span><span><small>Enabled</small><strong>${formatDate(mfa.confirmedAt, { dateOnly: true })}</strong></span></div>
    <details class="security-details"><summary>Generate new recovery codes</summary><form id="mfaRecoveryForm"><div class="form-grid"><div class="field"><label>Current password</label><input type="password" name="currentPassword" required autocomplete="current-password"></div><div class="field"><label>Authenticator code</label><input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></div></div><div class="form-actions"><button class="button secondary" type="submit">Replace recovery codes</button><p class="form-message"></p></div></form></details>
    ${mfa.requiredByPolicy
      ? `<div class="notice"><span>✓</span><span>Two-factor authentication is required by the current platform policy and cannot be disabled.</span></div>`
      : `<details class="security-details danger-zone"><summary>Disable two-factor authentication</summary><form id="mfaDisableForm"><div class="form-grid"><div class="field"><label>Current password</label><input type="password" name="currentPassword" required autocomplete="current-password"></div><div class="field"><label>Authenticator or recovery code</label><input name="code" autocomplete="one-time-code" maxlength="16" required></div></div><div class="form-actions"><button class="button danger" type="submit">Disable 2FA</button><p class="form-message"></p></div></form></details>`}
  </section>` : `<form class="panel form-panel security-panel" id="mfaSetupForm">
    <div class="security-heading"><span class="security-icon">◎</span><span><h2>Two-factor authentication</h2><p>${enrollmentRequired ? "Connect an authenticator to unlock the rest of Nimbus." : "Add an authenticator app code after your password at sign-in."}</p></span><span class="pill warning">${enrollmentRequired ? "Required" : "Not enabled"}</span></div>
    <div class="field"><label for="mfaSetupPassword">Current password</label><input id="mfaSetupPassword" type="password" name="currentPassword" required autocomplete="current-password"></div>
    <div class="form-actions"><button class="button primary" type="submit">${enrollmentRequired ? "Set up required 2FA" : "Set up authenticator"}</button><p class="form-message"></p></div>
  </form>`;
  const sessionRows = sessions.map((item) => `<article class="session-row">
    <span class="session-icon">${item.current ? "●" : "◉"}</span>
    <span class="session-copy"><strong>${escapeHtml(sessionDevice(item.userAgent))}${item.kind === "api" ? ` <em>Nimbus API</em>` : ""}${item.current ? ` <em>Current</em>` : ""}</strong><small>${escapeHtml(item.ipAddress)} · Last active ${formatRelative(item.lastSeenAt)} · Expires ${formatDate(item.expiresAt)}</small></span>
    <button class="row-button ${item.current ? "danger" : ""}" type="button" data-revoke-session="${escapeHtml(item.id)}">${item.current ? "Sign out" : "Revoke"}</button>
  </article>`).join("");
  if (enrollmentRequired) {
    els.viewRoot.innerHTML = `${appearancePanelMarkup()}${policyBanner}${mfaPanel}`;
    refreshAppearanceControls();
    return;
  }
  els.viewRoot.innerHTML = `${appearancePanelMarkup()}${recoveryPanel}<section class="layout-grid equal">
    <form class="panel form-panel" id="profileForm"><h2>Profile</h2><p>Update your display name.</p><div class="form-grid"><div class="field full"><label for="settingsName">Display name</label><input id="settingsName" name="displayName" maxlength="100" required value="${escapeHtml(state.user.displayName)}"></div><div class="field full"><label>Email address</label><input disabled value="${escapeHtml(state.user.email)}"></div></div><div class="form-actions"><button class="button primary">Save profile</button><p class="form-message"></p></div></form>
    <form class="panel form-panel" id="passwordForm"><h2>Password</h2><p>Changing your password revokes all active sessions.</p><div class="form-grid"><div class="field full"><label for="currentPassword">Current password</label><input id="currentPassword" type="password" name="currentPassword" required autocomplete="current-password"></div><div class="field full"><label for="newPassword">New password</label><input id="newPassword" type="password" name="password" minlength="12" required autocomplete="new-password"></div></div><div class="form-actions"><button class="button primary">Change password</button><p class="form-message"></p></div></form>
  </section>
  <div class="settings-security-grid">${mfaPanel}
    <section class="panel form-panel security-panel"><div class="security-heading"><span class="security-icon">◷</span><span><h2>Active sessions</h2><p>Review devices signed in to this account.</p></span><span class="pill">${plural(sessions.length, "session")}</span></div><div class="session-list">${sessionRows || `<p>No active sessions.</p>`}</div>${sessions.length > 1 ? `<form id="revokeOtherSessionsForm"><div class="field"><label for="revokeSessionsPassword">Current password</label><input id="revokeSessionsPassword" name="currentPassword" type="password" required autocomplete="current-password"></div><div class="form-actions"><button class="button secondary" type="submit">Revoke all other sessions</button><p class="form-message"></p></div></form>` : ""}</section>
  </div>${apiKeyCenterMarkup(mfa)}`;
  refreshAppearanceControls();
}

function operationsStatusPill(value) {
  const labels = {
    healthy: "Healthy",
    warning: "Warning",
    critical: "Critical",
    pending: "Pending",
    disabled: "Disabled",
    online: "Online",
    available: "Available",
    active: "Active",
    unknown: "Unknown",
  };
  const style = ["healthy", "online", "available", "active"].includes(value)
    ? "success"
    : ["warning", "pending", "unknown", "disabled"].includes(value) ? "warning" : "critical";
  return `<span class="operations-status ${style}"><i></i>${escapeHtml(labels[value] || value || "Unknown")}</span>`;
}

function operationsUsage(percentValue, { compact = false } = {}) {
  const value = Math.max(0, Math.min(100, Number(percentValue) || 0));
  const level = value >= 95 ? "critical" : value >= 85 ? "warning" : "healthy";
  return `<div class="operations-usage ${compact ? "compact" : ""}">
    <div class="operations-usage-head"><strong>${Math.round(value)}%</strong><small>${level === "healthy" ? "Normal" : level === "warning" ? "Pressure" : "Critical"}</small></div>
    <div class="operations-usage-track"><span class="${level}" style="width:${pct(value)}"></span></div>
  </div>`;
}

function renderAdminOperations() {
  const operations = state.admin.operations || {
    summary: {}, clusters: [], nodes: [], storages: [], incidents: [], recentResolved: [], tasks: [],
  };
  const summary = operations.summary || {};
  const query = state.search.trim().toLowerCase();
  const matches = (...values) => !query || values.some((value) => String(value || "").toLowerCase().includes(query));
  const nodes = (operations.nodes || []).filter((node) => matches(node.node, node.clusterName, node.status));
  const storages = (operations.storages || []).filter((storage) =>
    matches(storage.storageId, storage.node, storage.clusterName, storage.type, storage.status));
  const incidents = (operations.incidents || []).filter((incident) =>
    matches(incident.title, incident.message, incident.clusterName, incident.sourceId, incident.severity, incident.status));
  const tasks = (operations.tasks || []).filter((task) =>
    matches(task.resourceName, task.resourceId, task.clusterName, task.node, task.action, task.exitStatus));
  const critical = Number(summary.criticalIncidents || 0);
  const active = Number(summary.activeIncidents || 0);
  const overall = critical ? {
    style: "critical", icon: "!", title: "Immediate attention required",
    copy: `${plural(critical, "critical incident")} across the connected infrastructure.`,
  } : active ? {
    style: "warning", icon: "◇", title: "Infrastructure needs review",
    copy: `${plural(active, "active incident")} detected. Acknowledgements do not suppress automatic recovery.`,
  } : {
    style: "healthy", icon: "✓", title: "All monitored systems operational",
    copy: "No active cluster, node, storage, task, or assignment incidents are currently detected.",
  };
  const storagePercent = summary.storageTotalBytes
    ? Number(summary.storageUsedBytes || 0) / Number(summary.storageTotalBytes) * 100
    : 0;
  const clusterRows = (operations.clusters || []).map((cluster) => {
    const coverage = [
      cluster.telemetry?.nodesAvailable ? `${cluster.telemetryNodes} node metrics` : "Node metrics unavailable",
      cluster.telemetry?.storagesAvailable ? `${cluster.telemetryStorages} storage paths` : "Storage metrics unavailable",
    ];
    return `<tr>
      <td><div class="server-copy"><strong>${escapeHtml(cluster.name)}</strong><small>${escapeHtml(cluster.apiUrl)}</small></div></td>
      <td>${operationsStatusPill(cluster.health)}</td>
      <td><div class="server-copy"><strong>${cluster.onlineNodes} / ${cluster.telemetryNodes || cluster.nodeCount} online</strong><small>${escapeHtml(coverage.join(" · "))}</small></div></td>
      <td><div class="server-copy"><strong>${cluster.lastSyncAt ? escapeHtml(formatRelative(cluster.lastSyncAt)) : "Never"}</strong><small>${cluster.telemetry?.collectedAt ? `Health sampled ${escapeHtml(formatRelative(cluster.telemetry.collectedAt))}` : "Run a full health refresh"}</small></div></td>
      <td><span class="incident-count ${cluster.criticalIncidentCount ? "critical" : cluster.incidentCount ? "warning" : ""}">${cluster.incidentCount}</span></td>
    </tr>`;
  }).join("");
  const incidentRows = incidents.map((incident) => `<article class="operations-incident ${escapeHtml(incident.severity)}">
    <span class="operations-incident-icon">${incident.severity === "critical" ? "!" : "◇"}</span>
    <span class="operations-incident-copy">
      <span class="operations-incident-meta"><strong>${escapeHtml(incident.severity)}</strong><small>${escapeHtml(incident.clusterName)} · ${escapeHtml(incident.sourceType)} · ${escapeHtml(incident.sourceId)}</small></span>
      <h3>${escapeHtml(incident.title)}</h3>
      <p>${escapeHtml(incident.message)}</p>
      <small>First detected ${escapeHtml(formatDate(incident.firstSeenAt))} · Checked ${escapeHtml(formatRelative(incident.lastSeenAt))}</small>
    </span>
    <span class="operations-incident-action">
      ${incident.status === "acknowledged"
        ? `<span class="acknowledged-mark">✓ Acknowledged${incident.acknowledgedByName ? ` by ${escapeHtml(incident.acknowledgedByName)}` : ""}</span>`
        : `<button class="button secondary small" type="button" data-ack-incident="${escapeHtml(incident.id)}">Acknowledge</button>`}
    </span>
  </article>`).join("");
  const nodeRows = nodes.map((node) => `<tr>
    <td><div class="server-copy"><strong>${escapeHtml(node.node)}</strong><small>${escapeHtml(node.clusterName)} · ${Number(node.cpuCores)} cores · ${formatUptime(node.uptime)} uptime</small></div></td>
    <td>${operationsStatusPill(node.status)}</td>
    <td>${operationsUsage(node.cpuPercent, { compact: true })}</td>
    <td><div class="operations-capacity"><span><strong>${escapeHtml(formatBytes(node.memoryUsedBytes))}</strong><small>of ${escapeHtml(formatBytes(node.memoryTotalBytes))}</small></span>${operationsUsage(node.memoryPercent, { compact: true })}</div></td>
    <td><div class="operations-capacity"><span><strong>${escapeHtml(formatBytes(node.rootUsedBytes))}</strong><small>of ${escapeHtml(formatBytes(node.rootTotalBytes))}</small></span>${operationsUsage(node.rootPercent, { compact: true })}</div></td>
  </tr>`).join("");
  const storageRows = storages.slice().sort((left, right) => right.usagePercent - left.usagePercent).map((storage) => `<tr>
    <td><div class="server-copy"><strong>${escapeHtml(storage.storageId)}</strong><small>${escapeHtml(storage.type)} · ${storage.shared ? "shared" : "node-local"}${storage.content.length ? ` · ${escapeHtml(storage.content.join(", "))}` : ""}</small></div></td>
    <td><div class="server-copy"><strong>${escapeHtml(storage.node)}</strong><small>${escapeHtml(storage.clusterName)}</small></div></td>
    <td>${operationsStatusPill(storage.status)}</td>
    <td><div class="operations-capacity wide"><span><strong>${escapeHtml(formatBytes(storage.usedBytes))}</strong><small>${escapeHtml(formatBytes(storage.availableBytes))} available · ${escapeHtml(formatBytes(storage.totalBytes))} total</small></span>${operationsUsage(storage.usagePercent, { compact: true })}</div></td>
  </tr>`).join("");
  const taskRows = tasks.map((task) => {
    const stuck = !task.completed && task.durationMs >= Number(operations.thresholds?.stuckTaskMinutes || 15) * 60_000;
    const label = task.completed ? "Failed" : stuck ? "Stuck" : "Running";
    const style = task.completed || stuck ? "critical" : "warning";
    return `<tr>
      <td><div class="server-copy"><strong>${escapeHtml(actionName(task.action))}</strong><small>${escapeHtml(task.clusterName)} · ${escapeHtml(task.node)}</small></div></td>
      <td><div class="server-copy"><strong>${escapeHtml(task.resourceName)}</strong><small>${task.resourceType ? `${escapeHtml(task.resourceType.toUpperCase())} ${task.vmid}` : escapeHtml(task.resourceId)}</small></div></td>
      <td><span class="operations-status ${style}"><i></i>${label}</span></td>
      <td><div class="server-copy"><strong>${escapeHtml(formatDuration(task.durationMs))}</strong><small>${escapeHtml(task.exitStatus || "Awaiting Proxmox")}</small></div></td>
      <td>${escapeHtml(formatDate(task.completedAt || task.createdAt))}</td>
    </tr>`;
  }).join("");
  const coverageGaps = (operations.clusters || []).filter((cluster) =>
    cluster.status !== "disabled" && (!cluster.telemetry?.nodesAvailable || !cluster.telemetry?.storagesAvailable));
  const resolvedRows = (operations.recentResolved || []).slice(0, 8).map((incident) => `<div class="operations-resolved-item">
    <span class="operations-resolved-check">✓</span>
    <span><strong>${escapeHtml(incident.title)}</strong><small>${escapeHtml(incident.clusterName)} · Resolved ${escapeHtml(formatRelative(incident.resolvedAt))}</small></span>
  </div>`).join("");

  return `<section class="operations-hero ${overall.style}">
      <span class="operations-hero-icon">${overall.icon}</span>
      <div><p class="eyebrow">Live operations</p><h2>${escapeHtml(overall.title)}</h2><p>${escapeHtml(overall.copy)}</p></div>
      <div class="operations-hero-actions"><small>Generated ${escapeHtml(formatRelative(operations.generatedAt))}</small><button class="button primary" type="button" data-refresh-operations>Run full health refresh</button></div>
    </section>
    <section class="operations-kpi-grid">
      <article><span class="operations-kpi-icon cluster">◇</span><span><small>Clusters healthy</small><strong>${Number(summary.healthyClusters || 0)} <em>/ ${Number(summary.clusters || 0)}</em></strong><p>${summary.clusters ? "Based on synchronization and incidents" : "Add a cluster to begin"}</p></span></article>
      <article><span class="operations-kpi-icon node">⌘</span><span><small>Nodes online</small><strong>${Number(summary.onlineNodes || 0)} <em>/ ${Number(summary.nodes || 0)}</em></strong><p>${summary.nodes ? "Live Proxmox node telemetry" : "No node telemetry collected"}</p></span></article>
      <article><span class="operations-kpi-icon storage">◫</span><span><small>Storage capacity</small><strong>${Math.round(storagePercent)}<em>% used</em></strong><p>${escapeHtml(formatBytes(summary.storageUsedBytes || 0))} of ${escapeHtml(formatBytes(summary.storageTotalBytes || 0))}</p></span></article>
      <article><span class="operations-kpi-icon incident">!</span><span><small>Needs attention</small><strong>${active} <em>active</em></strong><p>${Number(summary.failedTasks24h || 0)} failed tasks · ${Number(summary.stuckTasks || 0)} stuck</p></span></article>
    </section>
    <section class="operations-primary-grid">
      <article class="panel operations-incidents-panel">
        <header class="panel-header"><div><h2>Active incidents</h2><p>Automatically opened and resolved from normalized Proxmox telemetry.</p></div><span class="pill ${critical ? "warning" : active ? "warning" : "success"}">${active ? `${active} active` : "All clear"}</span></header>
        <div class="operations-incident-list">${incidentRows || emptyState("✓", query ? "No matching incidents" : "No active incidents", query ? "Try another filter." : "Nimbus will open an incident when monitored infrastructure needs attention.")}</div>
      </article>
      <aside class="panel operations-resolved-panel">
        <header class="panel-header"><div><h2>Recently recovered</h2><p>Automatically resolved conditions.</p></div></header>
        <div class="operations-resolved-list">${resolvedRows || `<div class="detail-empty compact"><span>✓</span><strong>No recent recoveries</strong><small>Resolved incidents will appear here.</small></div>`}</div>
      </aside>
    </section>
    <section class="panel operations-cluster-panel">
      <header class="panel-header"><div><h2>Cluster health</h2><p>Connectivity, telemetry coverage, synchronization age, and open incidents.</p></div><span class="pill">${plural((operations.clusters || []).length, "cluster")}</span></header>
      ${(operations.clusters || []).length ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Cluster</th><th>Health</th><th>Coverage</th><th>Last sync</th><th>Incidents</th></tr></thead><tbody>${clusterRows}</tbody></table></div>` : emptyState("◇", "No clusters configured", "Add a Proxmox cluster from the Clusters tab.")}
      ${coverageGaps.length ? `<div class="operations-permission-note"><span>i</span><span><strong>Partial telemetry on ${plural(coverageGaps.length, "cluster")}.</strong> Node health requires <code>Sys.Audit</code>; storage capacity requires <code>Datastore.Audit</code>. Resource synchronization continues even when optional telemetry is unavailable.</span></div>` : ""}
    </section>
    <section class="panel operations-node-panel">
      <header class="panel-header"><div><h2>Node pressure</h2><p>CPU, memory, root storage, uptime, and availability.</p></div><span class="pill">${plural(nodes.length, "node")}</span></header>
      ${nodeRows ? `<div class="table-wrap"><table class="data-table operations-table"><thead><tr><th>Node</th><th>Status</th><th>CPU</th><th>Memory</th><th>Root storage</th></tr></thead><tbody>${nodeRows}</tbody></table></div>` : emptyState("⌘", query ? "No matching nodes" : "Node telemetry unavailable", query ? "Try another filter." : "Run a full health refresh and grant Sys.Audit to the panel service account.")}
    </section>
    <section class="panel operations-storage-panel">
      <header class="panel-header"><div><h2>Storage capacity</h2><p>All storage paths visible to the Proxmox API service account.</p></div><span class="pill">${plural(storages.length, "storage path")}</span></header>
      ${storageRows ? `<div class="table-wrap"><table class="data-table operations-table"><thead><tr><th>Storage</th><th>Node</th><th>Status</th><th>Capacity</th></tr></thead><tbody>${storageRows}</tbody></table></div>` : emptyState("◫", query ? "No matching storage" : "Storage telemetry unavailable", query ? "Try another filter." : "Run a full health refresh and grant Datastore.Audit only for storage that should be monitored.")}
    </section>
    <section class="panel operations-task-panel">
      <header class="panel-header"><div><h2>Tasks needing attention</h2><p>Incomplete actions plus Proxmox failures from the last 24 hours.</p></div><span class="pill ${tasks.length ? "warning" : "success"}">${tasks.length ? plural(tasks.length, "task") : "Clear"}</span></header>
      ${taskRows ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Action</th><th>Resource</th><th>State</th><th>Duration</th><th>Started / completed</th></tr></thead><tbody>${taskRows}</tbody></table></div>` : emptyState("✓", query ? "No matching tasks" : "No tasks need attention", query ? "Try another filter." : "Failed and unusually long-running actions will appear here.")}
    </section>`;
}

function adminTabs() {
  const tabs = [["operations", "Operations"], ["maintenance", "Maintenance"], ["inventory", "Inventory"], ["customers", "Customers"], ["clusters", "Clusters"], ["media", "ISO storage"], ["alerts", "Alerts"], ["email", "Email"], ["security", "Security"], ["users", "Users"], ["audit", "Audit log"]];
  return `<section class="panel admin-tab-shell"><div class="admin-tabs" role="tablist">${tabs.map(([id, label]) => `<button class="admin-tab ${state.adminTab === id ? "active" : ""}" data-admin-tab="${id}">${label}</button>`).join("")}</div></section>`;
}

function datetimeLocalValue(value) {
  if (!value) return "";
  const date = new Date(value);
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

function maintenanceTargetsFor(type) {
  if (type === "cluster") return (state.admin.clusters || []).map((cluster) => ({ id: cluster.id, label: cluster.name }));
  if (type === "node") {
    const nodes = state.admin.nodes || [];
    return nodes.map((node) => ({ id: `${node.clusterId}:${node.node}`, label: `${node.node} · ${node.clusterName}` }));
  }
  if (type === "resource") {
    return (state.admin.resources || []).filter((resource) => resource.customerId).map((resource) => ({
      id: resource.id,
      label: `${resource.displayName || resource.name} · ${resource.type.toUpperCase()} ${resource.vmid} · ${resource.customerName}`,
    }));
  }
  if (type === "customer") return (state.admin.customers || []).filter((customer) => customer.status === "active").map((customer) => ({ id: customer.id, label: customer.name }));
  return [{ id: "*", label: "Every active customer user" }];
}

function maintenanceTargetOptions(type, selectedIds = []) {
  const selected = new Set(selectedIds);
  return maintenanceTargetsFor(type).map((target) =>
    `<option value="${escapeHtml(target.id)}" ${selected.has(target.id) ? "selected" : ""}>${escapeHtml(target.label)}</option>`).join("");
}

function maintenanceFormMarkup(item = null) {
  const prefix = item ? "editMaintenance" : "maintenance";
  const targetType = item?.targets?.[0]?.type || "all";
  const selectedIds = (item?.targets || []).map((target) => target.id);
  const defaultStart = Math.ceil((Date.now() + 60 * 60_000) / (15 * 60_000)) * 15 * 60_000;
  const emailReady = Boolean(state.admin.emailSettings?.enabled);
  return `<div class="form-grid">
      <div class="field"><label for="${prefix}Kind">Notice type</label><select id="${prefix}Kind" name="kind"><option value="maintenance" ${item?.kind !== "incident" ? "selected" : ""}>Planned maintenance</option><option value="incident" ${item?.kind === "incident" ? "selected" : ""}>Service incident</option></select></div>
      <div class="field"><label for="${prefix}Severity">Severity</label><select id="${prefix}Severity" name="severity"><option value="info" ${item?.severity === "info" || !item ? "selected" : ""}>Information</option><option value="warning" ${item?.severity === "warning" ? "selected" : ""}>Warning</option><option value="critical" ${item?.severity === "critical" ? "selected" : ""}>Critical</option></select></div>
      <div class="field full"><label for="${prefix}Title">Title</label><input id="${prefix}Title" name="title" required maxlength="160" value="${escapeHtml(item?.title || "")}" placeholder="Network maintenance in Frankfurt"></div>
      <div class="field full"><label for="${prefix}Message">Customer message</label><textarea id="${prefix}Message" name="message" required maxlength="4000" rows="5" placeholder="Explain the expected impact and what customers should expect.">${escapeHtml(item?.message || "")}</textarea></div>
      <div class="field"><label for="${prefix}StartsAt">Starts</label><input id="${prefix}StartsAt" name="startsAt" type="datetime-local" required value="${escapeHtml(datetimeLocalValue(item?.startsAt || defaultStart))}"></div>
      <div class="field"><label for="${prefix}EndsAt">Ends <span class="optional">(optional)</span></label><input id="${prefix}EndsAt" name="endsAt" type="datetime-local" value="${escapeHtml(datetimeLocalValue(item?.endsAt))}"><small>Leave empty for an open-ended incident.</small></div>
      <div class="field"><label for="${prefix}Audience">Affected audience</label><select id="${prefix}Audience" name="targetType" data-maintenance-audience><option value="all" ${targetType === "all" ? "selected" : ""}>All customers</option><option value="cluster" ${targetType === "cluster" ? "selected" : ""}>Clusters</option><option value="node" ${targetType === "node" ? "selected" : ""}>Nodes</option><option value="resource" ${targetType === "resource" ? "selected" : ""}>Individual resources</option><option value="customer" ${targetType === "customer" ? "selected" : ""}>Customer accounts</option></select></div>
      <div class="field"><label for="${prefix}TargetIds">Targets</label><select id="${prefix}TargetIds" name="targetIds" multiple size="5" ${targetType === "all" ? "disabled" : "required"}>${maintenanceTargetOptions(targetType, selectedIds)}</select><small>${targetType === "all" ? "Every active customer user receives the notice." : "Hold Ctrl or Command to choose multiple targets."}</small></div>
      <label class="policy-checkbox full"><input name="notifyEmail" type="checkbox" ${item?.notifyEmail === false ? "" : "checked"}><span><strong>Queue email for opted-in users</strong><small>${emailReady ? "Uses the branded Email Center template when this notice is published." : "SMTP is disabled; the notice will still appear inside the panel."}</small></span></label>
      ${item ? "" : `<div class="field full"><label for="${prefix}Publication">Publication</label><select id="${prefix}Publication" name="publication"><option value="publish">Create and publish now</option><option value="draft">Save as editable draft</option></select><small>Publishing freezes the recipient list from current assignments. Drafts remain private to administrators.</small></div>`}
    </div>`;
}

function maintenanceFormPayload(form) {
  const data = new FormData(form);
  const targetType = String(data.get("targetType") || "all");
  const startsAt = new Date(String(data.get("startsAt") || "")).getTime();
  const rawEnd = String(data.get("endsAt") || "").trim();
  const targetIds = targetType === "all" ? ["*"] : data.getAll("targetIds").map(String);
  return {
    kind: data.get("kind"),
    severity: data.get("severity"),
    title: data.get("title"),
    message: data.get("message"),
    startsAt,
    endsAt: rawEnd ? new Date(rawEnd).getTime() : null,
    notifyEmail: data.has("notifyEmail"),
    publication: data.get("publication") || undefined,
    targets: targetIds.map((id) => ({ type: targetType, id })),
  };
}

function renderAdminMaintenance() {
  const notices = state.admin.maintenanceEvents?.items || [];
  const active = notices.filter((item) => item.status === "active").length;
  const scheduled = notices.filter((item) => item.status === "scheduled").length;
  const drafts = notices.filter((item) => item.status === "draft").length;
  const publishedRecipients = notices.reduce((sum, item) => sum + Number(item.recipientCount || 0), 0);
  return `<section class="admin-summary-grid">
      <article><strong>${active}</strong><span>active notices</span></article>
      <article><strong>${scheduled}</strong><span>scheduled windows</span></article>
      <article><strong>${drafts}</strong><span>private drafts</span></article>
      <article class="safe"><strong>${publishedRecipients}</strong><span>frozen user deliveries</span></article>
    </section>
    <section class="layout-grid maintenance-admin-layout">
      <form class="panel form-panel maintenance-create-form" id="createMaintenanceForm" data-admin-create="maintenance">
        <h2>Create service notice</h2><p>Target the whole platform, a cluster, nodes, assigned resources, or customer accounts.</p>
        ${maintenanceFormMarkup()}
        <div class="form-actions"><button class="button primary" type="submit">Create notice</button><p class="form-message" role="status"></p></div>
      </form>
      <article class="panel policy-card">
        <header class="panel-header"><div><h2>Frozen audience</h2><p>Ownership is resolved only when you publish.</p></div></header>
        <div class="notice"><span>⌁</span><span>Nimbus converts the selected infrastructure targets into customer-user deliveries using its local assignment database.</span></div>
        <div class="notice"><span>✓</span><span>Later assignment changes cannot expose an old notice to a different customer.</span></div>
        <div class="notice warning"><span>✉</span><span>Email is opt-in per login. Every affected user still sees the notice in the private Maintenance Center.</span></div>
      </article>
    </section>
    <section class="panel maintenance-admin-panel">
      <header class="panel-header"><div><h2>Maintenance timeline</h2><p>Draft, schedule, incident, and resolution history.</p></div><span class="pill">${state.admin.maintenanceEvents?.total || 0} notices</span></header>
      <div class="maintenance-list">${notices.length ? notices.map((item) => maintenanceItemMarkup(item, { admin: true })).join("") : emptyState("△", "No maintenance notices", "Create the first targeted service notice above.")}</div>
    </section>`;
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

function emailStatusCopy(settings) {
  if (!settings.configured) return ["Not configured", "Save an SMTP endpoint to begin testing delivery.", "warning"];
  if (settings.lastTestStatus === "failed") return ["Test failed", friendlyError({ code: settings.lastTestErrorCode }), "warning"];
  if (settings.lastTestStatus === "success") return ["Connection verified", `Last tested ${formatRelative(settings.lastTestAt)}.`, "success"];
  return [
    settings.enabled ? "Configured" : "Configured, disabled",
    "Run a connection test before enabling notifications.",
    settings.enabled ? "success" : "warning",
  ];
}

function renderAdminAlerts() {
  const assignments = state.admin.resources.filter((resource) => resource.customerId);
  const enabled = assignments.filter((resource) => resource.alertPolicy?.enabled);
  const events = state.admin.notificationEvents?.items || [];
  const latestAlerts = new Map();
  for (const event of events) {
    if (!event.type?.startsWith("alert.")) continue;
    const key = `${event.resourceId}:${event.type.replace(/\.(firing|resolved)$/, "")}`;
    if (!latestAlerts.has(key)) latestAlerts.set(key, event.category);
  }
  const firing = [...latestAlerts.values()].filter((category) => category === "infrastructure_alert").length;
  const rows = assignments.map((resource) => {
    const policy = resource.alertPolicy || {};
    const conditions = [
      policy.offline ? "Offline" : null,
      policy.cpu ? `CPU ${policy.cpuThreshold}%` : null,
      policy.memory ? `Memory ${policy.memoryThreshold}%` : null,
      policy.storage ? `Storage ${policy.storageThreshold}%` : null,
    ].filter(Boolean).join(" · ");
    return `<tr>
      <td>${resourceIdentity(resource)}</td>
      <td>${escapeHtml(resource.customerName)}</td>
      <td><span class="pill ${policy.enabled ? "success" : ""}">${policy.enabled ? "Enabled" : "Disabled"}</span></td>
      <td><div class="server-copy"><strong>${policy.enabled ? escapeHtml(conditions || "No conditions selected") : "—"}</strong><small>${policy.enabled ? `${policy.sustainMinutes} min duration · ${policy.cooldownMinutes} min cooldown` : "Open policy to enable alerting."}</small></div></td>
      <td><button class="row-button" data-assign="${escapeHtml(resource.id)}">Configure</button></td>
    </tr>`;
  }).join("");
  const eventRows = events.map((event) => `<tr>
    <td>${escapeHtml(formatDate(event.createdAt))}</td>
    <td><span class="pill ${event.severity === "success" ? "success" : event.severity === "warning" || event.severity === "critical" ? "warning" : ""}">${escapeHtml(event.severity)}</span></td>
    <td><div class="server-copy"><strong>${escapeHtml(event.title)}</strong><small>${escapeHtml(event.message)}</small></div></td>
    <td>${escapeHtml(event.customerName || event.customerId)}</td>
    <td>${escapeHtml(event.resourceName || "—")}</td>
  </tr>`).join("");
  return `<section class="admin-summary-grid">
      <article><strong>${enabled.length}</strong><span>alert policies enabled</span></article>
      <article><strong>${Math.max(0, firing)}</strong><span>recent unresolved signals</span></article>
      <article><strong>${events.length}</strong><span>recent notification events</span></article>
      <article class="safe"><strong>1 + 1</strong><span>alert and recovery per incident</span></article>
    </section>
    <section class="panel"><header class="panel-header"><div><h2>Per-server alert policies</h2><p>Thresholds are evaluated only after a successful Proxmox synchronization.</p></div><span class="pill">${assignments.length} assignments</span></header>
      ${assignments.length ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Resource</th><th>Customer</th><th>Alerting</th><th>Conditions</th><th><span class="visually-hidden">Actions</span></th></tr></thead><tbody>${rows}</tbody></table></div>` : emptyState("✦", "No assigned resources", "Assign a VM or container before enabling alert policies.")}
    </section>
    <section class="panel alert-event-panel"><header class="panel-header"><div><h2>Recent notification events</h2><p>Platform-wide alert, recovery, and task history.</p></div><span class="pill">${state.admin.notificationEvents?.total || 0} total</span></header>
      ${events.length ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Time</th><th>Severity</th><th>Event</th><th>Customer</th><th>Resource</th></tr></thead><tbody>${eventRows}</tbody></table></div>` : emptyState("✦", "No notification events yet", "Events will appear after customer actions complete or an enabled alert policy fires.")}
    </section>`;
}

function renderAdminEmail() {
  const settings = state.admin.emailSettings || {};
  const jobs = state.admin.emailJobs?.items || [];
  const [statusTitle, statusDetail, statusStyle] = emailStatusCopy(settings);
  const defaultRecipient = state.user?.email || "";
  const jobRows = jobs.map((job) => {
    const style = job.status === "sent" ? "success" : job.status === "failed" ? "warning" : "";
    const statusText = job.status === "pending" && job.attempts ? "Retry scheduled" : job.status;
    const detail = job.lastErrorCode
      ? friendlyError({ code: job.lastErrorCode })
      : `${job.attempts} / ${job.maxAttempts} attempts`;
    return `<tr>
      <td><div class="server-copy"><strong>${escapeHtml(job.subject)}</strong><small>${escapeHtml(job.category.replace(/[_-]/g, " "))}</small></div></td>
      <td>${escapeHtml(job.to)}</td>
      <td><span class="pill ${style}">${escapeHtml(statusText)}</span></td>
      <td><div class="server-copy"><strong>${escapeHtml(formatDate(job.sentAt || job.updatedAt))}</strong><small>${escapeHtml(detail)}</small></div></td>
      <td>${job.status === "failed" ? `<button class="row-button" data-retry-email="${escapeHtml(job.id)}">Retry</button>` : "—"}</td>
    </tr>`;
  }).join("");
  return `<section class="email-status-grid">
      <article class="email-status-card"><span class="email-status-icon">✉</span><span><small>Delivery state</small><strong>${escapeHtml(statusTitle)}</strong><p>${escapeHtml(statusDetail)}</p></span><span class="pill ${statusStyle}">${settings.enabled ? "Enabled" : "Disabled"}</span></article>
      <article class="email-status-card"><span class="email-status-icon secure">⌁</span><span><small>Transport security</small><strong>${settings.security === "tls" ? "TLS" : "STARTTLS"}</strong><p>${settings.configured ? `${escapeHtml(settings.host)}:${Number(settings.port || 0)}` : "Certificate verification is always required."}</p></span><span class="pill success">Verified TLS only</span></article>
    </section>
    <section class="layout-grid email-layout">
      <form class="panel form-panel" id="emailSettingsForm">
        <h2>SMTP delivery</h2><p>Credentials are encrypted with the same application secret that protects Proxmox tokens.</p>
        <div class="form-grid">
          <div class="field"><label for="emailSmtpHost">SMTP host</label><input id="emailSmtpHost" name="host" required maxlength="253" value="${escapeHtml(settings.host || "")}" placeholder="smtp.example.com"></div>
          <div class="field"><label for="emailSmtpPort">Port</label><input id="emailSmtpPort" name="port" type="number" min="1" max="65535" required value="${Number(settings.port || 587)}"></div>
          <div class="field"><label for="emailSecurity">Encryption</label><select id="emailSecurity" name="security"><option value="starttls" ${settings.security !== "tls" ? "selected" : ""}>STARTTLS (usually 587)</option><option value="tls" ${settings.security === "tls" ? "selected" : ""}>TLS (usually 465)</option></select></div>
          <div class="field"><label for="emailUsername">Username <span class="optional">(optional)</span></label><input id="emailUsername" name="username" maxlength="255" value="${escapeHtml(settings.username || "")}" autocomplete="username"></div>
          <div class="field full"><label for="emailPassword">Password ${settings.passwordConfigured ? `<span class="optional">(leave blank to keep encrypted password)</span>` : ""}</label><input id="emailPassword" name="password" type="password" maxlength="1024" autocomplete="new-password" placeholder="${settings.passwordConfigured ? "Encrypted password already stored" : "SMTP password"}"></div>
          <div class="field"><label for="emailFromName">Sender name</label><input id="emailFromName" name="fromName" required maxlength="100" value="${escapeHtml(settings.fromName || "Nimbus Direct")}"></div>
          <div class="field"><label for="emailFromAddress">Sender address</label><input id="emailFromAddress" name="fromEmail" type="email" required maxlength="254" value="${escapeHtml(settings.fromEmail || "")}" placeholder="nimbus@example.com"></div>
          <div class="field full"><label for="emailReplyTo">Reply-to address <span class="optional">(optional)</span></label><input id="emailReplyTo" name="replyTo" type="email" maxlength="254" value="${escapeHtml(settings.replyTo || "")}"></div>
          <div class="field full"><label for="emailAppUrl">Public panel URL <span class="optional">(required for invitations and password recovery)</span></label><input id="emailAppUrl" name="appUrl" type="url" maxlength="2048" value="${escapeHtml(settings.appUrl || "")}" placeholder="https://panel.example.com"><small>Nimbus uses this base URL only to generate short-lived account links. Use the exact external URL customers open.</small></div>
          <label class="policy-checkbox full"><input name="enabled" type="checkbox" ${settings.enabled ? "checked" : ""}><span><strong>Enable queued email delivery</strong><small>Future alerts and account messages can be delivered only while this is enabled. Tests can run while disabled.</small></span></label>
        </div>
        <div class="form-actions"><button class="button primary" type="submit">Save SMTP settings</button><p class="form-message" role="status"></p></div>
      </form>
      <div class="section-stack">
        <article class="panel email-test-panel">
          <header class="panel-header"><div><h2>Connection test</h2><p>Checks TLS and authentication without sending a message.</p></div></header>
          <div class="email-test-body">
            <div class="notice"><span>✓</span><span>Nimbus validates the SMTP certificate. There is no insecure “skip verification” option.</span></div>
            <button class="button secondary" type="button" data-test-email-connection ${settings.configured ? "" : "disabled"}>Test connection</button>
          </div>
        </article>
        <form class="panel form-panel email-test-form" id="emailTestForm">
          <h2>Send a test email</h2><p>Creates a real queue record and confirms end-to-end delivery.</p>
          <div class="field"><label for="emailTestRecipient">Recipient</label><input id="emailTestRecipient" name="recipient" type="email" maxlength="254" required value="${escapeHtml(defaultRecipient)}"></div>
          <div class="form-actions"><button class="button primary" type="submit" ${settings.configured ? "" : "disabled"}>Send test email</button><p class="form-message" role="status"></p></div>
        </form>
      </div>
    </section>
    <section class="panel email-delivery-panel">
      <header class="panel-header"><div><h2>Delivery history</h2><p>Message bodies and credentials are never returned to the browser.</p></div><span class="pill">${state.admin.emailJobs?.total || 0} messages</span></header>
      ${jobs.length ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Message</th><th>Recipient</th><th>Status</th><th>Updated</th><th><span class="visually-hidden">Actions</span></th></tr></thead><tbody>${jobRows}</tbody></table></div>` : emptyState("✉", "No email deliveries yet", "Send a test email to create the first delivery record.")}
    </section>`;
}

function customerOptions(selected = "") {
  return `<option value="">No customer</option>${state.admin.customers.map((customer) => `<option value="${escapeHtml(customer.id)}" ${customer.id === selected ? "selected" : ""}>${escapeHtml(customer.name)}</option>`).join("")}`;
}

function securityEventTone(action) {
  if (String(action).includes("failed")) return "warning";
  if (action === "auth.login" || action === "auth.api_login" || action === "security.mfa_enabled") return "success";
  if (String(action).includes("reset") || String(action).includes("disabled")) return "critical";
  return "neutral";
}

function renderAdminSecurity() {
  const security = state.admin.security || { policy: {}, summary: {}, events: { items: [], total: 0 } };
  const policy = security.policy || {};
  const summary = security.summary || {};
  const query = state.search.trim().toLowerCase();
  const matches = (...values) => !query || values.some((value) => String(value || "").toLowerCase().includes(query));
  const users = (state.admin.users || []).filter((user) => matches(user.displayName, user.email, user.role, user.customerName, user.status));
  const events = (security.events?.items || []).filter((event) =>
    matches(event.action, event.displayName, event.email, event.customerName, event.ipAddress, event.actorRole));
  const postureRows = users.map((user) => {
    const required = user.role === "admin" ? policy.requireAdminMfa : policy.requireCustomerMfa;
    const protectedAccount = Boolean(user.mfaEnabled);
    return `<tr>
      <td><div class="server-name"><span class="server-avatar">${escapeHtml(initials(user.displayName))}</span><span class="server-copy"><strong>${escapeHtml(user.displayName)}</strong><small>${escapeHtml(user.email)}</small></span></div></td>
      <td>${escapeHtml(user.role === "admin" ? "Administrator" : user.customerName || "Customer")}</td>
      <td><span class="status-badge ${protectedAccount ? "" : "disabled"}">${protectedAccount ? "Protected" : "Not enabled"}</span></td>
      <td><span class="status-badge ${required ? "pending" : "disabled"}">${required ? "Required" : "Optional"}</span></td>
      <td><span class="status-badge ${user.status === "disabled" ? "disabled" : ""}">${escapeHtml(user.status)}</span></td>
    </tr>`;
  }).join("");
  const eventRows = events.map((event) => {
    const tone = securityEventTone(event.action);
    return `<tr>
      <td><span class="security-event-type ${tone}"><i></i>${escapeHtml(activityLabel(event.action))}</span></td>
      <td><div class="server-copy"><strong>${escapeHtml(event.displayName || "Unknown account")}</strong><small>${escapeHtml(event.email || event.customerName || "Platform event")}</small></div></td>
      <td>${escapeHtml(event.ipAddress || "Not recorded")}</td>
      <td>${escapeHtml(formatDate(event.createdAt))}</td>
    </tr>`;
  }).join("");
  const coverage = Number(summary.mfaCoverage ?? 100);
  return `<section class="security-center-hero">
      <span class="security-center-icon">⌁</span>
      <div><p class="eyebrow">Account protection</p><h2>${coverage}% of active accounts use 2FA</h2><p>Authentication policy is enforced by the backend before customer, infrastructure, or administrator data is returned.</p></div>
      <span class="security-coverage ${coverage === 100 ? "complete" : ""}"><strong>${Number(summary.mfaProtected || 0)}</strong><small>of ${Number(summary.activeAccounts || 0)} protected</small></span>
    </section>
    <section class="security-summary-grid">
      <article><small>Required enrollment</small><strong>${Number(summary.requiredPending || 0)}</strong><span>${summary.requiredPending ? "Accounts awaiting setup" : "Policy requirements satisfied"}</span></article>
      <article><small>Active sessions</small><strong>${Number(summary.activeSessions || 0)}</strong><span>Across enabled accounts</span></article>
      <article><small>Successful logins</small><strong>${Number(summary.successfulLogins24h || 0)}</strong><span>During the last 24 hours</span></article>
      <article class="${summary.failedLogins24h ? "warning" : ""}"><small>Failed logins</small><strong>${Number(summary.failedLogins24h || 0)}</strong><span>During the last 24 hours</span></article>
    </section>
    <section class="layout-grid security-center-layout">
      <form class="panel form-panel" id="securityPolicyForm">
        <header class="panel-header"><div><h2>Security policy</h2><p>Changes apply immediately to active and newly created accounts.</p></div><span class="pill">Backend enforced</span></header>
        <div class="security-policy-list">
          <label class="policy-checkbox"><input type="checkbox" name="requireAdminMfa" ${policy.requireAdminMfa ? "checked" : ""}><span><strong>Require 2FA for administrators</strong><small>Administrators without 2FA can access only the enrollment screen.</small></span></label>
          <label class="policy-checkbox"><input type="checkbox" name="requireCustomerMfa" ${policy.requireCustomerMfa ? "checked" : ""}><span><strong>Require 2FA for customers</strong><small>Customer resources remain hidden until enrollment is complete.</small></span></label>
          <label class="policy-checkbox"><input type="checkbox" name="newLoginEmail" ${policy.newLoginEmail ? "checked" : ""}><span><strong>Email successful sign-in alerts</strong><small>Send an account-security email after every completed password or 2FA login.</small></span></label>
        </div>
        ${state.admin.emailSettings?.enabled ? "" : `<div class="notice warning"><span>!</span><span>Sign-in emails begin only after Email Center delivery is enabled. The 2FA policy works independently of email.</span></div>`}
        <div class="form-actions"><button class="button primary" type="submit">Save security policy</button><p class="form-message" role="status"></p></div>
      </form>
      <article class="panel security-guidance">
        <header class="panel-header"><div><h2>Safe enforcement</h2><p>Nimbus prevents policy changes from becoming a lockout.</p></div></header>
        <div class="notice"><span>1</span><span>A password remains sufficient to reach the restricted 2FA enrollment screen.</span></div>
        <div class="notice"><span>2</span><span>All normal APIs fail closed with no customer or infrastructure data until setup finishes.</span></div>
        <div class="notice"><span>3</span><span>Administrator-assisted 2FA reset remains available for account recovery and signs out the affected user.</span></div>
      </article>
    </section>
    <section class="panel security-posture-panel">
      <header class="panel-header"><div><h2>Account posture</h2><p>2FA coverage and enforcement status for every Nimbus login.</p></div><span class="pill">${plural(users.length, "account")}</span></header>
      ${postureRows ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Account</th><th>Scope</th><th>2FA</th><th>Policy</th><th>Status</th></tr></thead><tbody>${postureRows}</tbody></table></div>` : emptyState("◎", "No matching accounts", "Try another filter.")}
    </section>
    <section class="panel security-events-panel">
      <header class="panel-header"><div><h2>Security events</h2><p>Successful and failed authentication, password, MFA, session, and policy actions.</p></div><span class="pill">${Number(security.events?.total || 0)} events</span></header>
      ${eventRows ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Event</th><th>Account</th><th>IP address</th><th>Time</th></tr></thead><tbody>${eventRows}</tbody></table></div>` : emptyState("⌁", query ? "No matching security events" : "No security events yet", query ? "Try another filter." : "Authentication and account-security actions will appear here.")}
    </section>`;
}

function renderAdminUsers() {
  const users = state.admin.users;
  const invitationReady = Boolean(state.admin.emailSettings?.enabled && state.admin.emailSettings?.appUrl);
  const userRows = users.map((user) => {
    const apiPolicy = state.admin.apiPolicies?.find((policy) => policy.userId === user.id);
    let onboarding = `<span class="status-badge">Ready</span>`;
    if (!user.passwordSet) {
      const pending = user.invitationExpiresAt && Number(user.invitationExpiresAt) > Date.now();
      onboarding = `<span class="status-badge ${pending ? "pending" : "disabled"}">${pending ? "Invitation pending" : user.invitationExpiresAt ? "Invitation expired" : "Link revoked"}</span>`;
    }
    return `<tr>
      <td><div class="server-name"><span class="server-avatar">${escapeHtml(initials(user.displayName))}</span><span class="server-copy"><strong>${escapeHtml(user.displayName)}</strong><small>${escapeHtml(user.email)}</small></span></div></td>
      <td>${escapeHtml(user.customerName || "Global")}</td>
      <td><span class="role-badge ${user.role === "admin" ? "platform" : ""}">${escapeHtml(user.role)}</span></td>
      <td>${onboarding}</td>
      <td><span class="status-badge ${user.mfaEnabled ? "" : "disabled"}">${user.mfaEnabled ? "Enabled" : "Off"}</span></td>
      <td><span class="status-badge ${apiPolicy?.enabled ? "" : "disabled"}">${apiPolicy?.enabled ? `${Number(apiPolicy.activeKeys || 0)} active` : "Off"}</span></td>
      <td><span class="status-badge ${user.status === "disabled" ? "disabled" : ""}">${escapeHtml(user.status)}</span></td>
      <td><div class="row-buttons">
        ${!user.passwordSet ? `<button class="row-button" data-resend-invitation="${escapeHtml(user.id)}" ${invitationReady ? "" : "disabled"}>Resend invite</button><button class="row-button danger" data-revoke-invitation="${escapeHtml(user.id)}">Revoke link</button>` : ""}
        <button class="row-button" data-api-access-user="${escapeHtml(user.id)}">API access</button>
        <button class="row-button" data-edit-user="${escapeHtml(user.id)}">Edit</button>
        <button class="row-button danger" data-delete-user="${escapeHtml(user.id)}">Delete</button>
      </div></td>
    </tr>`;
  }).join("");
  return `<section class="layout-grid">
    <form class="panel form-panel" id="createUserForm">
      <h2>Create user</h2><p>Send a single-use invitation or set a temporary password manually.</p>
      <div class="form-grid">
        <div class="field"><label for="userName">Display name</label><input id="userName" name="displayName" maxlength="100" required></div>
        <div class="field"><label for="userEmail">Email</label><input id="userEmail" name="email" type="email" maxlength="254" required></div>
        <div class="field"><label for="userRole">Role</label><select id="userRole" name="role"><option value="customer">Customer</option><option value="admin">Administrator</option></select></div>
        <div class="field"><label for="userCustomer">Customer</label><select id="userCustomer" name="customerId">${customerOptions()}</select></div>
        <div class="field full"><label for="userOnboardingMode">Account access</label><select id="userOnboardingMode" name="onboardingMode"><option value="invitation" ${invitationReady ? "" : "disabled"}>Email secure invitation${invitationReady ? "" : " (configure Email Center first)"}</option><option value="password" ${invitationReady ? "" : "selected"}>Set temporary password manually</option></select><small>Invitation links are single-use and expire after 30 minutes.</small></div>
        <div class="field full" data-onboarding-password ${invitationReady ? "hidden" : ""}><label for="userPassword">Temporary password</label><input id="userPassword" name="password" type="password" minlength="12" maxlength="256" ${invitationReady ? "" : "required"} autocomplete="new-password"></div>
      </div>
      ${invitationReady ? "" : `<div class="notice warning"><span>!</span><span>Enable SMTP delivery and save the public panel URL in <strong>Email Center</strong> before sending invitations.</span></div>`}
      <div class="form-actions"><button class="button primary" type="submit">${invitationReady ? "Create and send invitation" : "Create user"}</button><p class="form-message" role="status"></p></div>
    </form>
    <article class="panel policy-card">
      <header class="panel-header"><div><h2>Secure onboarding</h2><p>Passwords never travel by email.</p></div></header>
      <div class="notice"><span>✉</span><span><strong>Invitation:</strong> a 30-minute, single-use link lets the user choose their own password.</span></div>
      <div class="notice"><span>⌁</span><span>Only a keyed hash of each account token is stored. Resending automatically invalidates the previous link.</span></div>
      <div class="notice warning"><span>◇</span><span><strong>Administrator:</strong> global cluster, customer, user, assignment, and audit control.</span></div>
    </article>
  </section>
  <section class="panel" style="margin-top:18px">
    <header class="panel-header"><div><h2>Users</h2><p>${plural(users.length, "account")}</p></div></header>
    <div class="table-wrap"><table class="data-table"><thead><tr><th>User</th><th>Customer</th><th>Role</th><th>Onboarding</th><th>2FA</th><th>API</th><th>Status</th><th><span class="visually-hidden">Actions</span></th></tr></thead><tbody>${userRows}</tbody></table></div>
  </section>`;
}

function renderAdminAudit() {
  const items = state.admin.audit.items;
  return `<section class="panel"><header class="panel-header"><div><h2>Platform audit log</h2><p>Administrator and customer actions across all accounts.</p></div><span class="pill">${state.admin.audit.total} events</span></header><div class="table-wrap"><table class="data-table"><thead><tr><th>Time</th><th>Actor</th><th>Customer</th><th>Action</th><th>Resource</th></tr></thead><tbody>${items.map((item) => `<tr><td>${escapeHtml(formatDate(item.createdAt))}</td><td>${escapeHtml(item.displayName || item.actorRole)}</td><td>${escapeHtml(item.customerName || "Platform")}</td><td>${escapeHtml(activityLabel(item.action))}</td><td>${escapeHtml(item.resourceId || "—")}</td></tr>`).join("")}</tbody></table></div></section>`;
}

function renderAdmin() {
  const renderers = { operations: renderAdminOperations, maintenance: renderAdminMaintenance, inventory: renderAdminInventory, customers: renderAdminCustomers, clusters: renderAdminClusters, media: renderAdminMedia, alerts: renderAdminAlerts, email: renderAdminEmail, security: renderAdminSecurity, users: renderAdminUsers, audit: renderAdminAudit };
  els.viewRoot.innerHTML = `${adminTabs()}<div class="admin-section">${renderers[state.adminTab]()}</div>`;
}

const renderers = { overview: renderOverview, instances: renderInstances, network: renderNetwork, activity: renderActivity, notifications: renderNotifications, maintenance: renderMaintenance, support: renderSupport, settings: renderSettings, admin: renderAdmin };

function route() {
  if (!state.user || !state.dashboard) return;
  const rawRoute = location.hash.replace(/^#/, "") || "overview";
  const instanceMatch = rawRoute.match(/^instance\/(.+)$/);
  const supportMatch = rawRoute.match(/^support\/(.+)$/);
  let resourceId = null;
  let supportTicketId = null;
  if (instanceMatch) {
    try { resourceId = decodeURIComponent(instanceMatch[1]); } catch { resourceId = null; }
  }
  if (supportMatch) {
    try { supportTicketId = decodeURIComponent(supportMatch[1]); } catch { supportTicketId = null; }
  }
  let view = resourceId ? "instance" : supportTicketId ? "support" : rawRoute;
  if (!views[view]) view = "overview";
  if (view === "admin" && state.user.role !== "admin") view = "overview";
  if (state.dashboard.security?.mfa?.enrollmentRequired && view !== "settings") {
    location.hash = "#settings";
    return;
  }
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
  else if (view === "notifications" && !state.notifications) {
    els.viewRoot.innerHTML = `<div class="loading-inline"><span class="spinner"></span>Loading notifications</div>`;
    loadNotifications().then(renderNotifications).catch((error) => showToast("error", "Could not load notifications", friendlyError(error)));
  } else if (view === "network" && !state.network) {
    els.viewRoot.innerHTML = `<div class="loading-inline"><span class="spinner"></span>Discovering guest addresses</div>`;
    loadNetwork().then(renderNetwork).catch((error) => {
      state.network = { networks: {}, error: error.code || "network_unavailable" };
      renderNetwork();
      showToast("error", "Could not discover addresses", friendlyError(error));
    });
  } else if (view === "maintenance" && !state.maintenance) {
    els.viewRoot.innerHTML = `<div class="loading-inline"><span class="spinner"></span>Loading maintenance notices</div>`;
    loadMaintenance().then(renderMaintenance).catch((error) => showToast("error", "Could not load maintenance", friendlyError(error)));
  }
  else if (view === "support" && (!state.support || (supportTicketId && state.support.selected?.ticket?.id !== supportTicketId) || (!supportTicketId && state.support.selected))) {
    els.viewRoot.innerHTML = `<div class="loading-inline"><span class="spinner"></span>Loading support tickets</div>`;
    loadSupport(supportTicketId).then(renderSupport).catch((error) => showToast("error", "Could not load support tickets", friendlyError(error)));
  }
  else if (view === "settings" && !state.apiKeys) {
    els.viewRoot.innerHTML = `<div class="loading-inline"><span class="spinner"></span>Loading account security</div>`;
    loadApiKeys().then(renderSettings).catch((error) => showToast("error", "Could not load API access", friendlyError(error)));
  }
  else renderers[view]();
  closeSidebar();
}

function formPayload(form) {
  return Object.fromEntries(new FormData(form).entries());
}

function openAssignment(resourceId) {
  const resource = state.admin.resources.find((item) => item.id === resourceId);
  if (!resource) return;
  const alertPolicy = resource.alertPolicy || {
    enabled: false, offline: true, cpu: true, memory: true, storage: true,
    cpuThreshold: 90, memoryThreshold: 90, storageThreshold: 90, sustainMinutes: 5, cooldownMinutes: 60,
  };
  els.editForm.dataset.kind = "assignment";
  els.editForm.dataset.id = resource.id;
  els.editDialogTitle.textContent = resource.customerId ? "Edit assignment policy" : "Assign resource";
  els.editDialogBody.innerHTML = `<div class="assignment-resource">${resourceIdentity(resource)}${statusMarkup(resource)}</div>
    <div class="form-grid">
      <div class="field"><label for="assignmentCustomer">Customer</label><select id="assignmentCustomer" name="customerId" required>${customerOptions(resource.customerId || "")}</select></div>
      <div class="field"><label for="assignmentName">Optional display name</label><input id="assignmentName" name="displayName" value="${escapeHtml(resource.displayName || "")}" placeholder="Customer-facing name"></div>
      <div class="field full"><label for="assignmentSnapshotLimit">Maximum snapshots</label><input id="assignmentSnapshotLimit" name="snapshotLimit" type="number" min="1" max="50" step="1" required value="${Number(resource.snapshotLimit) || 3}"><small>This limit is enforced by the backend before Proxmox receives a create request.</small></div>
    </div>
    <fieldset class="permission-grid"><legend>Allowed operations</legend>${permissions.map(([id, label]) => `<label><input type="checkbox" name="permissions" value="${id}" ${resource.permissions?.includes(id) || (!resource.customerId && DEFAULT_UI_PERMISSIONS.has(id)) ? "checked" : ""}><span>${escapeHtml(label)}</span></label>`).join("")}</fieldset>
    <fieldset class="alert-policy-editor">
      <legend>Notifications & alerts</legend>
      <label class="policy-checkbox alert-master"><input type="checkbox" name="alertEnabled" ${alertPolicy.enabled ? "checked" : ""}><span><strong>Enable infrastructure alerting for this assignment</strong><small>Evaluated after successful metadata synchronization. Existing stopped guests are baselined without an outage email.</small></span></label>
      <div class="alert-condition-grid">
        <label class="policy-checkbox"><input type="checkbox" name="alertOffline" ${alertPolicy.offline ? "checked" : ""}><span><strong>Unexpected offline state</strong><small>Ignores intentional Nimbus stop and shutdown actions.</small></span></label>
        <label class="policy-checkbox"><input type="checkbox" name="alertCpu" ${alertPolicy.cpu ? "checked" : ""}><span><strong>High CPU usage</strong><small>Alert after the configured duration.</small></span></label>
        <label class="policy-checkbox"><input type="checkbox" name="alertMemory" ${alertPolicy.memory ? "checked" : ""}><span><strong>High memory usage</strong><small>Calculated from current used and assigned memory.</small></span></label>
        <label class="policy-checkbox"><input type="checkbox" name="alertStorage" ${alertPolicy.storage ? "checked" : ""}><span><strong>High storage usage</strong><small>Calculated from current used and assigned storage.</small></span></label>
      </div>
      <div class="form-grid alert-threshold-grid">
        <div class="field"><label for="alertCpuThreshold">CPU threshold (%)</label><input id="alertCpuThreshold" name="alertCpuThreshold" type="number" min="50" max="100" step="1" required value="${Number(alertPolicy.cpuThreshold)}"></div>
        <div class="field"><label for="alertMemoryThreshold">Memory threshold (%)</label><input id="alertMemoryThreshold" name="alertMemoryThreshold" type="number" min="50" max="100" step="1" required value="${Number(alertPolicy.memoryThreshold)}"></div>
        <div class="field"><label for="alertStorageThreshold">Storage threshold (%)</label><input id="alertStorageThreshold" name="alertStorageThreshold" type="number" min="50" max="100" step="1" required value="${Number(alertPolicy.storageThreshold)}"></div>
        <div class="field"><label for="alertSustainMinutes">Condition duration (minutes)</label><input id="alertSustainMinutes" name="alertSustainMinutes" type="number" min="1" max="1440" step="1" required value="${Number(alertPolicy.sustainMinutes)}"></div>
        <div class="field"><label for="alertCooldownMinutes">Repeat cooldown (minutes)</label><input id="alertCooldownMinutes" name="alertCooldownMinutes" type="number" min="5" max="10080" step="1" required value="${Number(alertPolicy.cooldownMinutes)}"><small>One alert and one recovery are sent per incident.</small></div>
      </div>
    </fieldset>
    <div class="ownership-proof"><strong>Server-side ownership key</strong><code>${escapeHtml(resource.clusterId)} / ${escapeHtml(resource.node)} / ${resource.type} / ${resource.vmid}</code><small>Nimbus resolves this key from its database; it never trusts customer-supplied coordinates.</small></div>`;
  els.editDialogError.textContent = "";
  if (!els.editDialog.open) els.editDialog.showModal();
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
  const passwordLabel = user.passwordSet ? "New password" : "Set password manually";
  const passwordHelp = user.passwordSet ? "Leave blank to keep the current password" : "Setting a password completes onboarding and revokes invitation links";
  els.editForm.dataset.kind = "user";
  els.editForm.dataset.id = user.id;
  els.editDialogTitle.textContent = "Edit user";
  els.editDialogBody.innerHTML = `<div class="form-grid"><div class="field full"><label>Email address</label><input disabled value="${escapeHtml(user.email)}"></div><div class="field"><label for="editUserName">Display name</label><input id="editUserName" name="displayName" maxlength="100" required value="${escapeHtml(user.displayName)}"></div><div class="field"><label for="editUserStatus">Status</label><select id="editUserStatus" name="status"><option value="active" ${user.status === "active" ? "selected" : ""}>Active</option><option value="disabled" ${user.status === "disabled" ? "selected" : ""}>Disabled</option></select></div><div class="field"><label for="editUserRole">Role</label><select id="editUserRole" name="role"><option value="customer" ${user.role === "customer" ? "selected" : ""}>Customer</option><option value="admin" ${user.role === "admin" ? "selected" : ""}>Administrator</option></select></div><div class="field"><label for="editUserCustomer">Customer</label><select id="editUserCustomer" name="customerId">${customerOptions(user.customerId || "")}</select></div><div class="field full"><label for="editUserPassword">${passwordLabel} <span class="optional">(optional)</span></label><input id="editUserPassword" name="password" type="password" minlength="12" maxlength="256" autocomplete="new-password" placeholder="${passwordHelp}"></div>${user.mfaEnabled && user.id !== state.user.id ? `<label class="policy-checkbox full danger-zone"><input name="resetMfa" type="checkbox"><span><strong>Reset two-factor authentication</strong><small>Requires your administrator password below. The user will be signed out everywhere and must enroll again.</small></span></label><div class="field full"><label for="adminPasswordForMfaReset">Your administrator password</label><input id="adminPasswordForMfaReset" name="adminPasswordForMfaReset" type="password" autocomplete="current-password"></div>` : `<div class="field full"><label>Two-factor authentication</label><input disabled value="${user.mfaEnabled ? "Enabled" : "Not enabled"}"></div>`}</div>`;
  els.editDialogError.textContent = "";
  els.editDialog.showModal();
}

async function openApiAccessEditor(userId) {
  const user = state.admin.users.find((item) => item.id === userId);
  if (!user) return;
  els.editForm.dataset.kind = "api-policy-loading";
  els.editForm.dataset.id = user.id;
  els.editDialogTitle.textContent = `API access · ${user.displayName}`;
  els.editDialogBody.innerHTML = `<div class="loading-inline"><span class="spinner"></span>Loading API policy</div>`;
  els.editDialogError.textContent = "";
  if (!els.editDialog.open) els.editDialog.showModal();
  try {
    const center = await apiFetch(`/api/admin/users/${encodeURIComponent(user.id)}/api-access`);
    state.apiAccessEditor = center;
    const policy = center.policy || {};
    const activeKeys = (center.keys || []).filter((key) => key.active);
    els.editForm.dataset.kind = "api-policy";
    els.editDialogBody.innerHTML = `<div class="api-admin-policy">
      <label class="policy-checkbox"><input type="checkbox" name="apiEnabled" ${policy.enabled ? "checked" : ""}><span><strong>Enable integration API access</strong><small>The user can create keys only inside the maximum policy below. Disabling access immediately revokes all active keys.</small></span></label>
      <div class="form-grid">
        <div class="field"><label for="apiMaxKeys">Maximum active keys</label><input id="apiMaxKeys" name="maxActiveKeys" type="number" min="1" max="50" required value="${Number(policy.maxActiveKeys || 3)}"><small>Reducing this limit revokes the oldest excess keys.</small></div>
        <div class="field"><label for="apiMaxLifetime">Maximum lifetime in days</label><input id="apiMaxLifetime" name="maxLifetimeDays" type="number" min="1" max="3650" required value="${Number(policy.maxLifetimeDays || 365)}"></div>
        <label class="policy-checkbox full"><input type="checkbox" name="allowNoExpiry" ${policy.allowNoExpiry ? "checked" : ""}><span><strong>Allow keys without an expiry date</strong><small>Leave disabled for the safer default.</small></span></label>
      </div>
      <fieldset class="api-group-grid"><legend>Maximum permission groups</legend>${(center.groups || []).map((group) => `<label><input type="checkbox" name="policyGroups" value="${escapeHtml(group.id)}" ${policy.groups?.includes(group.id) ? "checked" : ""}><span><strong>${escapeHtml(group.label)}</strong><small>${escapeHtml(group.description)}</small></span></label>`).join("")}</fieldset>
      <fieldset class="api-resource-grid"><legend>Maximum resources</legend>
        <label class="api-all-resources"><input type="checkbox" name="allVisibleResources" ${policy.allVisibleResources ? "checked" : ""}><span><strong>All resources currently visible to this user</strong><small>Future direct assignments are included automatically.</small></span></label>
        <div data-policy-resource-list>${(center.resources || []).map((resource) => `<label><input type="checkbox" name="policyResources" value="${escapeHtml(resource.id)}" ${policy.resourceIds?.includes(resource.id) ? "checked" : ""} ${policy.allVisibleResources ? "disabled" : ""}><span class="resource-type ${resource.type}">${resource.type === "lxc" ? "CT" : "VM"}</span><span><strong>${escapeHtml(resource.name)}</strong><small>${resource.type.toUpperCase()} ${resource.vmid} · ${escapeHtml(resource.node)}</small></span></label>`).join("") || "<p>This user has no visible resources.</p>"}</div>
      </fieldset>
      <section class="api-admin-keys"><div><h3>Existing keys</h3><p>${plural(activeKeys.length, "active key")} · revoked keys remain in the audit history.</p></div>
        ${activeKeys.length ? `<div class="api-admin-key-list">${activeKeys.map((key) => `<article><span><strong>${escapeHtml(key.name)}</strong><small>${escapeHtml(key.tokenHint)} · ${key.expiresAt ? `expires ${formatDate(key.expiresAt, { dateOnly: true })}` : "never expires"}</small></span><button class="row-button danger" type="button" data-admin-revoke-api-key="${escapeHtml(key.id)}" data-api-user="${escapeHtml(user.id)}">Revoke</button></article>`).join("")}</div><button class="button danger small" type="button" data-admin-revoke-all-api-keys="${escapeHtml(user.id)}">Revoke all active keys</button>` : `<p class="muted-copy">No active keys.</p>`}
      </section>
    </div>`;
  } catch (error) {
    els.editDialogError.textContent = friendlyError(error);
  }
}

async function reviewApiKey(form) {
  if (!form.checkValidity()) {
    form.reportValidity();
    return;
  }
  const data = new FormData(form);
  const groups = data.getAll("groups");
  const resourceIds = data.getAll("resourceIds");
  if (!groups.length) {
    form.querySelector(".form-message").textContent = "Choose at least one permission group.";
    form.querySelector(".form-message").className = "form-message error";
    return;
  }
  const needsResources = [...form.querySelectorAll('input[name="groups"]:checked')]
    .some((input) => input.dataset.resourceGroup === "true");
  if (needsResources && !resourceIds.length) {
    form.querySelector(".form-message").textContent = "Choose at least one VM or container for these permissions.";
    form.querySelector(".form-message").className = "form-message error";
    return;
  }
  const expiry = data.get("expiresAt");
  const draft = {
    name: data.get("name"),
    groups,
    resourceIds,
    expiresAt: expiry ? new Date(`${expiry}T23:59:59`).getTime() : null,
  };
  const button = form.querySelector("button[type='submit']");
  const message = form.querySelector(".form-message");
  button.disabled = true;
  message.className = "form-message";
  message.textContent = "Computing effective permissions…";
  try {
    const { preview } = await apiFetch("/api/v1/api-keys/preview", { method: "POST", body: draft });
    state.apiKeyDraft = { ...draft, preview };
    els.editForm.dataset.kind = "api-key-create";
    els.editForm.dataset.id = "";
    els.editDialogTitle.textContent = "Review API key";
    els.editDialogBody.innerHTML = `${apiKeySummaryMarkup(preview)}
      <div class="api-key-confirmation">
        <div class="field"><label for="apiKeyPassword">Current password</label><input id="apiKeyPassword" name="currentPassword" type="password" required autocomplete="current-password"></div>
        ${state.dashboard.security?.mfa?.enabled ? `<div class="field"><label for="apiKeyMfaCode">Authenticator or recovery code</label><input id="apiKeyMfaCode" name="code" required maxlength="16" autocomplete="one-time-code"></div>` : ""}
      </div>
      <div class="notice warning"><span>!</span><span>The secret is shown only once. Store it in the integration's secret storage, never in source code.</span></div>`;
    els.editDialogError.textContent = "";
    els.editForm.querySelector("button[type='submit']").textContent = "Create API key";
    if (!els.editDialog.open) els.editDialog.showModal();
  } catch (error) {
    message.className = "form-message error";
    message.textContent = friendlyError(error);
  } finally {
    button.disabled = false;
  }
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

function openMaintenanceEditor(maintenanceId) {
  const item = state.admin.maintenanceEvents?.items?.find((entry) => entry.id === maintenanceId);
  if (!item || item.status !== "draft") return;
  els.editForm.dataset.kind = "maintenance";
  els.editForm.dataset.id = item.id;
  els.editDialogTitle.textContent = "Edit maintenance draft";
  els.editDialogBody.innerHTML = `${maintenanceFormMarkup(item)}
    <div class="notice"><span>⌁</span><span>The affected recipient list is resolved only when this draft is published.</span></div>`;
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

function openSnapshotCreate() {
  const resource = (state.dashboard?.resources || []).find((item) => item.id === state.instance.resourceId)
    || state.admin?.resources?.find((item) => item.id === state.instance.resourceId);
  if (!resource) return;
  els.snapshotForm.dataset.operation = "create";
  els.snapshotForm.dataset.resource = resource.id;
  delete els.snapshotForm.dataset.snapshot;
  els.snapshotDialogEyebrow.textContent = "New recovery point";
  els.snapshotDialogTitle.textContent = "Create snapshot";
  els.snapshotDialogBody.innerHTML = `<div class="snapshot-dialog-summary">${resourceIdentity(resource)}</div>
    <div class="field"><label for="snapshotName">Snapshot name</label><input id="snapshotName" name="name" required maxlength="80" pattern="[A-Za-z0-9][A-Za-z0-9_.-]{0,79}" placeholder="before-update"><small>Letters, numbers, dots, underscores, and hyphens only.</small></div>
    <div class="field"><label for="snapshotDescription">Description <span class="optional">(optional)</span></label><textarea id="snapshotDescription" name="description" maxlength="500" placeholder="What is changing after this recovery point?"></textarea></div>
    ${resource.type === "qemu" ? `<label class="policy-checkbox"><input name="includeMemory" type="checkbox" ${resource.status !== "running" ? "disabled" : ""}><span><strong>Include running memory</strong><small>${resource.status === "running" ? "Creates a larger snapshot that can resume the VM's current runtime state." : "Start the VM before saving its memory state."}</small></span></label>` : ""}
    <div class="notice snapshot-dialog-notice"><span>i</span><span>Snapshots share the server's storage. Keep independent Proxmox backups for disaster recovery.</span></div>`;
  els.snapshotDialogError.textContent = "";
  els.confirmSnapshot.className = "button primary";
  els.confirmSnapshot.textContent = "Create snapshot";
  els.snapshotDialog.showModal();
  queueMicrotask(() => document.getElementById("snapshotName")?.focus());
}

function openSnapshotMutation(operation, name) {
  const resource = (state.dashboard?.resources || []).find((item) => item.id === state.instance.resourceId)
    || state.admin?.resources?.find((item) => item.id === state.instance.resourceId);
  if (!resource) return;
  const restoring = operation === "restore";
  els.snapshotForm.dataset.operation = operation;
  els.snapshotForm.dataset.resource = resource.id;
  els.snapshotForm.dataset.snapshot = name;
  els.snapshotDialogEyebrow.textContent = restoring ? "Destructive recovery action" : "Permanent snapshot removal";
  els.snapshotDialogTitle.textContent = restoring ? "Restore snapshot?" : "Delete snapshot?";
  els.snapshotDialogBody.innerHTML = `<div class="snapshot-dialog-summary">${resourceIdentity(resource)}</div>
    <div class="snapshot-confirm-copy">
      <span class="snapshot-icon">${restoring ? "↶" : "×"}</span>
      <span><small>Selected snapshot</small><strong>${escapeHtml(name)}</strong></span>
    </div>
    <div class="notice warning snapshot-dialog-notice"><span>!</span><span>${restoring ? "Restoring replaces the server's current disk state and may discard newer data." : "Deleting this recovery point cannot be undone."}</span></div>
    <div class="field"><label for="snapshotConfirmName">Type <code>${escapeHtml(name)}</code> to confirm</label><input id="snapshotConfirmName" name="confirmName" required autocomplete="off" spellcheck="false"></div>`;
  els.snapshotDialogError.textContent = "";
  els.confirmSnapshot.className = "button danger";
  els.confirmSnapshot.textContent = restoring ? "Restore snapshot" : "Delete snapshot";
  els.snapshotDialog.showModal();
  queueMicrotask(() => document.getElementById("snapshotConfirmName")?.focus());
}

async function runSnapshotOperation(form) {
  const operation = form.dataset.operation;
  const resourceId = form.dataset.resource;
  const selectedSnapshot = form.dataset.snapshot;
  const data = new FormData(form);
  let path = `/api/v1/resources/${encodeURIComponent(resourceId)}/snapshots`;
  let body;
  let taskAction;
  if (operation === "create") {
    body = {
      name: data.get("name"),
      description: data.get("description"),
      includeMemory: data.has("includeMemory"),
    };
    taskAction = "snapshot_create";
  } else {
    const confirmName = String(data.get("confirmName") || "");
    if (confirmName !== selectedSnapshot) {
      els.snapshotDialogError.textContent = friendlyError({ code: "snapshot_confirmation_mismatch" });
      return;
    }
    path += `/${encodeURIComponent(selectedSnapshot)}/${operation}`;
    body = { confirmName };
    taskAction = `snapshot_${operation}`;
  }
  els.snapshotDialogError.textContent = "";
  els.confirmSnapshot.disabled = true;
  try {
    const result = await apiFetch(path, {
      method: "POST",
      headers: { "Idempotency-Key": `${state.user.id}-${resourceId}-${taskAction}-${selectedSnapshot || body.name}-${Date.now()}` },
      body,
    });
    if (result.task) mergeTask(result.task);
    els.snapshotDialog.close();
    if (result.completed) {
      await loadInstanceDetails(resourceId, { quiet: true });
      showToast("success", operation === "create" ? "Snapshot created" : operation === "restore" ? "Snapshot restored" : "Snapshot deleted", "The recovery point was updated successfully.");
    } else {
      route();
      scheduleTaskPolling();
      showToast("success", `${actionLabel(taskAction)} started`, "Nimbus will follow the Proxmox task automatically.");
    }
  } catch (error) {
    if (error.payload?.task) {
      mergeTask(error.payload.task);
      scheduleTaskPolling();
      route();
    }
    els.snapshotDialogError.textContent = friendlyError(error);
  } finally {
    els.confirmSnapshot.disabled = false;
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

async function armIsoBoot(resourceId) {
  try {
    await apiFetch(`/api/v1/resources/${encodeURIComponent(resourceId)}/media/boot-once`, { method: "POST", body: {} });
    await loadInstanceMedia({ quiet: true });
    showToast("success", "One-time ISO boot ready", "Start or reboot the VM. Nimbus will restore its previous boot order afterward.");
  } catch (error) { showToast("error", "Could not schedule ISO boot", friendlyError(error)); }
}

async function cancelIsoBoot(resourceId) {
  try {
    await apiFetch(`/api/v1/resources/${encodeURIComponent(resourceId)}/media/boot-once/cancel`, { method: "POST", body: {} });
    await loadInstanceMedia({ quiet: true });
    showToast("success", "Normal boot restored", "The VM will use its previous boot order.");
  } catch (error) { showToast("error", "Could not restore boot order", friendlyError(error)); }
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
    if (completedAny) {
      await loadDashboard();
      if (state.currentView === "instance" && state.instance.resourceId) await loadInstanceDetails(state.instance.resourceId, { quiet: true });
    }
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
    if (state.currentView === "network") await loadNetwork();
    if (state.currentView === "notifications") await loadNotifications();
    if (state.currentView === "maintenance") await loadMaintenance();
    if (state.currentView === "support") await loadSupport();
    if (state.currentView === "settings") await loadApiKeys();
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

async function completeAuthentication(result) {
  setDemoReadOnly(result.demoReadOnly);
  state.user = result.user;
  state.csrfToken = result.csrfToken;
  state.mfaChallenge = null;
  setAuthenticated(true);
  applyUser();
  await loadDashboard();
  location.hash = "#overview";
  route();
}

function setAuthMode(mode) {
  els.loginForm.hidden = mode !== "login";
  els.mfaForm.hidden = mode !== "mfa";
  els.forgotPasswordForm.hidden = mode !== "forgot";
  els.accountCompletionForm.hidden = mode !== "account";
}

function showLoginForm() {
  state.mfaChallenge = null;
  state.accountFlow = null;
  setAuthMode("login");
  els.authError.textContent = "";
  els.mfaAuthError.textContent = "";
  els.forgotPasswordMessage.textContent = "";
  els.accountCompletionMessage.textContent = "";
  els.accountCompletionForm.classList.remove("account-flow-invalid", "account-flow-complete");
  els.accountCompletionBackButton.textContent = "Go to sign in";
  document.getElementById("loginTitle").textContent = "Sign in to your infrastructure";
  els.authDescription.textContent = "Use the account issued by your infrastructure provider.";
  document.getElementById("loginPassword").value = "";
  document.getElementById("loginEmail").focus();
}

function showMfaLogin(challenge) {
  state.mfaChallenge = challenge;
  setAuthMode("mfa");
  els.mfaAuthError.textContent = "";
  els.mfaLoginCode.value = "";
  document.getElementById("loginTitle").textContent = "Verify your sign-in";
  els.authDescription.textContent = "Enter a code from your authenticator or one unused recovery code.";
  els.mfaLoginCode.focus();
}

function resetMfaLogin() {
  showLoginForm();
}

function showForgotPassword() {
  setAuthMode("forgot");
  document.getElementById("loginTitle").textContent = "Reset your password";
  els.authDescription.textContent = "We’ll email a short-lived link if the account can use password recovery.";
  els.forgotPasswordMessage.className = "form-message";
  els.forgotPasswordMessage.textContent = "";
  els.forgotPasswordEmail.value = document.getElementById("loginEmail").value;
  els.forgotPasswordEmail.focus();
}

async function initializeAccountFlow(purpose, token) {
  state.accountFlow = { purpose, token };
  setAuthenticated(false);
  setAuthMode("account");
  els.accountCompletionForm.reset();
  els.accountCompletionForm.classList.remove("account-flow-invalid", "account-flow-complete");
  els.accountCompletionMessage.className = "form-message";
  els.accountCompletionMessage.textContent = "Checking this secure link…";
  els.accountFlowRecipient.textContent = "";
  els.accountCompletionForm.querySelector("button[type='submit']").disabled = true;
  document.getElementById("loginTitle").textContent = purpose === "invitation" ? "Accept your invitation" : "Choose a new password";
  els.authDescription.textContent = "This link is single-use and expires 30 minutes after it was issued.";
  try {
    const result = await apiFetch("/api/auth/account-token", { method: "POST", body: { purpose, token } });
    els.accountFlowRecipient.textContent = result.emailHint ? `For ${result.emailHint}` : "";
    els.accountCompletionMessage.textContent = `Link valid until ${formatDate(result.expiresAt)}.`;
    els.accountCompletionForm.querySelector("button[type='submit']").disabled = false;
    els.accountPassword.focus();
  } catch (error) {
    els.accountCompletionForm.classList.add("account-flow-invalid");
    els.accountCompletionMessage.className = "form-message error";
    els.accountCompletionMessage.textContent = friendlyError(error);
    document.getElementById("loginTitle").textContent = "This link cannot be used";
    els.authDescription.textContent = "Ask an administrator for a new invitation or request another password-reset link.";
  }
}

async function initializeApp() {
  const params = new URLSearchParams(location.search);
  const inviteToken = params.get("invite");
  const resetToken = params.get("reset");
  if (inviteToken || resetToken) {
    const purpose = inviteToken ? "invitation" : "password_reset";
    const token = inviteToken || resetToken;
    history.replaceState({}, "", `${location.pathname}${location.hash}`);
    await initializeAccountFlow(purpose, token);
    return;
  }
  await loadSession();
}

els.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  els.authError.textContent = "";
  const button = event.currentTarget.querySelector("button");
  button.disabled = true;
  try {
    const result = await apiFetch("/api/auth/login", { method: "POST", body: formPayload(event.currentTarget) });
    if (result.mfaRequired) {
      showMfaLogin(result);
      return;
    }
    await completeAuthentication(result);
  } catch (error) { els.authError.textContent = friendlyError(error); }
  finally { button.disabled = false; }
});

els.mfaForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  els.mfaAuthError.textContent = "";
  const button = event.currentTarget.querySelector("button[type='submit']");
  button.disabled = true;
  try {
    const result = await apiFetch("/api/auth/mfa", {
      method: "POST",
      body: {
        challengeToken: state.mfaChallenge?.challengeToken,
        code: new FormData(event.currentTarget).get("code"),
      },
    });
    await completeAuthentication(result);
  } catch (error) {
    els.mfaAuthError.textContent = friendlyError(error);
    if (error.code === "invalid_mfa_challenge") setTimeout(resetMfaLogin, 1000);
  } finally {
    button.disabled = false;
  }
});

els.mfaBackButton.addEventListener("click", resetMfaLogin);
els.forgotPasswordButton.addEventListener("click", showForgotPassword);
els.forgotPasswordBackButton.addEventListener("click", showLoginForm);
els.accountCompletionBackButton.addEventListener("click", showLoginForm);

els.forgotPasswordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector("button[type='submit']");
  els.forgotPasswordMessage.className = "form-message";
  els.forgotPasswordMessage.textContent = "Submitting securely…";
  button.disabled = true;
  try {
    await apiFetch("/api/auth/password/forgot", { method: "POST", body: formPayload(event.currentTarget) });
    els.forgotPasswordMessage.className = "form-message success";
    els.forgotPasswordMessage.textContent = "If an eligible account exists, a reset link is on its way. Check your inbox and spam folder.";
  } catch (error) {
    els.forgotPasswordMessage.className = "form-message error";
    els.forgotPasswordMessage.textContent = friendlyError(error);
  } finally {
    button.disabled = false;
  }
});

els.accountCompletionForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  if (!state.accountFlow?.token || form.classList.contains("account-flow-invalid")) return;
  const payload = formPayload(form);
  if (payload.password !== payload.confirmPassword) {
    els.accountCompletionMessage.className = "form-message error";
    els.accountCompletionMessage.textContent = friendlyError({ code: "password_confirmation_mismatch" });
    return;
  }
  const button = form.querySelector("button[type='submit']");
  button.disabled = true;
  els.accountCompletionMessage.className = "form-message";
  els.accountCompletionMessage.textContent = "Saving your password and revoking old sessions…";
  try {
    const completedPurpose = state.accountFlow.purpose;
    await apiFetch("/api/auth/account/complete", {
      method: "POST",
      body: { ...payload, purpose: state.accountFlow.purpose, token: state.accountFlow.token },
    });
    state.accountFlow = null;
    form.classList.add("account-flow-complete");
    document.getElementById("loginTitle").textContent = completedPurpose === "invitation" ? "Your account is ready" : "Password updated";
    els.authDescription.textContent = "Sign in with your new password. Two-factor authentication remains enabled when it was already configured.";
    els.accountCompletionMessage.className = "form-message success";
    els.accountCompletionMessage.textContent = "Your password was saved and all existing sessions were revoked.";
    els.accountCompletionBackButton.textContent = "Continue to sign in";
  } catch (error) {
    els.accountCompletionMessage.className = "form-message error";
    els.accountCompletionMessage.textContent = friendlyError(error);
    button.disabled = false;
  }
});

els.logoutButton.addEventListener("click", async () => {
  try { await apiFetch("/api/auth/logout", { method: "POST", body: {} }); } catch { /* clear local view regardless */ }
  location.reload();
});
els.refreshButton.addEventListener("click", () => refresh());
els.appearanceButton.addEventListener("click", cycleAppearance);
els.authAppearanceButton.addEventListener("click", cycleAppearance);
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

els.snapshotForm.addEventListener("submit", (event) => {
  event.preventDefault();
  runSnapshotOperation(event.currentTarget);
});

els.editForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const { kind, id } = form.dataset;
  const data = new FormData(form);
  try {
    if (kind === "assignment") {
      const payload = {
        customerId: data.get("customerId"),
        displayName: data.get("displayName"),
        snapshotLimit: Number(data.get("snapshotLimit")),
        permissions: data.getAll("permissions"),
        alertPolicy: {
          enabled: data.has("alertEnabled"),
          offline: data.has("alertOffline"),
          cpu: data.has("alertCpu"),
          memory: data.has("alertMemory"),
          storage: data.has("alertStorage"),
          cpuThreshold: Number(data.get("alertCpuThreshold")),
          memoryThreshold: Number(data.get("alertMemoryThreshold")),
          storageThreshold: Number(data.get("alertStorageThreshold")),
          sustainMinutes: Number(data.get("alertSustainMinutes")),
          cooldownMinutes: Number(data.get("alertCooldownMinutes")),
        },
      };
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
      const resetMfa = data.has("resetMfa");
      const adminPasswordForMfaReset = payload.adminPasswordForMfaReset;
      delete payload.password;
      delete payload.resetMfa;
      delete payload.adminPasswordForMfaReset;
      if (payload.role === "admin") payload.customerId = null;
      if (resetMfa && !adminPasswordForMfaReset) {
        els.editDialogError.textContent = "Enter your administrator password to reset 2FA.";
        return;
      }
      if (resetMfa) {
        await apiFetch(`/api/admin/users/${encodeURIComponent(id)}/mfa/reset`, {
          method: "POST",
          body: { currentPassword: adminPasswordForMfaReset },
        });
      }
      await apiFetch(`/api/admin/users/${encodeURIComponent(id)}`, { method: "PATCH", body: payload });
      if (password) await apiFetch(`/api/admin/users/${encodeURIComponent(id)}/password`, { method: "POST", body: { password } });
    } else if (kind === "api-policy") {
      const payload = {
        enabled: data.has("apiEnabled"),
        maxActiveKeys: Number(data.get("maxActiveKeys")),
        maxLifetimeDays: Number(data.get("maxLifetimeDays")),
        allowNoExpiry: data.has("allowNoExpiry"),
        groups: data.getAll("policyGroups"),
        allVisibleResources: data.has("allVisibleResources"),
        resourceIds: data.has("allVisibleResources") ? [] : data.getAll("policyResources"),
      };
      if (payload.enabled && !payload.groups.length) {
        els.editDialogError.textContent = "Choose at least one maximum permission group before enabling API access.";
        return;
      }
      await apiFetch(`/api/admin/users/${encodeURIComponent(id)}/api-access`, { method: "PATCH", body: payload });
    } else if (kind === "api-key-create") {
      if (!state.apiKeyDraft) {
        els.editDialogError.textContent = "The API key preview expired. Close this window and review the key again.";
        return;
      }
      const result = await apiFetch("/api/v1/api-keys", {
        method: "POST",
        body: {
          ...state.apiKeyDraft,
          preview: undefined,
          currentPassword: data.get("currentPassword"),
          code: data.get("code"),
        },
      });
      state.apiKeySecret = result.secret;
      state.apiKeyDraft = null;
      state.apiKeys = await apiFetch("/api/v1/api-keys");
      els.editForm.dataset.kind = "api-key-secret";
      els.editDialogTitle.textContent = "API key created";
      els.editDialogBody.innerHTML = `${apiKeySummaryMarkup(result.key.summary, { secret: result.secret })}
        <div class="notice"><span>✓</span><span>The key is active immediately and remains constrained by the live administrator and resource-assignment policies.</span></div>`;
      els.editDialogError.textContent = "";
      els.editForm.querySelector("button[type='submit']").textContent = "Done";
      renderSettings();
      return;
    } else if (kind === "api-key-secret") {
      els.editDialog.close();
      return;
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
    } else if (kind === "maintenance") {
      const payload = maintenanceFormPayload(form);
      delete payload.publication;
      await apiFetch(`/api/admin/maintenance-events/${encodeURIComponent(id)}`, { method: "PATCH", body: payload });
    } else return;
    els.editDialog.close();
    await refresh({ quiet: true });
    showToast("success", kind === "assignment" ? "Assignment saved" : "Changes saved", kind === "assignment" ? "The customer policy is active immediately." : "The control-center record has been updated.");
  } catch (error) { els.editDialogError.textContent = friendlyError(error); }
});

els.viewRoot.addEventListener("click", async (event) => {
  const target = event.target.closest("button, a");
  if (!target) return;
  if (target.dataset.appearance) {
    setAppearance(target.dataset.appearance);
    return;
  }
  if (target.dataset.copyApiSecret !== undefined) {
    try {
      await navigator.clipboard.writeText(state.apiKeySecret || "");
      showToast("success", "API secret copied", "Store it in the integration's secret storage.");
    } catch { showToast("error", "Could not copy", "Select and copy the API secret manually."); }
    return;
  }
  if (target.dataset.copyMfaSecret !== undefined) {
    try {
      await navigator.clipboard.writeText(state.mfaEnrollment?.secret || "");
      showToast("success", "Setup key copied", "Paste it into your authenticator app.");
    } catch { showToast("error", "Could not copy", "Select and copy the setup key manually."); }
    return;
  }
  if (target.dataset.copyRecovery !== undefined) {
    try {
      await navigator.clipboard.writeText((state.recoveryCodes || []).join("\n"));
      showToast("success", "Recovery codes copied", "Store them somewhere secure.");
    } catch { showToast("error", "Could not copy", "Select and copy the recovery codes manually."); }
    return;
  }
  if (target.dataset.dismissRecovery !== undefined) {
    state.recoveryCodes = null;
    renderSettings();
    return;
  }
  if (target.dataset.cancelMfaSetup !== undefined) {
    state.mfaEnrollment = null;
    renderSettings();
    return;
  }
  if (target.dataset.revokeSession) {
    const current = state.dashboard.security?.sessions?.find((item) => item.id === target.dataset.revokeSession)?.current;
    if (!confirm(current ? "Sign out this device now?" : "Revoke this active session?")) return;
    try {
      await apiFetch(`/api/v1/security/sessions/${encodeURIComponent(target.dataset.revokeSession)}`, { method: "DELETE", body: {} });
      if (current) { location.reload(); return; }
      await loadDashboard();
      renderSettings();
      showToast("success", "Session revoked", "That device must sign in again.");
    } catch (error) { showToast("error", "Could not revoke session", friendlyError(error)); }
    return;
  }
  if (target.dataset.revokeApiKey) {
    const key = state.apiKeys?.keys?.find((item) => item.id === target.dataset.revokeApiKey);
    if (!confirm(`Revoke “${key?.name || "this API key"}” now? The integration will immediately lose access.`)) return;
    try {
      await apiFetch(`/api/v1/api-keys/${encodeURIComponent(target.dataset.revokeApiKey)}`, { method: "DELETE", body: {} });
      await loadApiKeys();
      renderSettings();
      showToast("success", "API key revoked", "Requests using that secret are now rejected.");
    } catch (error) { showToast("error", "Could not revoke API key", friendlyError(error)); }
    return;
  }
  if (target.dataset.readNotification) {
    try {
      await apiFetch(`/api/v1/notifications/${encodeURIComponent(target.dataset.readNotification)}/read`, { method: "POST", body: {} });
      await Promise.all([loadDashboard(), loadNotifications()]);
      renderNotifications();
    } catch (error) { showToast("error", "Could not update notification", friendlyError(error)); }
    return;
  }
  if (target.dataset.readAllNotifications !== undefined) {
    try {
      await apiFetch("/api/v1/notifications/read-all", { method: "POST", body: {} });
      await Promise.all([loadDashboard(), loadNotifications()]);
      renderNotifications();
      showToast("success", "Notifications cleared", "Every visible notification is now marked as read.");
    } catch (error) { showToast("error", "Could not update notifications", friendlyError(error)); }
    return;
  }
  if (target.dataset.readMaintenance) {
    try {
      await apiFetch(`/api/v1/maintenance/${encodeURIComponent(target.dataset.readMaintenance)}/read`, { method: "POST", body: {} });
      await Promise.all([loadDashboard(), loadMaintenance()]);
      renderMaintenance();
    } catch (error) { showToast("error", "Could not update maintenance notice", friendlyError(error)); }
    return;
  }
  if (target.dataset.openSupport) {
    location.hash = `#support/${encodeURIComponent(target.dataset.openSupport)}`;
    return;
  }
  if (target.dataset.closeSupport) {
    if (!confirm("Close this support ticket? You can reopen it later if the issue returns.")) return;
    target.disabled = true;
    try {
      await apiFetch(`/api/v1/support/tickets/${encodeURIComponent(target.dataset.closeSupport)}/close`, { method: "POST", body: {} });
      await Promise.all([loadDashboard(), loadSupport(target.dataset.closeSupport)]);
      renderSupport();
      showToast("success", "Support ticket closed", "The conversation remains available in your ticket history.");
    } catch (error) {
      target.disabled = false;
      showToast("error", "Could not close ticket", friendlyError(error));
    }
    return;
  }
  if (target.dataset.reopenSupport) {
    target.disabled = true;
    try {
      await apiFetch(`/api/v1/support/tickets/${encodeURIComponent(target.dataset.reopenSupport)}/reopen`, { method: "POST", body: {} });
      await Promise.all([loadDashboard(), loadSupport(target.dataset.reopenSupport)]);
      renderSupport();
      showToast("success", "Support ticket reopened", "The ticket is waiting for the support team.");
    } catch (error) {
      target.disabled = false;
      showToast("error", "Could not reopen ticket", friendlyError(error));
    }
    return;
  }
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
  if (target.dataset.createSnapshot !== undefined) { openSnapshotCreate(); return; }
  if (target.dataset.restoreSnapshot) { openSnapshotMutation("restore", target.dataset.restoreSnapshot); return; }
  if (target.dataset.deleteSnapshot) { openSnapshotMutation("delete", target.dataset.deleteSnapshot); return; }
  if (target.dataset.mountIso) { await mountIso(state.instance.resourceId, target.dataset.mountIso); return; }
  if (target.dataset.armIsoBoot !== undefined) {
    if (!confirm("Boot from the mounted ISO on the VM's next start or reboot? Nimbus will restore the previous boot order afterward.")) return;
    await armIsoBoot(state.instance.resourceId);
    return;
  }
  if (target.dataset.cancelIsoBoot !== undefined) { await cancelIsoBoot(state.instance.resourceId); return; }
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
  if (target.dataset.resendInvitation) {
    target.disabled = true;
    try {
      await apiFetch(`/api/admin/users/${encodeURIComponent(target.dataset.resendInvitation)}/invitation/resend`, { method: "POST", body: {} });
      await loadAdmin();
      renderAdmin();
      showToast("success", "Invitation sent", "The previous link was invalidated and a new 30-minute link was queued.");
    } catch (error) {
      target.disabled = false;
      showToast("error", "Could not resend invitation", friendlyError(error));
    }
    return;
  }
  if (target.dataset.revokeInvitation) {
    if (!confirm("Revoke this invitation link? The user account remains, but it cannot sign in until you resend an invitation or set a password manually.")) return;
    target.disabled = true;
    try {
      await apiFetch(`/api/admin/users/${encodeURIComponent(target.dataset.revokeInvitation)}/invitation/revoke`, { method: "POST", body: {} });
      await loadAdmin();
      renderAdmin();
      showToast("success", "Invitation revoked", "The account remains pending and the existing link can no longer be used.");
    } catch (error) {
      target.disabled = false;
      showToast("error", "Could not revoke invitation", friendlyError(error));
    }
    return;
  }
  if (target.dataset.editUser) { openUserEditor(target.dataset.editUser); return; }
  if (target.dataset.apiAccessUser) { await openApiAccessEditor(target.dataset.apiAccessUser); return; }
  if (target.dataset.adminRevokeApiKey) {
    if (!confirm("Revoke this API key now? The integration will immediately lose access.")) return;
    try {
      await apiFetch(`/api/admin/users/${encodeURIComponent(target.dataset.apiUser)}/api-keys/${encodeURIComponent(target.dataset.adminRevokeApiKey)}`, { method: "DELETE", body: {} });
      await loadAdmin();
      await openApiAccessEditor(target.dataset.apiUser);
      showToast("success", "API key revoked", "The key can no longer authenticate.");
    } catch (error) { showToast("error", "Could not revoke API key", friendlyError(error)); }
    return;
  }
  if (target.dataset.adminRevokeAllApiKeys) {
    if (!confirm("Revoke every active API key for this user? All connected integrations will immediately lose access.")) return;
    try {
      await apiFetch(`/api/admin/users/${encodeURIComponent(target.dataset.adminRevokeAllApiKeys)}/api-keys/revoke-all`, { method: "POST", body: {} });
      await loadAdmin();
      await openApiAccessEditor(target.dataset.adminRevokeAllApiKeys);
      showToast("success", "API keys revoked", "All active integration keys were disabled.");
    } catch (error) { showToast("error", "Could not revoke API keys", friendlyError(error)); }
    return;
  }
  if (target.dataset.editCluster) { openClusterEditor(target.dataset.editCluster); return; }
  if (target.dataset.editIsoPolicy) { openIsoPolicyEditor(target.dataset.editIsoPolicy); return; }
  if (target.dataset.editMaintenance) { openMaintenanceEditor(target.dataset.editMaintenance); return; }
  if (target.dataset.publishMaintenance) {
    if (!confirm("Publish this notice now? Nimbus will freeze the currently affected customer-user audience and optionally queue email.")) return;
    target.disabled = true;
    try {
      const result = await apiFetch(`/api/admin/maintenance-events/${encodeURIComponent(target.dataset.publishMaintenance)}/publish`, { method: "POST", body: {} });
      await loadAdmin();
      renderAdmin();
      showToast("success", "Maintenance notice published", `${plural(result.event.recipientCount || 0, "user")} can now see it${result.queuedEmails ? ` · ${plural(result.queuedEmails, "email")} queued` : ""}.`);
    } catch (error) {
      target.disabled = false;
      showToast("error", "Could not publish notice", friendlyError(error));
    }
    return;
  }
  if (target.dataset.resolveMaintenance) {
    if (!confirm("Mark this notice as resolved? A recovery email will be queued for affected users who opted in.")) return;
    target.disabled = true;
    try {
      const result = await apiFetch(`/api/admin/maintenance-events/${encodeURIComponent(target.dataset.resolveMaintenance)}/resolve`, { method: "POST", body: {} });
      await loadAdmin();
      renderAdmin();
      showToast("success", "Maintenance resolved", result.queuedEmails ? `${plural(result.queuedEmails, "recovery email")} queued.` : "The resolved state is visible in customer maintenance history.");
    } catch (error) {
      target.disabled = false;
      showToast("error", "Could not resolve notice", friendlyError(error));
    }
    return;
  }
  if (target.dataset.cancelMaintenance) {
    if (!confirm("Cancel this scheduled notice? Affected users will see the cancelled state in their maintenance history.")) return;
    target.disabled = true;
    try {
      await apiFetch(`/api/admin/maintenance-events/${encodeURIComponent(target.dataset.cancelMaintenance)}/cancel`, { method: "POST", body: {} });
      await loadAdmin();
      renderAdmin();
      showToast("success", "Maintenance cancelled", "The published notice now shows as cancelled.");
    } catch (error) {
      target.disabled = false;
      showToast("error", "Could not cancel notice", friendlyError(error));
    }
    return;
  }
  if (target.dataset.deleteMaintenance) {
    if (!confirm("Delete this unpublished draft?")) return;
    try {
      await apiFetch(`/api/admin/maintenance-events/${encodeURIComponent(target.dataset.deleteMaintenance)}`, { method: "DELETE", body: {} });
      await loadAdmin();
      renderAdmin();
      showToast("success", "Draft deleted", "No customer ever received this notice.");
    } catch (error) { showToast("error", "Could not delete draft", friendlyError(error)); }
    return;
  }
  if (target.dataset.testEmailConnection !== undefined) {
    target.disabled = true;
    try {
      await apiFetch("/api/admin/email/test-connection", { method: "POST", body: {} });
      await loadAdmin();
      renderAdmin();
      showToast("success", "SMTP connection verified", "TLS and authentication completed successfully.");
    } catch (error) {
      await loadAdmin().catch(() => {});
      renderAdmin();
      showToast("error", "Connection test failed", friendlyError(error));
    }
    return;
  }
  if (target.dataset.retryEmail) {
    target.disabled = true;
    try {
      await apiFetch(`/api/admin/email/jobs/${encodeURIComponent(target.dataset.retryEmail)}/retry`, { method: "POST", body: {} });
      await loadAdmin();
      renderAdmin();
      showToast("success", "Email queued again", "Nimbus will retry this delivery in the background.");
    } catch (error) {
      target.disabled = false;
      showToast("error", "Could not retry email", friendlyError(error));
    }
    return;
  }
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
  if (target.dataset.refreshOperations !== undefined) {
    target.disabled = true;
    const original = target.textContent;
    target.textContent = "Checking infrastructure…";
    try {
      const result = await apiFetch("/api/admin/operations/refresh", { method: "POST", body: {}, timeoutMs: 180_000 });
      state.admin.operations = result.operations;
      await loadAdmin();
      renderAdmin();
      const failed = (result.results || []).filter((item) => !item.success).length;
      showToast(
        failed ? "error" : "success",
        failed ? "Health refresh completed with warnings" : "Infrastructure health refreshed",
        failed
          ? `${plural(failed, "cluster")} could not be synchronized. The Operations Center kept its last good telemetry.`
          : "Cluster, node, storage, task, and assignment health are current.",
      );
    } catch (error) {
      showToast("error", "Health refresh failed", friendlyError(error));
      target.disabled = false;
      target.textContent = original;
    }
    return;
  }
  if (target.dataset.ackIncident) {
    target.disabled = true;
    try {
      await apiFetch(`/api/admin/operations/incidents/${encodeURIComponent(target.dataset.ackIncident)}/acknowledge`, {
        method: "POST",
        body: {},
      });
      await loadAdmin();
      renderAdmin();
      showToast("success", "Incident acknowledged", "Nimbus will continue monitoring and resolve it automatically when the condition clears.");
    } catch (error) {
      target.disabled = false;
      showToast("error", "Could not acknowledge incident", friendlyError(error));
    }
    return;
  }
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
  if (target.name === "onboardingMode") {
    const form = target.closest("form");
    const passwordField = form?.querySelector("[data-onboarding-password]");
    const passwordInput = form?.elements.password;
    const invitation = target.value === "invitation";
    if (passwordField) passwordField.hidden = invitation;
    if (passwordInput) {
      passwordInput.required = !invitation;
      if (invitation) passwordInput.value = "";
    }
    const submit = form?.querySelector("button[type='submit']");
    if (submit) submit.textContent = invitation ? "Create and send invitation" : "Create user";
  }
  if (target.matches("[data-iso-cluster]")) {
    state.isoClusterId = target.value;
    renderAdmin();
  }
  if (target.matches("[data-maintenance-audience]")) updateMaintenanceAudience(target);
});

function updateMaintenanceAudience(audience) {
  const form = audience.closest("form");
  const targetSelect = form?.elements.targetIds;
  if (!targetSelect) return;
  targetSelect.disabled = audience.value === "all";
  targetSelect.required = audience.value !== "all";
  targetSelect.innerHTML = maintenanceTargetOptions(audience.value, []);
  const help = targetSelect.parentElement?.querySelector("small");
  if (help) help.textContent = audience.value === "all"
    ? "Every active customer user receives the notice."
    : "Hold Ctrl or Command to choose multiple targets.";
}

els.editDialog.addEventListener("change", (event) => {
  if (event.target.matches("[data-maintenance-audience]")) updateMaintenanceAudience(event.target);
  if (event.target.name === "allVisibleResources") {
    els.editDialog.querySelectorAll('input[name="policyResources"]').forEach((input) => {
      input.disabled = event.target.checked;
      if (event.target.checked) input.checked = false;
    });
  }
});

els.editDialog.addEventListener("click", async (event) => {
  const target = event.target.closest("button");
  if (!target) return;
  if (target.dataset.copyApiSecret !== undefined) {
    try {
      await navigator.clipboard.writeText(state.apiKeySecret || "");
      showToast("success", "API secret copied", "Store it in the integration's secret storage.");
    } catch { showToast("error", "Could not copy", "Select and copy the API secret manually."); }
    return;
  }
  if (target.dataset.adminRevokeApiKey) {
    if (!confirm("Revoke this API key now? The integration will immediately lose access.")) return;
    target.disabled = true;
    try {
      await apiFetch(`/api/admin/users/${encodeURIComponent(target.dataset.apiUser)}/api-keys/${encodeURIComponent(target.dataset.adminRevokeApiKey)}`, { method: "DELETE", body: {} });
      await loadAdmin();
      await openApiAccessEditor(target.dataset.apiUser);
      showToast("success", "API key revoked", "The key can no longer authenticate.");
    } catch (error) {
      target.disabled = false;
      showToast("error", "Could not revoke API key", friendlyError(error));
    }
    return;
  }
  if (target.dataset.adminRevokeAllApiKeys) {
    if (!confirm("Revoke every active API key for this user? All connected integrations will immediately lose access.")) return;
    target.disabled = true;
    try {
      await apiFetch(`/api/admin/users/${encodeURIComponent(target.dataset.adminRevokeAllApiKeys)}/api-keys/revoke-all`, { method: "POST", body: {} });
      await loadAdmin();
      await openApiAccessEditor(target.dataset.adminRevokeAllApiKeys);
      showToast("success", "API keys revoked", "All active integration keys were disabled.");
    } catch (error) {
      target.disabled = false;
      showToast("error", "Could not revoke API keys", friendlyError(error));
    }
  }
});

els.editDialog.addEventListener("close", () => {
  state.apiKeyDraft = null;
  state.apiKeySecret = null;
  state.apiAccessEditor = null;
  const submit = els.editForm.querySelector("button[type='submit']");
  if (submit) {
    submit.textContent = "Save changes";
    submit.disabled = false;
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

async function submitSecurityForm(form) {
  const endpoints = {
    mfaSetupForm: ["/api/v1/security/mfa/setup", "Two-factor setup started"],
    mfaConfirmForm: ["/api/v1/security/mfa/confirm", "Two-factor authentication enabled"],
    mfaDisableForm: ["/api/v1/security/mfa/disable", "Two-factor authentication disabled"],
    mfaRecoveryForm: ["/api/v1/security/mfa/recovery-codes", "Recovery codes replaced"],
    revokeOtherSessionsForm: ["/api/v1/security/sessions/revoke-others", "Other sessions revoked"],
  };
  const entry = endpoints[form.id];
  if (!entry) return false;
  if (!form.checkValidity()) { form.reportValidity(); return true; }
  const message = form.querySelector(".form-message");
  const button = form.querySelector("button[type='submit']");
  if (message) { message.className = "form-message"; message.textContent = "Verifying securely…"; }
  if (button) button.disabled = true;
  try {
    const result = await apiFetch(entry[0], { method: "POST", body: formPayload(form) });
    if (form.id === "mfaSetupForm") {
      state.mfaEnrollment = result.enrollment;
    } else {
      state.mfaEnrollment = null;
      if (result.recoveryCodes) state.recoveryCodes = result.recoveryCodes;
      await loadDashboard();
    }
    renderSettings();
    showToast("success", entry[1], form.id === "mfaConfirmForm"
      ? "Save the recovery codes before leaving this page."
      : "Your account security settings are up to date.");
  } catch (error) {
    if (message) { message.className = "form-message error"; message.textContent = friendlyError(error); }
    showToast("error", "Security change failed", friendlyError(error));
    if (button) button.disabled = false;
  }
  return true;
}

els.viewRoot.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  if (form.id === "apiKeyCreateForm") {
    await reviewApiKey(form);
    return;
  }
  if (await submitSecurityForm(form)) return;
  if (form.id === "securityPolicyForm") {
    const data = new FormData(form);
    const message = form.querySelector(".form-message");
    const button = form.querySelector("button[type='submit']");
    message.className = "form-message";
    message.textContent = "Applying policy…";
    button.disabled = true;
    try {
      const result = await apiFetch("/api/admin/security/policy", {
        method: "PATCH",
        body: {
          requireAdminMfa: data.has("requireAdminMfa"),
          requireCustomerMfa: data.has("requireCustomerMfa"),
          newLoginEmail: data.has("newLoginEmail"),
        },
      });
      state.admin.security = result.security;
      await loadDashboard();
      if (state.dashboard.security?.mfa?.enrollmentRequired) {
        state.admin = null;
        location.hash = "#settings";
        route();
        showToast("success", "Security policy enabled", "Set up two-factor authentication to unlock administrator access.");
      } else {
        renderAdmin();
        showToast("success", "Security policy saved", "The new account-security rules are enforced immediately.");
      }
    } catch (error) {
      message.className = "form-message error";
      message.textContent = friendlyError(error);
      button.disabled = false;
    }
    return;
  }
  if (form.id === "supportTicketForm") {
    if (!form.checkValidity()) { form.reportValidity(); return; }
    const message = form.querySelector(".form-message");
    const button = form.querySelector("button[type='submit']");
    message.className = "form-message";
    message.textContent = "Creating your private support conversation…";
    button.disabled = true;
    try {
      const result = await apiFetch("/api/v1/support/tickets", { method: "POST", body: formPayload(form) });
      await loadDashboard();
      state.support = null;
      location.hash = `#support/${encodeURIComponent(result.ticket.id)}`;
      await loadSupport(result.ticket.id);
      renderSupport();
      showToast("success", "Support ticket created", `${result.ticket.reference} is now waiting for support.`);
    } catch (error) {
      message.className = "form-message error";
      message.textContent = friendlyError(error);
      button.disabled = false;
    }
    return;
  }
  if (form.id === "supportReplyForm") {
    if (!form.checkValidity()) { form.reportValidity(); return; }
    const ticketId = form.dataset.ticketId;
    const data = new FormData(form);
    const message = form.querySelector(".form-message");
    const button = form.querySelector("button[type='submit']");
    message.className = "form-message";
    message.textContent = data.has("internal") ? "Saving private administrator note…" : "Sending reply…";
    button.disabled = true;
    try {
      await apiFetch(`/api/v1/support/tickets/${encodeURIComponent(ticketId)}/messages`, {
        method: "POST",
        body: { message: data.get("message"), internal: data.has("internal") },
      });
      await Promise.all([loadDashboard(), loadSupport(ticketId)]);
      renderSupport();
      showToast("success", data.has("internal") ? "Internal note saved" : "Reply sent", data.has("internal") ? "Only administrators can see this note." : "The support conversation has been updated.");
    } catch (error) {
      message.className = "form-message error";
      message.textContent = friendlyError(error);
      button.disabled = false;
    }
    return;
  }
  if (form.id === "supportManageForm") {
    const ticketId = form.dataset.ticketId;
    const message = form.querySelector(".form-message");
    const button = form.querySelector("button[type='submit']");
    button.disabled = true;
    message.className = "form-message";
    message.textContent = "Saving ticket ownership and status…";
    try {
      await apiFetch(`/api/v1/support/tickets/${encodeURIComponent(ticketId)}`, {
        method: "PATCH",
        body: formPayload(form),
      });
      await Promise.all([loadDashboard(), loadSupport(ticketId)]);
      renderSupport();
      showToast("success", "Ticket updated", "Status, priority, and ownership are current.");
    } catch (error) {
      message.className = "form-message error";
      message.textContent = friendlyError(error);
      button.disabled = false;
    }
    return;
  }
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
  if (form.id === "emailTestForm") {
    const message = form.querySelector(".form-message");
    const button = form.querySelector("button[type='submit']");
    if (!form.checkValidity()) { form.reportValidity(); return; }
    message.className = "form-message";
    message.textContent = "Connecting and sending…";
    button.disabled = true;
    try {
      await apiFetch("/api/admin/email/test-message", { method: "POST", body: formPayload(form) });
      await loadAdmin();
      renderAdmin();
      showToast("success", "Test email delivered", "The SMTP server accepted the message.");
    } catch (error) {
      await loadAdmin().catch(() => {});
      renderAdmin();
      showToast("error", "Test email failed", friendlyError(error));
    }
    return;
  }
  if (form.id === "notificationPreferencesForm") {
    const data = new FormData(form);
    const message = form.querySelector(".form-message");
    const button = form.querySelector("button[type='submit'], button:not([type])");
    button.disabled = true;
    try {
      const result = await apiFetch("/api/v1/notifications/preferences", {
        method: "PATCH",
        body: {
          inAppEnabled: data.has("inAppEnabled"),
          emailEnabled: data.has("emailEnabled"),
          actionSuccess: data.has("actionSuccess"),
          actionFailure: data.has("actionFailure"),
          infrastructureAlerts: data.has("infrastructureAlerts"),
          resolutionAlerts: data.has("resolutionAlerts"),
        },
      });
      state.dashboard.notificationPreferences = result.preferences;
      if (state.notifications) state.notifications.preferences = result.preferences;
      renderNotifications();
      showToast("success", "Preferences saved", "Your private notification channels have been updated.");
    } catch (error) {
      message.className = "form-message error";
      message.textContent = friendlyError(error);
      button.disabled = false;
    }
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
      const onboardingMode = payload.onboardingMode || "password";
      delete payload.onboardingMode;
      if (payload.role === "admin") payload.customerId = null;
      if (onboardingMode === "invitation") {
        delete payload.password;
        await apiFetch("/api/admin/invitations", { method: "POST", body: payload });
      } else {
        await apiFetch("/api/admin/users", { method: "POST", body: payload });
      }
    } else if (createKind === "iso-policy" || form.id === "createIsoPolicyForm") {
      const payload = formPayload(form);
      payload.maxUploadBytes = Math.round(Number(payload.maxUploadGb) * 1024 ** 3);
      payload.customerQuotaBytes = Math.round(Number(payload.quotaGb) * 1024 ** 3);
      payload.allowDelete = new FormData(form).has("allowDelete");
      delete payload.maxUploadGb;
      delete payload.quotaGb;
      await apiFetch("/api/admin/iso-policies", { method: "POST", body: payload });
    } else if (createKind === "maintenance" || form.id === "createMaintenanceForm") {
      const result = await apiFetch("/api/admin/maintenance-events", {
        method: "POST",
        body: maintenanceFormPayload(form),
      });
      await loadAdmin();
      renderAdmin();
      showToast(
        "success",
        result.event.status === "draft" ? "Maintenance draft saved" : "Maintenance notice published",
        result.event.status === "draft"
          ? "The notice remains private and editable."
          : `${plural(result.event.recipientCount || 0, "user")} can now see it${result.queuedEmails ? ` · ${plural(result.queuedEmails, "email")} queued` : ""}.`,
      );
      return;
    } else if (form.id === "emailSettingsForm") {
      const payload = formPayload(form);
      payload.port = Number(payload.port);
      payload.enabled = new FormData(form).has("enabled");
      await apiFetch("/api/admin/email/settings", { method: "PUT", body: payload });
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
window.addEventListener("nimbusappearancechange", () => {
  refreshAppearanceControls();
  drawInstanceChart();
});
document.addEventListener("visibilitychange", scheduleTaskPolling);

refreshAppearanceControls();
initializeApp();
