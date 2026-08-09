import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

async function waitForServer(baseUrl, child, logs) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Nimbus exited during startup:\n${logs.join("")}`);
    try {
      const response = await fetch(`${baseUrl}/api/health`);
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`Nimbus did not become healthy:\n${logs.join("")}`);
}

test("customer ISO boot and Snapshot Center workflows stay assignment-scoped", async () => {
  const directory = await mkdtemp(join(tmpdir(), "nimbus-direct-server-"));
  const port = 43_000 + process.pid % 1_000;
  const baseUrl = `http://127.0.0.1:${port}`;
  const logs = [];
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd: new URL("..", import.meta.url),
    env: {
      ...process.env,
      NODE_ENV: "development",
      HOST: "127.0.0.1",
      PORT: String(port),
      DATA_DIR: directory,
      APP_SECRET: "server-integration-secret-that-is-at-least-32-characters",
      SESSION_COOKIE_SECURE: "false",
      ALLOW_DEMO_DATA: "true",
      BOOTSTRAP_ADMIN_EMAIL: "admin@example.test",
      BOOTSTRAP_ADMIN_PASSWORD: "admin password for server test",
      BOOTSTRAP_CUSTOMER_ID: "acme",
      BOOTSTRAP_CUSTOMER_NAME: "Acme",
      BOOTSTRAP_CUSTOMER_EMAIL: "customer@example.test",
      BOOTSTRAP_CUSTOMER_PASSWORD: "customer password for server test",
      RESOURCE_SYNC_SECONDS: "3600",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => logs.push(String(chunk)));
  child.stderr.on("data", (chunk) => logs.push(String(chunk)));

  let cookie = "";
  let csrfToken = "";
  async function request(path, { method = "GET", body, headers = {} } = {}) {
    const requestHeaders = { Accept: "application/json", ...headers };
    if (cookie) requestHeaders.Cookie = cookie;
    if (csrfToken && method !== "GET") requestHeaders["X-CSRF-Token"] = csrfToken;
    let requestBody = body;
    if (body !== undefined && !Buffer.isBuffer(body)) {
      requestHeaders["Content-Type"] = "application/json";
      requestBody = JSON.stringify(body);
    }
    const response = await fetch(`${baseUrl}${path}`, { method, headers: requestHeaders, body: requestBody });
    const payload = response.status === 204 ? null : await response.json();
    if (!response.ok) throw Object.assign(new Error(payload?.message || payload?.error || `HTTP ${response.status}`), { response, payload });
    return { response, payload };
  }

  try {
    await waitForServer(baseUrl, child, logs);
    const login = await request("/api/auth/login", {
      method: "POST",
      body: { email: "admin@example.test", password: "admin password for server test" },
    });
    cookie = String(login.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = login.payload.csrfToken;
    assert.ok(cookie);
    assert.ok(csrfToken);

    const initialState = (await request("/api/admin/state")).payload;
    assert.equal(initialState.emailSettings.configured, false);
    assert.equal(initialState.emailJobs.total, 0);
    assert.equal(initialState.operations.summary.nodes, 5);
    assert.equal(initialState.operations.summary.onlineNodes, 5);
    assert.equal(initialState.operations.summary.activeIncidents, 0);
    const operationsRefresh = (await request("/api/admin/operations/refresh", {
      method: "POST",
      body: {},
    })).payload;
    assert.equal(operationsRefresh.results[0].success, true);
    assert.equal(operationsRefresh.operations.summary.healthyClusters, 1);
    const emailSettings = (await request("/api/admin/email/settings", {
      method: "PUT",
      body: {
        enabled: true,
        host: "smtp.example.test",
        port: 587,
        security: "starttls",
        username: "nimbus@example.test",
        password: "smtp-integration-secret",
        fromName: "Nimbus Direct",
        fromEmail: "nimbus@example.test",
      },
    })).payload.settings;
    assert.equal(emailSettings.passwordConfigured, true);
    assert.equal("password" in emailSettings, false);
    assert.equal("passwordEncrypted" in emailSettings, false);
    const stateWithEmail = (await request("/api/admin/state")).payload;
    assert.equal(stateWithEmail.emailSettings.host, "smtp.example.test");
    assert.equal(JSON.stringify(stateWithEmail).includes("smtp-integration-secret"), false);
    const resource = initialState.resources.find((entry) => entry.type === "qemu" && entry.customerId === "acme");
    const policy = initialState.isoPolicies[0];
    assert.ok(resource);
    assert.ok(policy);
    await request("/api/admin/assignments", {
      method: "POST",
      body: {
        customerId: "acme",
        resourceId: resource.id,
        snapshotLimit: 2,
        permissions: [
          "view_status", "reboot", "console", "iso_view", "iso_upload", "iso_mount", "iso_boot",
          "snapshot_create", "snapshot_restore", "snapshot_delete",
        ],
        alertPolicy: {
          enabled: true,
          offline: true,
          cpu: true,
          memory: true,
          storage: true,
          cpuThreshold: 90,
          memoryThreshold: 90,
          storageThreshold: 90,
          sustainMinutes: 5,
          cooldownMinutes: 60,
        },
      },
    });
    const maintenance = (await request("/api/admin/maintenance-events", {
      method: "POST",
      body: {
        kind: "maintenance",
        severity: "warning",
        title: "Demo hypervisor maintenance",
        message: "The assigned demo VM may reboot during this window.",
        startsAt: Date.now() + 60_000,
        endsAt: Date.now() + 120_000,
        notifyEmail: true,
        publication: "publish",
        targets: [{ type: "resource", id: resource.id }],
      },
    })).payload;
    assert.equal(maintenance.event.status, "scheduled");
    assert.equal(maintenance.event.recipientCount, 1);
    assert.equal(maintenance.queuedEmails, 0);
    const lockedMaintenance = (await request("/api/admin/maintenance-events", {
      method: "POST",
      body: {
        kind: "maintenance",
        severity: "warning",
        title: "Customer power controls paused",
        message: "Power actions are paused while the hypervisor is serviced.",
        startsAt: Date.now() - 1_000,
        endsAt: Date.now() + 120_000,
        notifyEmail: false,
        lockGroups: ["power_management"],
        publication: "publish",
        targets: [{ type: "resource", id: resource.id }],
      },
    })).payload;
    assert.equal(lockedMaintenance.event.status, "active");
    assert.deepEqual(lockedMaintenance.event.lockGroups.map((group) => group.id), ["power_management"]);
    await request("/api/auth/logout", { method: "POST", body: {} });
    cookie = "";
    csrfToken = "";
    const customerLogin = await request("/api/auth/login", {
      method: "POST",
      body: { email: "customer@example.test", password: "customer password for server test" },
    });
    cookie = String(customerLogin.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = customerLogin.payload.csrfToken;
    await assert.rejects(
      () => request("/api/admin/operations"),
      (error) => error.payload?.error === "admin_required" && error.response.status === 403,
    );
    const customerDashboard = (await request("/api/v1/dashboard")).payload;
    assert.equal(customerDashboard.maintenance.upcomingCount, 1);
    assert.equal(customerDashboard.maintenance.activeCount, 1);
    assert.equal(customerDashboard.maintenanceLocks.activeCount, 1);
    assert.deepEqual(customerDashboard.maintenanceLocks.items[0].resourceIds, [resource.id]);
    assert.deepEqual(customerDashboard.maintenanceLocks.items[0].groups.map((group) => group.id), ["power_management"]);
    assert.equal(customerDashboard.capabilities.maintenanceCenter, true);
    assert.equal(customerDashboard.capabilities.supportTicketCenter, true);
    const customerNetwork = (await request("/api/v1/network")).payload.networks;
    assert.equal(Object.keys(customerNetwork).length, customerDashboard.resources.length);
    assert.equal(customerNetwork[resource.id].primaryIp, resource.ip);
    assert.equal(customerNetwork[resource.id].source, "demo");
    await assert.rejects(
      () => request(`/api/v1/resources/${encodeURIComponent(resource.id)}/actions`, {
        method: "POST",
        body: { action: "reboot" },
      }),
      (error) => error.response.status === 423
        && error.payload?.error === "maintenance_action_locked"
        && error.payload?.lock?.group?.id === "power_management",
    );
    const consoleLaunch = (await request(`/api/v1/resources/${encodeURIComponent(resource.id)}/console`, {
      method: "POST",
      body: {},
    })).payload;
    assert.match(consoleLaunch.nativeLaunchUrl, /^\/api\/v1\/console\/native-launch\//);
    assert.equal(consoleLaunch.console.type, resource.type === "lxc" ? "terminal" : "graphical");
    assert.equal(consoleLaunch.console.label, resource.type === "lxc" ? "Terminal console" : "Graphical console");
    const consoleToken = decodeURIComponent(consoleLaunch.nativeLaunchUrl.split("/").at(-1));
    const nativeHandoff = await fetch(`${baseUrl}${consoleLaunch.nativeLaunchUrl}`, {
      redirect: "manual",
      headers: { Accept: "text/html" },
    });
    assert.equal(nativeHandoff.status, 303);
    assert.equal(nativeHandoff.headers.get("location"), `/console.html?token=${encodeURIComponent(consoleToken)}`);
    const nativeCookie = String(nativeHandoff.headers.get("set-cookie") || "").split(";")[0];
    assert.match(nativeCookie, /^nimbus_console=/);
    const nativeSession = await fetch(`${baseUrl}/api/v1/console/session/${encodeURIComponent(consoleToken)}`, {
      headers: { Accept: "application/json", Cookie: nativeCookie },
    });
    assert.equal(nativeSession.status, 200);
    const nativeSessionPayload = await nativeSession.json();
    assert.equal(nativeSessionPayload.resource.vmid, resource.vmid);
    assert.equal(nativeSessionPayload.console.type, resource.type === "lxc" ? "terminal" : "graphical");
    assert.equal(nativeSessionPayload.credentials.user, "nimbus-demo@pve");
    const xtermModule = await fetch(`${baseUrl}/vendor/xterm/lib/xterm.mjs`);
    const xtermFitModule = await fetch(`${baseUrl}/vendor/xterm-fit/lib/addon-fit.mjs`);
    assert.equal(xtermModule.status, 200);
    assert.match(xtermModule.headers.get("content-type"), /^text\/javascript/);
    assert.match(xtermModule.headers.get("cache-control"), /max-age=86400/);
    assert.equal(xtermFitModule.status, 200);
    assert.match(xtermFitModule.headers.get("content-type"), /^text\/javascript/);
    assert.match(xtermFitModule.headers.get("cache-control"), /max-age=86400/);
    const consolePage = await fetch(`${baseUrl}/console.html`);
    assert.equal(consolePage.status, 200);
    assert.equal(consolePage.headers.get("cache-control"), "no-store");
    const stolenSession = await fetch(`${baseUrl}/api/v1/console/session/${encodeURIComponent(consoleToken)}`, {
      headers: { Accept: "application/json", Cookie: "nimbus_console=wrong-token" },
    });
    assert.equal(stolenSession.status, 401);
    const customerMaintenance = (await request("/api/v1/maintenance")).payload.maintenance;
    assert.equal(customerMaintenance.items.find((item) => item.id === maintenance.event.id)?.title, "Demo hypervisor maintenance");
    assert.deepEqual(
      customerMaintenance.items.find((item) => item.id === lockedMaintenance.event.id)?.lockGroups.map((group) => group.id),
      ["power_management"],
    );
    for (const notice of customerMaintenance.items) {
      await request(`/api/v1/maintenance/${encodeURIComponent(notice.deliveryId)}/read`, {
        method: "POST",
        body: {},
      });
    }
    assert.equal((await request("/api/v1/maintenance")).payload.maintenance.unread, 0);

    await request("/api/auth/logout", { method: "POST", body: {} });
    cookie = "";
    csrfToken = "";
    const maintenanceAdminLogin = await request("/api/auth/login", {
      method: "POST",
      body: { email: "admin@example.test", password: "admin password for server test" },
    });
    cookie = String(maintenanceAdminLogin.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = maintenanceAdminLogin.payload.csrfToken;
    const resolvedLock = (await request(
      `/api/admin/maintenance-events/${encodeURIComponent(lockedMaintenance.event.id)}/resolve`,
      { method: "POST", body: {} },
    )).payload.event;
    assert.equal(resolvedLock.status, "resolved");
    await request("/api/auth/logout", { method: "POST", body: {} });
    cookie = "";
    csrfToken = "";
    const resumedCustomerLogin = await request("/api/auth/login", {
      method: "POST",
      body: { email: "customer@example.test", password: "customer password for server test" },
    });
    cookie = String(resumedCustomerLogin.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = resumedCustomerLogin.payload.csrfToken;

    const supportTicket = (await request("/api/v1/support/tickets", {
      method: "POST",
      body: {
        subject: "Demo VM network problem",
        category: "network",
        priority: "high",
        resourceId: resource.id,
        message: "The assigned demo VM cannot reach its configured gateway.",
      },
    })).payload.ticket;
    assert.equal(supportTicket.customerId, "acme");
    assert.equal(supportTicket.resourceId, resource.id);
    assert.equal(supportTicket.status, "waiting_support");
    assert.match(supportTicket.reference, /^ND-/);
    const customerSupport = (await request("/api/v1/support/tickets")).payload.tickets;
    assert.equal(customerSupport.total, 1);
    assert.equal(customerSupport.items[0].id, supportTicket.id);
    assert.equal((await request(`/api/v1/support/tickets/${encodeURIComponent(supportTicket.id)}`)).payload.messages.length, 1);
    const otherResource = initialState.resources.find((entry) => entry.customerId !== "acme");
    await assert.rejects(
      () => request("/api/v1/support/tickets", {
        method: "POST",
        body: {
          subject: "Resource outside customer scope",
          category: "technical",
          priority: "normal",
          resourceId: otherResource.id,
          message: "This resource must never be accepted for the current customer.",
        },
      }),
      (error) => error.payload?.error === "invalid_ticket_resource" && error.response.status === 404,
    );

    const iso = Buffer.from("small integration-test ISO payload");
    const uploaded = await request(`/api/v1/resources/${encodeURIComponent(resource.id)}/media/upload?policyId=${encodeURIComponent(policy.id)}`, {
      method: "POST",
      body: iso,
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(iso.length),
        "X-Nimbus-Filename": encodeURIComponent("installer-test.iso"),
        "X-Nimbus-Size": String(iso.length),
      },
    });
    assert.equal(uploaded.payload.image.status, "ready");

    await request(`/api/v1/resources/${encodeURIComponent(resource.id)}/media/mount`, {
      method: "POST",
      body: { isoImageId: uploaded.payload.image.id },
    });
    const armed = await request(`/api/v1/resources/${encodeURIComponent(resource.id)}/media/boot-once`, {
      method: "POST",
      body: {},
    });
    assert.equal(armed.payload.boot.status, "armed");
    assert.equal("armedBoot" in armed.payload.boot, false);
    assert.equal("originalBoot" in armed.payload.boot, false);
    assert.equal((await request(`/api/v1/resources/${encodeURIComponent(resource.id)}/media`)).payload.boot.status, "armed");

    await request(`/api/v1/resources/${encodeURIComponent(resource.id)}/actions`, {
      method: "POST",
      body: { action: "reboot" },
    });
    const notifications = (await request("/api/v1/notifications")).payload;
    assert.equal(notifications.notifications.unread, 1);
    assert.equal(notifications.notifications.items[0].type, "action.reboot");
    assert.equal(notifications.preferences.emailEnabled, false);
    const preferences = (await request("/api/v1/notifications/preferences", {
      method: "PATCH",
      body: { actionSuccess: false, actionFailure: true, infrastructureAlerts: true, resolutionAlerts: true },
    })).payload.preferences;
    assert.equal(preferences.actionSuccess, false);
    await request(`/api/v1/notifications/${encodeURIComponent(notifications.notifications.items[0].id)}/read`, {
      method: "POST",
      body: {},
    });
    assert.equal((await request("/api/v1/notifications")).payload.notifications.unread, 0);
    assert.equal((await request(`/api/v1/resources/${encodeURIComponent(resource.id)}/media`)).payload.boot, null);
    await request(`/api/v1/resources/${encodeURIComponent(resource.id)}/media/eject`, {
      method: "POST",
      body: {},
    });

    const createdSnapshot = await request(`/api/v1/resources/${encodeURIComponent(resource.id)}/snapshots`, {
      method: "POST",
      body: { name: "release-1", description: "Before the release", includeMemory: false },
      headers: { "Idempotency-Key": "snapshot-create-release-1" },
    });
    assert.equal(createdSnapshot.payload.completed, true);
    const snapshotDetails = (await request(`/api/v1/resources/${encodeURIComponent(resource.id)}`)).payload;
    assert.deepEqual(snapshotDetails.snapshots.map((snapshot) => snapshot.name), ["release-1", "before-upgrade"]);
    assert.deepEqual(snapshotDetails.snapshotPolicy, { limit: 2, count: 2, remaining: 0 });
    await assert.rejects(
      () => request(`/api/v1/resources/${encodeURIComponent(resource.id)}/snapshots`, {
        method: "POST",
        body: { name: "over-limit" },
      }),
      (error) => error.payload?.error === "snapshot_limit_reached" && error.response.status === 409,
    );
    await assert.rejects(
      () => request(`/api/v1/resources/${encodeURIComponent(resource.id)}/snapshots/release-1/restore`, {
        method: "POST",
        body: { confirmName: "wrong-name" },
      }),
      (error) => error.payload?.error === "snapshot_confirmation_mismatch" && error.response.status === 400,
    );
    assert.equal((await request(`/api/v1/resources/${encodeURIComponent(resource.id)}/snapshots/release-1/restore`, {
      method: "POST",
      body: { confirmName: "release-1" },
    })).payload.completed, true);
    assert.equal((await request(`/api/v1/resources/${encodeURIComponent(resource.id)}/snapshots/release-1/delete`, {
      method: "POST",
      body: { confirmName: "release-1" },
    })).payload.completed, true);

    await request("/api/auth/logout", { method: "POST", body: {} });
    cookie = "";
    csrfToken = "";
    const finalAdminLogin = await request("/api/auth/login", {
      method: "POST",
      body: { email: "admin@example.test", password: "admin password for server test" },
    });
    cookie = String(finalAdminLogin.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = finalAdminLogin.payload.csrfToken;
    const adminSupport = (await request("/api/v1/support/tickets")).payload;
    assert.equal(adminSupport.tickets.total, 1);
    assert.equal(adminSupport.tickets.items[0].customerName, "Acme");
    await request(`/api/v1/support/tickets/${encodeURIComponent(supportTicket.id)}/messages`, {
      method: "POST",
      body: { message: "Private diagnostic note.", internal: true },
    });
    await request(`/api/v1/support/tickets/${encodeURIComponent(supportTicket.id)}/messages`, {
      method: "POST",
      body: { message: "We repaired the demo network route.", internal: false },
    });
    const managedSupport = (await request(`/api/v1/support/tickets/${encodeURIComponent(supportTicket.id)}`, {
      method: "PATCH",
      body: {
        status: "resolved",
        priority: "normal",
        assignedTo: adminSupport.assignees[0].id,
      },
    })).payload.ticket;
    assert.equal(managedSupport.status, "resolved");
    assert.equal(managedSupport.assignedTo, adminSupport.assignees[0].id);
    const adminThread = (await request(`/api/v1/support/tickets/${encodeURIComponent(supportTicket.id)}`)).payload;
    assert.equal(adminThread.messages.length, 3);
    assert.equal(adminThread.messages.filter((message) => message.internal).length, 1);
    const finalState = (await request("/api/admin/state")).payload;
    assert.equal(finalState.resources.find((entry) => entry.id === resource.id).alertPolicy.enabled, true);
    assert.ok(finalState.notificationEvents.items.some((entry) => entry.type === "action.reboot"));
    assert.ok(finalState.audit.items.some((entry) => entry.action === "resource.iso_boot.armed"));
    assert.ok(finalState.audit.items.some((entry) => entry.action === "resource.iso_boot.restored"));
    assert.ok(finalState.audit.items.some((entry) => entry.action === "resource.snapshot.created"));
    assert.ok(finalState.audit.items.some((entry) => entry.action === "resource.snapshot.restored"));
    assert.ok(finalState.audit.items.some((entry) => entry.action === "resource.snapshot.deleted"));
    assert.equal(finalState.maintenanceEvents.items[0].title, "Demo hypervisor maintenance");
    assert.ok(finalState.audit.items.some((entry) => entry.action === "admin.maintenance.published"));
    assert.ok(finalState.audit.items.some((entry) => entry.action === "support.ticket.created"));
    assert.ok(finalState.audit.items.some((entry) => entry.action === "admin.support.internal_note_added"));
    assert.ok(finalState.audit.items.some((entry) => entry.action === "admin.support.ticket_updated"));

    const customerUser = finalState.users.find((entry) => entry.email === "customer@example.test");
    const emailCountBeforePasswordReset = finalState.emailJobs.total;
    await request(`/api/admin/users/${encodeURIComponent(customerUser.id)}/password`, {
      method: "POST",
      body: { password: "customer replacement password" },
    });
    const passwordResetState = (await request("/api/admin/state")).payload;
    assert.equal(passwordResetState.emailJobs.total, emailCountBeforePasswordReset + 1);
    assert.ok(passwordResetState.emailJobs.items.some((job) =>
      job.category === "account_security"
      && job.to === "customer@example.test"
      && job.subject.includes("password")));
    assert.ok(passwordResetState.security.events.items.some((entry) =>
      entry.action === "admin.user.password_reset"
      && entry.userId === adminSupport.assignees[0].id));

    const loginPolicy = (await request("/api/admin/security/policy", {
      method: "PATCH",
      body: { newLoginEmail: true },
    })).payload.policy;
    assert.equal(loginPolicy.newLoginEmail, true);
    const emailCountBeforeLogin = (await request("/api/admin/state")).payload.emailJobs.total;
    await request("/api/auth/logout", { method: "POST", body: {} });
    cookie = "";
    csrfToken = "";
    const notifiedAdminLogin = await request("/api/auth/login", {
      method: "POST",
      body: { email: "admin@example.test", password: "admin password for server test" },
    });
    cookie = String(notifiedAdminLogin.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = notifiedAdminLogin.payload.csrfToken;
    const securityState = (await request("/api/admin/state")).payload;
    assert.equal(securityState.emailJobs.total, emailCountBeforeLogin + 1);
    assert.ok(securityState.emailJobs.items.some((job) =>
      job.category === "account_security"
      && job.to === "admin@example.test"
      && job.subject.includes("sign-in")));
    assert.equal(securityState.security.policy.newLoginEmail, true);
    assert.ok(securityState.security.events.items.some((entry) => entry.action === "admin.security.policy_updated"));
  } finally {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await Promise.race([once(child, "exit"), new Promise((resolve) => setTimeout(resolve, 2_000))]);
    }
    await rm(directory, { recursive: true, force: true });
  }
});
