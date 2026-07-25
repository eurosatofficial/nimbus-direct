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
          "view_status", "reboot", "iso_view", "iso_upload", "iso_mount", "iso_boot",
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
    await request("/api/auth/logout", { method: "POST", body: {} });
    cookie = "";
    csrfToken = "";
    const customerLogin = await request("/api/auth/login", {
      method: "POST",
      body: { email: "customer@example.test", password: "customer password for server test" },
    });
    cookie = String(customerLogin.response.headers.get("set-cookie") || "").split(";")[0];
    csrfToken = customerLogin.payload.csrfToken;

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
    const finalState = (await request("/api/admin/state")).payload;
    assert.equal(finalState.resources.find((entry) => entry.id === resource.id).alertPolicy.enabled, true);
    assert.ok(finalState.notificationEvents.items.some((entry) => entry.type === "action.reboot"));
    assert.ok(finalState.audit.items.some((entry) => entry.action === "resource.iso_boot.armed"));
    assert.ok(finalState.audit.items.some((entry) => entry.action === "resource.iso_boot.restored"));
    assert.ok(finalState.audit.items.some((entry) => entry.action === "resource.snapshot.created"));
    assert.ok(finalState.audit.items.some((entry) => entry.action === "resource.snapshot.restored"));
    assert.ok(finalState.audit.items.some((entry) => entry.action === "resource.snapshot.deleted"));
  } finally {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await Promise.race([once(child, "exit"), new Promise((resolve) => setTimeout(resolve, 2_000))]);
    }
    await rm(directory, { recursive: true, force: true });
  }
});
