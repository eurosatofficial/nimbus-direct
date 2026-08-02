import test from "node:test";
import assert from "node:assert/strict";
import { readConfig } from "../server/config.mjs";

const KEYS = [
  "NODE_ENV", "APP_SECRET", "BOOTSTRAP_CUSTOMER_ID", "BOOTSTRAP_CUSTOMER_NAME",
  "BOOTSTRAP_SUPPORT_EMAIL", "BOOTSTRAP_PLAN_NAME", "PROXMOX_REQUEST_TIMEOUT_MS", "RESOURCE_SYNC_SECONDS",
  "ISO_MAX_UPLOAD_MB", "ISO_UPLOAD_TIMEOUT_MINUTES", "EMAIL_SMTP_TIMEOUT_SECONDS", "EMAIL_QUEUE_INTERVAL_SECONDS",
  "API_ACCESS_TOKEN_MINUTES", "API_REFRESH_TOKEN_DAYS", "API_MAX_DEVICE_SESSIONS",
  "ALLOW_DEMO_DATA", "DEMO_READ_ONLY",
];

function withEnvironment(values, callback) {
  const previous = Object.fromEntries(KEYS.map((key) => [key, process.env[key]]));
  for (const key of KEYS) delete process.env[key];
  Object.assign(process.env, values);
  try { return callback(); }
  finally {
    for (const key of KEYS) {
      if (previous[key] === undefined) delete process.env[key];
      else process.env[key] = previous[key];
    }
  }
}

test("configuration exposes direct-assignment bootstrap and sync settings", () => {
  withEnvironment({
    NODE_ENV: "production",
    APP_SECRET: "a-production-secret-with-at-least-32-characters",
    BOOTSTRAP_CUSTOMER_ID: "acme",
    BOOTSTRAP_CUSTOMER_NAME: "Acme Studio",
    BOOTSTRAP_SUPPORT_EMAIL: "support@example.com",
    BOOTSTRAP_PLAN_NAME: "Gold",
    PROXMOX_REQUEST_TIMEOUT_MS: "15000",
    RESOURCE_SYNC_SECONDS: "90",
    ISO_MAX_UPLOAD_MB: "4096",
    ISO_UPLOAD_TIMEOUT_MINUTES: "45",
    EMAIL_SMTP_TIMEOUT_SECONDS: "12",
    EMAIL_QUEUE_INTERVAL_SECONDS: "7",
    API_ACCESS_TOKEN_MINUTES: "20",
    API_REFRESH_TOKEN_DAYS: "45",
    API_MAX_DEVICE_SESSIONS: "7",
    ALLOW_DEMO_DATA: "true",
    DEMO_READ_ONLY: "true",
  }, () => {
    const config = readConfig();
    assert.equal(config.bootstrap.customerId, "acme");
    assert.equal(config.bootstrap.customerName, "Acme Studio");
    assert.equal(config.bootstrap.supportEmail, "support@example.com");
    assert.equal(config.proxmoxTimeoutMs, 15000);
    assert.equal(config.syncIntervalMs, 90000);
    assert.equal(config.isoMaxUploadBytes, 4096 * 1024 * 1024);
    assert.equal(config.isoUploadTimeoutMs, 45 * 60 * 1000);
    assert.equal(config.emailSmtpTimeoutMs, 12_000);
    assert.equal(config.emailQueueIntervalMs, 7_000);
    assert.equal(config.apiAccessTokenTtlMs, 20 * 60 * 1000);
    assert.equal(config.apiRefreshTokenTtlMs, 45 * 24 * 60 * 60 * 1000);
    assert.equal(config.apiMaxDeviceSessions, 7);
    assert.equal(config.allowDemoData, true);
    assert.equal(config.demoReadOnly, true);
    assert.equal("globalProxmoxTenantId" in config, false);
  });
});

test("public read-only mode cannot be enabled without simulated demo data", () => {
  withEnvironment({
    NODE_ENV: "production",
    APP_SECRET: "a-production-secret-with-at-least-32-characters",
    ALLOW_DEMO_DATA: "false",
    DEMO_READ_ONLY: "true",
  }, () => assert.throws(() => readConfig(), /DEMO_READ_ONLY requires ALLOW_DEMO_DATA=true/));
});

test("invalid timeouts and sync intervals fail at startup", () => {
  withEnvironment({
    NODE_ENV: "production",
    APP_SECRET: "a-production-secret-with-at-least-32-characters",
    PROXMOX_REQUEST_TIMEOUT_MS: "0",
  }, () => assert.throws(() => readConfig(), /Invalid positive integer/));
});

test("native refresh lifetime must exceed the access-token lifetime", () => {
  withEnvironment({
    NODE_ENV: "production",
    APP_SECRET: "a-production-secret-with-at-least-32-characters",
    API_ACCESS_TOKEN_MINUTES: String(60 * 24 * 31),
    API_REFRESH_TOKEN_DAYS: "30",
  }, () => assert.throws(() => readConfig(), /API_REFRESH_TOKEN_DAYS must be longer/));
});
