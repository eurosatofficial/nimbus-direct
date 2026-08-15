import test from "node:test";
import assert from "node:assert/strict";
import { readConfig } from "../server/config.mjs";

const KEYS = [
  "NODE_ENV", "APP_SECRET", "BOOTSTRAP_CUSTOMER_ID", "BOOTSTRAP_CUSTOMER_NAME",
  "BOOTSTRAP_SUPPORT_EMAIL", "BOOTSTRAP_PLAN_NAME", "PROXMOX_REQUEST_TIMEOUT_MS", "RESOURCE_SYNC_SECONDS",
  "ISO_MAX_UPLOAD_MB", "ISO_UPLOAD_TIMEOUT_MINUTES", "EMAIL_SMTP_TIMEOUT_SECONDS", "EMAIL_QUEUE_INTERVAL_SECONDS",
  "API_ACCESS_TOKEN_MINUTES", "API_REFRESH_TOKEN_DAYS", "API_MAX_DEVICE_SESSIONS",
  "WEBAUTHN_RP_ID", "WEBAUTHN_ORIGIN", "WEBAUTHN_RP_NAME",
  "PRIVACY_POLICY_URL",
  "PUSH_MODE", "PUSH_RELAY_URL", "PUSH_RELAY_TIMEOUT_SECONDS",
  "APNS_KEY_ID", "APNS_TEAM_ID", "APNS_TOPIC", "APNS_PRIVATE_KEY_BASE64", "APNS_TIMEOUT_SECONDS",
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
    WEBAUTHN_RP_ID: "nimbus.example.com",
    WEBAUTHN_ORIGIN: "https://nimbus.example.com",
    WEBAUTHN_RP_NAME: "Example Nimbus",
    PRIVACY_POLICY_URL: "https://legal.example.com/nimbus/privacy/",
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
    assert.deepEqual(config.webauthn, {
      enabled: true,
      rpId: "nimbus.example.com",
      origin: "https://nimbus.example.com",
      rpName: "Example Nimbus",
    });
    assert.equal(config.operatorPrivacyPolicyUrl, "https://legal.example.com/nimbus/privacy/");
    assert.equal(config.push.mode, "disabled");
    assert.equal(config.allowDemoData, true);
    assert.equal(config.demoReadOnly, true);
    assert.equal("globalProxmoxTenantId" in config, false);
  });
});

test("privacy policy URL requires a safe HTTPS destination", () => {
  const base = {
    NODE_ENV: "production",
    APP_SECRET: "a-production-secret-with-at-least-32-characters",
  };
  withEnvironment({ ...base, PRIVACY_POLICY_URL: "not a URL" }, () => {
    assert.throws(() => readConfig(), /valid absolute URL/);
  });
  withEnvironment({ ...base, PRIVACY_POLICY_URL: "http://privacy.example.com/" }, () => {
    assert.throws(() => readConfig(), /must use HTTPS/);
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

test("passkey configuration requires a matching HTTPS relying-party origin", () => {
  const base = {
    NODE_ENV: "production",
    APP_SECRET: "a-production-secret-with-at-least-32-characters",
  };
  withEnvironment({ ...base, WEBAUTHN_RP_ID: "nimbus.example.com" }, () => {
    assert.throws(() => readConfig(), /require both WEBAUTHN_RP_ID and WEBAUTHN_ORIGIN/);
  });
  withEnvironment({
    ...base,
    WEBAUTHN_RP_ID: "nimbus.example.com",
    WEBAUTHN_ORIGIN: "http://nimbus.example.com",
  }, () => assert.throws(() => readConfig(), /must use HTTPS/));
  withEnvironment({
    ...base,
    WEBAUTHN_RP_ID: "other.example.com",
    WEBAUTHN_ORIGIN: "https://nimbus.example.com",
  }, () => assert.throws(() => readConfig(), /must match WEBAUTHN_ORIGIN/));
});

test("relay push mode never accepts operator APNs credentials", () => {
  const base = {
    NODE_ENV: "production",
    APP_SECRET: "a-production-secret-with-at-least-32-characters",
    PUSH_MODE: "relay",
    PUSH_RELAY_URL: "https://push.nimbus.example/",
  };
  withEnvironment(base, () => {
    const config = readConfig();
    assert.equal(config.push.mode, "relay");
    assert.equal(config.push.enabled, true);
    assert.equal(config.push.relay.url, "https://push.nimbus.example");
    assert.equal(config.push.direct.privateKey, "");
  });
  withEnvironment({ ...base, APNS_KEY_ID: "secret-key-id" }, () => {
    assert.throws(() => readConfig(), /must not contain APNs credentials/);
  });
  withEnvironment({ ...base, PUSH_RELAY_URL: "http://push.nimbus.example" }, () => {
    assert.throws(() => readConfig(), /must use HTTPS/);
  });
});

test("direct push mode remains available for custom app forks", () => {
  const privateKey = Buffer.from("test-only BEGIN PRIVATE KEY marker").toString("base64");
  withEnvironment({
    NODE_ENV: "production",
    APP_SECRET: "a-production-secret-with-at-least-32-characters",
    PUSH_MODE: "direct",
    APNS_KEY_ID: "KEY123",
    APNS_TEAM_ID: "TEAM123",
    APNS_TOPIC: "com.example.custom-nimbus",
    APNS_PRIVATE_KEY_BASE64: privateKey,
  }, () => {
    const config = readConfig();
    assert.equal(config.push.mode, "direct");
    assert.equal(config.push.direct.topic, "com.example.custom-nimbus");
    assert.match(config.push.direct.privateKey, /BEGIN PRIVATE KEY/);
  });
});
