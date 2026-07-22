import test from "node:test";
import assert from "node:assert/strict";
import { readConfig } from "../server/config.mjs";

const KEYS = [
  "NODE_ENV", "APP_SECRET", "BOOTSTRAP_CUSTOMER_ID", "BOOTSTRAP_CUSTOMER_NAME",
  "BOOTSTRAP_SUPPORT_EMAIL", "BOOTSTRAP_PLAN_NAME", "PROXMOX_REQUEST_TIMEOUT_MS", "RESOURCE_SYNC_SECONDS",
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
  }, () => {
    const config = readConfig();
    assert.equal(config.bootstrap.customerId, "acme");
    assert.equal(config.bootstrap.customerName, "Acme Studio");
    assert.equal(config.bootstrap.supportEmail, "support@example.com");
    assert.equal(config.proxmoxTimeoutMs, 15000);
    assert.equal(config.syncIntervalMs, 90000);
    assert.equal("globalProxmoxTenantId" in config, false);
  });
});

test("invalid timeouts and sync intervals fail at startup", () => {
  withEnvironment({
    NODE_ENV: "production",
    APP_SECRET: "a-production-secret-with-at-least-32-characters",
    PROXMOX_REQUEST_TIMEOUT_MS: "0",
  }, () => assert.throws(() => readConfig(), /Invalid positive integer/));
});
