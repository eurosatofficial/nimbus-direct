import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openStore } from "../server/store.mjs";

const APP_SECRET = "api-auth-test-secret-that-is-long-and-unique";
const ACCESS_TTL = 15 * 60 * 1000;
const REFRESH_TTL = 30 * 24 * 60 * 60 * 1000;

async function temporaryStore(callback) {
  const directory = await mkdtemp(join(tmpdir(), "nimbus-direct-api-auth-"));
  const store = await openStore(directory, { appSecret: APP_SECRET });
  try { return await callback(store); }
  finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
}

test("native device tokens are hashed, rotated, scoped, and reusable-token safe", async () => {
  await temporaryStore(async (store) => {
    const customer = store.createCustomer({ id: "acme", name: "Acme" });
    const user = await store.createUser({
      email: "mobile@example.com",
      displayName: "Mobile User",
      password: "mobile password for API tests",
      customerId: customer.id,
    });
    const first = store.createApiDeviceSession({
      userId: user.id,
      accessTtlMs: ACCESS_TTL,
      refreshTtlMs: REFRESH_TTL,
      deviceName: "Liam's iPhone",
      platform: "ios",
      appVersion: "1.0.0",
      ipAddress: "10.0.0.25",
      userAgent: "Nimbus-iOS/1.0.0",
    });

    assert.match(first.accessToken, /^nmb_at_/);
    assert.match(first.refreshToken, /^nmb_rt_/);
    assert.equal(first.session.kind, "api");
    assert.equal(first.session.current, true);
    assert.equal(first.session.deviceName, "Liam's iPhone");
    assert.equal(store.getApiAccessSession(first.accessToken).user.customerId, "acme");

    const storedDevice = store.database.prepare("SELECT * FROM api_device_sessions").get();
    const storedRefresh = store.database.prepare("SELECT * FROM api_refresh_tokens").get();
    assert.equal(JSON.stringify(storedDevice).includes(first.accessToken), false);
    assert.equal(JSON.stringify(storedRefresh).includes(first.refreshToken), false);

    const rotated = store.rotateApiRefreshToken(first.refreshToken, {
      accessTtlMs: ACCESS_TTL,
      ipAddress: "10.0.0.26",
      userAgent: "Nimbus-iOS/1.0.1",
    });
    assert.notEqual(rotated.accessToken, first.accessToken);
    assert.notEqual(rotated.refreshToken, first.refreshToken);
    assert.equal(store.getApiAccessSession(first.accessToken), null);
    assert.equal(store.getApiAccessSession(rotated.accessToken).user.id, user.id);

    assert.throws(
      () => store.rotateApiRefreshToken(first.refreshToken, { accessTtlMs: ACCESS_TTL }),
      (error) => error.code === "refresh_token_reused" && error.status === 401,
    );
    assert.equal(store.getApiAccessSession(rotated.accessToken), null);
    assert.deepEqual(store.listApiDeviceSessions(user.id), []);
    assert.equal(
      store.database.prepare("SELECT revoked_reason FROM api_device_sessions").get().revoked_reason,
      "refresh_token_reuse",
    );
  });
});

test("native sessions obey device limits, user ownership, revocation, and password resets", async () => {
  await temporaryStore(async (store) => {
    const customer = store.createCustomer({ id: "acme", name: "Acme" });
    const user = await store.createUser({
      email: "mobile@example.com",
      displayName: "Mobile User",
      password: "mobile password for API tests",
      customerId: customer.id,
    });
    const other = await store.createUser({
      email: "other@example.com",
      displayName: "Other User",
      password: "other password for API tests",
      customerId: customer.id,
    });
    const tokens = [];
    for (const deviceName of ["Phone", "Tablet", "Desktop"]) {
      tokens.push(store.createApiDeviceSession({
        userId: user.id,
        accessTtlMs: ACCESS_TTL,
        refreshTtlMs: REFRESH_TTL,
        deviceName,
        platform: "other",
        maxSessions: 2,
      }));
    }
    assert.equal(store.listApiDeviceSessions(user.id).length, 2);
    assert.equal(store.getApiAccessSession(tokens[0].accessToken), null);

    const current = tokens[2];
    assert.equal(store.revokeApiDeviceSession(other.id, current.session.id), false);
    assert.equal(store.revokeApiDeviceSession(user.id, current.session.id), true);
    assert.equal(store.getApiAccessSession(current.accessToken), null);

    const final = store.createApiDeviceSession({
      userId: user.id,
      accessTtlMs: ACCESS_TTL,
      refreshTtlMs: REFRESH_TTL,
      deviceName: "Replacement phone",
      platform: "android",
    });
    await store.updatePassword(user.id, "a completely new password for tests");
    assert.equal(store.getApiAccessSession(final.accessToken), null);
    assert.throws(
      () => store.rotateApiRefreshToken(final.refreshToken, { accessTtlMs: ACCESS_TTL }),
      (error) => error.code === "invalid_refresh_token",
    );
  });
});

