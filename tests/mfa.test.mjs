import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  createTotpEnrollment,
  encodeBase32,
  generateRecoveryCodes,
  generateTotp,
  verifyTotp,
} from "../server/mfa.mjs";
import { openStore } from "../server/store.mjs";

const APP_SECRET = "mfa-test-secret-that-is-long-and-unique";

test("TOTP generation follows RFC 6238 and accepts only the configured time window", () => {
  const secret = encodeBase32(Buffer.from("12345678901234567890"));
  assert.equal(generateTotp(secret, { timestamp: 59_000, digits: 8 }), "94287082");
  assert.equal(generateTotp(secret, { timestamp: 1_111_111_109_000, digits: 8 }), "07081804");
  const code = generateTotp(secret, { timestamp: 1_700_000_000_000 });
  assert.equal(verifyTotp(secret, code, { timestamp: 1_700_000_000_000 }), true);
  assert.equal(verifyTotp(secret, code, { timestamp: 1_700_000_090_000 }), false);
  assert.equal(verifyTotp(secret, "000000", { timestamp: 1_700_000_000_000 }), false);
});

test("enrollments use standard otpauth URIs and recovery codes are unique", () => {
  const enrollment = createTotpEnrollment("Operator@Example.Test");
  assert.match(enrollment.secret, /^[A-Z2-7]{32}$/);
  assert.match(enrollment.uri, /^otpauth:\/\/totp\//);
  assert.match(enrollment.uri, /issuer=Nimbus\+Direct/);
  assert.match(enrollment.uri, /secret=[A-Z2-7]{32}/);
  const recoveryCodes = generateRecoveryCodes();
  assert.equal(recoveryCodes.length, 10);
  assert.equal(new Set(recoveryCodes).size, 10);
  assert.ok(recoveryCodes.every((code) => /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(code)));
});

test("MFA secrets, recovery codes, challenges, and sessions remain protected and user-scoped", async () => {
  const directory = await mkdtemp(join(tmpdir(), "nimbus-direct-mfa-store-"));
  const store = await openStore(directory, { appSecret: APP_SECRET });
  try {
    const first = await store.createUser({
      email: "first@example.test",
      displayName: "First",
      password: "first account password",
      role: "admin",
    });
    const second = await store.createUser({
      email: "second@example.test",
      displayName: "Second",
      password: "second account password",
      role: "admin",
    });
    const enrollment = createTotpEnrollment(first.email);
    store.saveMfaSetup(first.id, enrollment.secret);
    const raw = store.database.prepare("SELECT * FROM user_mfa WHERE user_id=?").get(first.id);
    assert.equal(raw.totp_secret_encrypted.includes(enrollment.secret), false);
    assert.equal(store.getMfaSecret(first.id, { pending: true }), enrollment.secret);

    const recoveryCodes = generateRecoveryCodes(3);
    assert.equal(store.enableMfa(first.id, recoveryCodes).recoveryCodesRemaining, 3);
    const enabledRaw = store.database.prepare("SELECT * FROM user_mfa WHERE user_id=?").get(first.id);
    assert.equal(enabledRaw.recovery_code_hashes.includes(recoveryCodes[0]), false);
    assert.equal(store.consumeRecoveryCode(first.id, recoveryCodes[0]), true);
    assert.equal(store.consumeRecoveryCode(first.id, recoveryCodes[0]), false);
    assert.equal(store.getMfaStatus(first.id).recoveryCodesRemaining, 2);
    assert.equal(store.listUsers().find((user) => user.id === first.id).mfaEnabled, true);

    const challenge = store.createMfaChallenge({ userId: first.id });
    assert.equal(store.getMfaChallenge(challenge.token).user_id, first.id);
    store.failMfaChallenge(challenge.token);
    assert.equal(store.getMfaChallenge(challenge.token).attempts, 1);
    assert.equal(store.consumeMfaChallenge(challenge.token).user_id, first.id);
    assert.equal(store.consumeMfaChallenge(challenge.token), null);

    const firstSession = store.createSession({
      userId: first.id,
      ttlMs: 60_000,
      ipAddress: "192.0.2.10",
      userAgent: "Test Browser",
    });
    const secondSession = store.createSession({ userId: second.id, ttlMs: 60_000, ipAddress: "192.0.2.20" });
    const firstSessionState = store.getSession(firstSession.token);
    const listed = store.listSessions(first.id, { currentIdHash: firstSessionState.idHash });
    assert.equal(listed.length, 1);
    assert.equal(listed[0].current, true);
    assert.equal(listed[0].ipAddress, "192.0.2.10");
    assert.equal(listed[0].userAgent, "Test Browser");
    assert.equal(store.deleteUserSession(first.id, store.getSession(secondSession.token).idHash), false);
    assert.equal(store.getSession(secondSession.token).user.id, second.id);

    store.disableMfa(first.id);
    assert.equal(store.getMfaStatus(first.id).enabled, false);
    assert.equal(store.getMfaSecret(first.id), null);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
