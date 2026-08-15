import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { verifyPassword } from "../server/security.mjs";
import { openStore } from "../server/store.mjs";

const APP_SECRET = "account-lifecycle-secret-that-is-long-enough";

async function temporaryStore(callback) {
  const directory = await mkdtemp(join(tmpdir(), "nimbus-direct-account-"));
  const store = await openStore(directory, { appSecret: APP_SECRET });
  try { return await callback(store); }
  finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
}

test("invitations are single-use, hashed at rest, and activate a pending account", async () => {
  await temporaryStore(async (store) => {
    const customer = store.createCustomer({ id: "acme", name: "Acme" });
    const admin = await store.createUser({
      email: "admin@example.test",
      displayName: "Admin",
      password: "administrator password test",
      role: "admin",
    });
    const invited = await store.createInvitedUser({
      email: "invited@example.test",
      displayName: "Invited User",
      customerId: customer.id,
      preferredLanguage: "de",
    });
    assert.equal(invited.passwordSet, false);
    assert.equal(invited.preferredLanguage, "de");
    const updatedProfile = store.updateProfile(invited.id, {
      preferredLanguage: "en",
      preferredTimeZone: "Europe/Berlin",
    });
    assert.equal(updatedProfile.preferredLanguage, "en");
    assert.equal(updatedProfile.preferredTimeZone, "Europe/Berlin");
    assert.throws(
      () => store.updateProfile(invited.id, { preferredTimeZone: "Not/A-Timezone" }),
      (error) => error.code === "invalid_preferred_timezone",
    );
    assert.equal(store.findUserForLogin(invited.email).password_set, 0);

    const first = store.createAccountToken({
      userId: invited.id,
      purpose: "invitation",
      createdBy: admin.id,
      requestedIp: "192.0.2.10",
    });
    assert.ok(store.getAccountToken(first.token, "invitation"));
    const storedFirst = store.database.prepare("SELECT * FROM account_tokens WHERE user_id=?").get(invited.id);
    assert.notEqual(storedFirst.id_hash, first.token);
    assert.equal(JSON.stringify(storedFirst).includes(first.token), false);

    const second = store.createAccountToken({
      userId: invited.id,
      purpose: "invitation",
      createdBy: admin.id,
    });
    assert.equal(store.getAccountToken(first.token, "invitation"), null);
    assert.ok(store.getAccountToken(second.token, "invitation"));
    assert.equal(store.getAccountToken(second.token, "password_reset"), null);
    assert.ok(store.listUsers().find((user) => user.id === invited.id).invitationExpiresAt);

    const session = store.createSession({ userId: invited.id, ttlMs: 60_000 });
    const completed = await store.consumeAccountToken(second.token, "invitation", "private invited password");
    assert.equal(completed.passwordSet, true);
    assert.equal(store.getSession(session.token), null);
    assert.equal(store.getAccountToken(second.token, "invitation"), null);
    assert.equal(await store.consumeAccountToken(second.token, "invitation", "another private password"), null);
    assert.equal(await verifyPassword("private invited password", store.findUserForLogin(invited.email).password_hash), true);
  });
});

test("password recovery revokes sessions, preserves 2FA, and rejects expired or revoked links", async () => {
  await temporaryStore(async (store) => {
    const user = await store.createUser({
      email: "secured@example.test",
      displayName: "Secured User",
      password: "original secured password",
      role: "admin",
    });
    store.saveMfaSetup(user.id, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
    store.enableMfa(user.id, ["ABCD234567"]);
    const session = store.createSession({ userId: user.id, ttlMs: 60_000 });
    const reset = store.createAccountToken({ userId: user.id, purpose: "password_reset" });

    const completed = await store.consumeAccountToken(reset.token, "password_reset", "replacement secured password");
    assert.equal(completed.passwordSet, true);
    assert.equal(store.getSession(session.token), null);
    assert.equal(store.getMfaStatus(user.id).enabled, true);
    assert.equal(await verifyPassword("replacement secured password", store.findUserForLogin(user.email).password_hash), true);

    const expired = store.createAccountToken({ userId: user.id, purpose: "password_reset" });
    store.database.prepare("UPDATE account_tokens SET expires_at=1 WHERE id_hash=(SELECT id_hash FROM account_tokens WHERE user_id=? AND used_at IS NULL)").run(user.id);
    assert.equal(store.getAccountToken(expired.token, "password_reset"), null);

    const revoked = store.createAccountToken({ userId: user.id, purpose: "password_reset" });
    assert.equal(store.revokeAccountTokens(user.id, "password_reset"), 1);
    assert.equal(store.getAccountToken(revoked.token, "password_reset"), null);
  });
});
