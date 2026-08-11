import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createPasskeyService } from "../server/passkeys.mjs";
import { openStore } from "../server/store.mjs";

const APP_SECRET = "passkey-test-secret-that-is-long-and-unique";

test("passkey options require user verification and discoverable credentials", async () => {
  const passkeys = createPasskeyService({
    enabled: true,
    rpId: "nimbus.example.test",
    origin: "https://nimbus.example.test",
    rpName: "Nimbus Test",
  });
  const user = {
    id: Buffer.from("passkey-user-id").toString("base64url"),
    email: "operator@example.test",
    display_name: "Operator",
  };
  const registration = await passkeys.registrationOptions(user);
  assert.equal(registration.rp.id, "nimbus.example.test");
  assert.equal(registration.authenticatorSelection.residentKey, "required");
  assert.equal(registration.authenticatorSelection.userVerification, "required");
  assert.deepEqual(registration.pubKeyCredParams.map((entry) => entry.alg), [-7, -257]);

  const authentication = await passkeys.authenticationOptions();
  assert.equal(authentication.rpId, "nimbus.example.test");
  assert.equal(authentication.userVerification, "required");
  assert.deepEqual(authentication.allowCredentials, []);
});

test("passkey credentials and one-time challenges remain user-scoped", async () => {
  const directory = await mkdtemp(join(tmpdir(), "nimbus-direct-passkeys-"));
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
    const stored = store.createPasskey(first.id, {
      id: "credential-one",
      webauthnUserID: first.id,
      name: "MacBook Touch ID",
      publicKey: Buffer.from([1, 2, 3, 4]),
      counter: 7,
      deviceType: "multiDevice",
      backedUp: true,
      transports: ["internal", "hybrid"],
    });
    assert.equal(stored.name, "MacBook Touch ID");
    assert.equal(stored.backedUp, true);
    assert.equal(store.listUsers().find((user) => user.id === first.id).passkeyCount, 1);
    assert.equal(store.listUsers().find((user) => user.id === second.id).passkeyCount, 0);

    const privateCredential = store.getPasskeyCredential("credential-one");
    assert.equal(privateCredential.userId, first.id);
    assert.deepEqual(privateCredential.publicKey, Buffer.from([1, 2, 3, 4]));
    assert.equal("publicKey" in stored, false);

    assert.equal(store.renamePasskey(first.id, stored.id, "Security key").name, "Security key");
    assert.throws(
      () => store.renamePasskey(second.id, stored.id, "Stolen name"),
      (error) => error.code === "passkey_not_found",
    );
    assert.equal(store.updatePasskeyCounter(stored.id, 8), true);
    assert.equal(store.getPasskeyCredential(stored.id).counter, 8);
    assert.ok(store.getPasskeyCredential(stored.id).lastUsedAt);

    const challenge = store.createWebAuthnChallenge({
      userId: first.id,
      purpose: "registration",
      challenge: "challenge-value",
      ttlMs: 60_000,
    });
    assert.equal(
      store.consumeWebAuthnChallenge(challenge.token, "registration", { userId: second.id }),
      null,
    );
    assert.equal(
      store.consumeWebAuthnChallenge(challenge.token, "registration", { userId: first.id }).challenge,
      "challenge-value",
    );
    assert.equal(
      store.consumeWebAuthnChallenge(challenge.token, "registration", { userId: first.id }),
      null,
    );

    assert.equal(store.deletePasskey(second.id, stored.id), false);
    assert.equal(store.deletePasskey(first.id, stored.id), true);
    assert.deepEqual(store.listPasskeys(first.id), []);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("disabled passkey service fails closed", async () => {
  const passkeys = createPasskeyService({ enabled: false });
  await assert.rejects(
    () => passkeys.authenticationOptions(),
    (error) => error.code === "passkeys_not_configured" && error.status === 409,
  );
});
