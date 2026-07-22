import test from "node:test";
import assert from "node:assert/strict";
import {
  decryptSecret,
  encryptSecret,
  hashPassword,
  hashToken,
  normalizeEmail,
  parseCookies,
  safeEqual,
  securityHeaders,
  sessionCookie,
  sessionCookieName,
  verifyPassword,
} from "../server/security.mjs";

test("Proxmox token secrets are encrypted with authenticated encryption", () => {
  const key = "a-credential-encryption-secret-longer-than-32-characters";
  const encrypted = encryptSecret("proxmox-token-secret", key);
  assert.match(encrypted, /^v1\./);
  assert.equal(encrypted.includes("proxmox-token-secret"), false);
  assert.equal(decryptSecret(encrypted, key), "proxmox-token-secret");
  assert.throws(() => decryptSecret(encrypted, `${key}-wrong`));
});

test("password hashes verify without retaining the password", async () => {
  const password = "correct horse battery staple";
  const encoded = await hashPassword(password);

  assert.match(encoded, /^scrypt\$/);
  assert.equal(encoded.includes(password), false);
  assert.equal(await verifyPassword(password, encoded), true);
  assert.equal(await verifyPassword("wrong password", encoded), false);
  await assert.rejects(() => hashPassword("too-short"), /between 12 and 256/);
});

test("session tokens are secret-bound and constant-time comparison is defensive", () => {
  assert.notEqual(hashToken("token", "secret-a"), hashToken("token", "secret-b"));
  assert.equal(hashToken("token", "secret-a"), hashToken("token", "secret-a"));
  assert.equal(safeEqual("same", "same"), true);
  assert.equal(safeEqual("same", "different"), false);
  assert.equal(safeEqual(null, "same"), false);
});

test("secure cookies use the __Host prefix and hardened attributes", () => {
  assert.equal(sessionCookieName(true), "__Host-nimbus_session");
  assert.equal(sessionCookieName(false), "nimbus_session");

  const cookie = sessionCookie("a token/with spaces", { secure: true, maxAge: 60_500 });
  assert.match(cookie, /^__Host-nimbus_session=/);
  assert.match(cookie, /Path=\//);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Max-Age=60/);
  assert.match(cookie, /Secure/);
  assert.doesNotMatch(cookie, /Domain=/);

  assert.deepEqual(parseCookies("one=first; encoded=hello%20world"), { one: "first", encoded: "hello world" });
});

test("security headers deny framing and unnecessary browser capabilities", () => {
  const headers = securityHeaders();
  assert.equal(headers["x-frame-options"], "DENY");
  assert.match(headers["content-security-policy"], /frame-ancestors 'none'/);
  assert.match(headers["permissions-policy"], /camera=\(\)/);
  assert.match(headers["strict-transport-security"], /includeSubDomains/);
  assert.equal(normalizeEmail("  Admin@Example.COM "), "admin@example.com");
});
