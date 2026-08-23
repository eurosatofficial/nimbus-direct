import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
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
  assert.match(headers["content-security-policy"], /form-action 'none'/);
  assert.match(headers["permissions-policy"], /camera=\(\)/);
  assert.match(headers["strict-transport-security"], /includeSubDomains/);
  assert.equal(normalizeEmail("  Admin@Example.COM "), "admin@example.com");
});

test("pre-authentication forms cannot fall back to credential-bearing GET requests", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const expectedForms = [
    ["loginForm", "/api/auth/login"],
    ["mfaForm", "/api/auth/mfa"],
    ["forgotPasswordForm", "/api/auth/password/forgot"],
    ["accountCompletionForm", "/api/auth/account/complete"],
  ];
  for (const [id, action] of expectedForms) {
    const tag = html.match(new RegExp(`<form[^>]*id=["']${id}["'][^>]*>`))?.[0];
    assert.ok(tag, `missing ${id}`);
    assert.match(tag, /method=["']post["']/i);
    assert.match(tag, new RegExp(`action=["']${action.replaceAll("/", "\\/")}["']`, "i"));
  }
  assert.match(html, /<noscript>[\s\S]*JavaScript is required for secure sign-in/);
});

test("the Security control-center renderer returns markup to the shared tab shell", async () => {
  const source = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const start = source.indexOf("function renderAdminSecurity()");
  const end = source.indexOf("function renderAdminUsers()", start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const renderer = source.slice(start, end);
  assert.match(renderer, /return `<section class="security-center-hero">/);
  assert.doesNotMatch(renderer, /els\.viewRoot\.innerHTML\s*=/);
  assert.match(source, /security:\s*renderAdminSecurity/);
});

test("the public demo UI is labeled and disables mutation controls without hiding browsing", async () => {
  const [source, html, css] = await Promise.all([
    readFile(new URL("../public/app.js", import.meta.url), "utf8"),
    readFile(new URL("../public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../public/styles.css", import.meta.url), "utf8"),
  ]);
  assert.match(source, /function setDemoReadOnly\(enabled\)/);
  assert.match(source, /function applyDemoReadOnlyUi\(root = els\.viewRoot\)/);
  assert.match(source, /new MutationObserver\(\(\) => applyDemoReadOnlyUi\(\)\)/);
  assert.match(source, /\[data-admin-tab\]/);
  assert.match(source, /\[data-details\]/);
  assert.match(source, /demo_read_only: "This public demo is read-only/);
  assert.match(html, /id="demoReadOnlyBanner"/);
  assert.match(html, /id="demoLoginNotice"/);
  assert.match(css, /\.demo-read-only-banner/);
  assert.match(css, /\.demo-form-disabled/);
});
