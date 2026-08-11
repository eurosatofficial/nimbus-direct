import test from "node:test";
import assert from "node:assert/strict";
import { assertDemoReadOnlyStore, isDemoReadOnlyRequestAllowed } from "../server/demo-mode.mjs";

test("public demo allows reads, session lifecycle, and a safe inventory refresh", () => {
  assert.equal(isDemoReadOnlyRequestAllowed("GET", "/api/v1/dashboard"), true);
  assert.equal(isDemoReadOnlyRequestAllowed("HEAD", "/"), true);
  assert.equal(isDemoReadOnlyRequestAllowed("POST", "/api/auth/login"), true);
  assert.equal(isDemoReadOnlyRequestAllowed("POST", "/api/auth/mfa"), true);
  assert.equal(isDemoReadOnlyRequestAllowed("POST", "/api/auth/passkeys/options"), true);
  assert.equal(isDemoReadOnlyRequestAllowed("POST", "/api/auth/passkeys/verify"), true);
  assert.equal(isDemoReadOnlyRequestAllowed("POST", "/api/auth/logout"), true);
  assert.equal(isDemoReadOnlyRequestAllowed("POST", "/api/v1/auth/token"), true);
  assert.equal(isDemoReadOnlyRequestAllowed("POST", "/api/v1/auth/mfa"), true);
  assert.equal(isDemoReadOnlyRequestAllowed("POST", "/api/v1/auth/refresh"), true);
  assert.equal(isDemoReadOnlyRequestAllowed("POST", "/api/v1/auth/logout"), true);
  assert.equal(isDemoReadOnlyRequestAllowed("POST", "/api/v1/resources/refresh"), true);
  assert.equal(isDemoReadOnlyRequestAllowed("POST", "/api/v1/resources/demo/actions"), false);
  assert.equal(isDemoReadOnlyRequestAllowed("PATCH", "/api/v1/profile"), false);
  assert.equal(isDemoReadOnlyRequestAllowed("PUT", "/api/admin/email/settings"), false);
  assert.equal(isDemoReadOnlyRequestAllowed("DELETE", "/api/admin/customers/demo"), false);
  assert.equal(isDemoReadOnlyRequestAllowed("POST", "/api/auth/password/forgot"), false);
});

test("public demo refuses real cluster and SMTP configuration", () => {
  const safeStore = {
    listClusters: () => [{ id: "demo-eu", apiUrl: "https://demo.invalid:8006" }],
    getEmailSettings: () => ({ configured: false }),
    getSecurityPolicy: () => ({ requireAdminMfa: false, requireCustomerMfa: false }),
    listUsers: () => [{ mfaEnabled: false, passkeyCount: 0 }],
  };
  assert.doesNotThrow(() => assertDemoReadOnlyStore({ demoReadOnly: true }, safeStore));
  assert.doesNotThrow(() => assertDemoReadOnlyStore({ demoReadOnly: false }, {
    listClusters: () => [{ id: "production", apiUrl: "https://pve.example.com:8006" }],
    getEmailSettings: () => ({ configured: true }),
  }));
  assert.throws(() => assertDemoReadOnlyStore({ demoReadOnly: true }, {
    ...safeStore,
    listClusters: () => [{ id: "production", apiUrl: "https://pve.example.com:8006" }],
  }), /non-demo Proxmox configuration/);
  assert.throws(() => assertDemoReadOnlyStore({ demoReadOnly: true }, {
    ...safeStore,
    getEmailSettings: () => ({ configured: true }),
  }), /stored SMTP configuration/);
  assert.throws(() => assertDemoReadOnlyStore({ demoReadOnly: true }, {
    ...safeStore,
    getSecurityPolicy: () => ({ requireAdminMfa: true, requireCustomerMfa: false }),
  }), /two-factor\/passkey authentication/);
  assert.throws(() => assertDemoReadOnlyStore({ demoReadOnly: true }, {
    ...safeStore,
    listUsers: () => [{ mfaEnabled: false, passkeyCount: 1 }],
  }), /two-factor\/passkey authentication/);
});
