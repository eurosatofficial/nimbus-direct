const READ_METHODS = new Set(["GET", "HEAD"]);
const DEMO_AUTH_WRITES = new Set([
  "POST /api/auth/login",
  "POST /api/auth/mfa",
  "POST /api/auth/passkeys/options",
  "POST /api/auth/passkeys/verify",
  "POST /api/auth/logout",
  "POST /api/v1/auth/token",
  "POST /api/v1/auth/mfa",
  "POST /api/v1/auth/refresh",
  "POST /api/v1/auth/logout",
  "POST /api/v1/resources/refresh",
]);

export function isDemoReadOnlyRequestAllowed(method, pathname) {
  const normalizedMethod = String(method || "GET").toUpperCase();
  if (READ_METHODS.has(normalizedMethod)) return true;
  return DEMO_AUTH_WRITES.has(`${normalizedMethod} ${pathname}`);
}

export function assertDemoReadOnlyStore(config, store) {
  if (!config.demoReadOnly) return;
  const clusters = store.listClusters();
  const unsafeCluster = clusters.find((cluster) =>
    cluster.id !== "demo-eu" || cluster.apiUrl !== "https://demo.invalid:8006");
  if (unsafeCluster) {
    throw new Error(
      `DEMO_READ_ONLY refuses to start with non-demo Proxmox configuration (${unsafeCluster.id}). Use a fresh Docker volume for the public demo.`,
    );
  }
  if (store.getEmailSettings().configured) {
    throw new Error(
      "DEMO_READ_ONLY refuses to start with stored SMTP configuration. Use a fresh Docker volume for the public demo.",
    );
  }
  const securityPolicy = store.getSecurityPolicy();
  if (securityPolicy.requireAdminMfa || securityPolicy.requireCustomerMfa
    || store.listUsers().some((user) => user.mfaEnabled || user.passkeyCount > 0)) {
    throw new Error(
      "DEMO_READ_ONLY refuses to start with required or enrolled two-factor/passkey authentication. Use fresh shared demo accounts.",
    );
  }
}
