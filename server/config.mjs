import { readFile } from "node:fs/promises";

export async function loadEnv(url) {
  try {
    const envFile = await readFile(url, "utf8");
    for (const line of envFile.split(/\r?\n/)) {
      if (!line.trim() || line.trimStart().startsWith("#")) continue;
      const match = line.match(/^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*)\s*$/);
      if (!match || process.env[match[1]] !== undefined) continue;
      process.env[match[1]] = match[2].replace(/^("|')|("|')$/g, "");
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

function boolean(value, fallback = false) {
  if (value === undefined) return fallback;
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function integer(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`Invalid positive integer: ${value}`);
  return parsed;
}

export function readConfig() {
  const production = process.env.NODE_ENV === "production";
  const appSecret = process.env.APP_SECRET || (production ? "" : "development-only-secret-change-me");
  if (appSecret.length < 32) throw new Error("APP_SECRET must contain at least 32 characters");
  const allowDemoData = boolean(process.env.ALLOW_DEMO_DATA, false);
  const demoReadOnly = boolean(process.env.DEMO_READ_ONLY, false);
  if (demoReadOnly && !allowDemoData) {
    throw new Error("DEMO_READ_ONLY requires ALLOW_DEMO_DATA=true");
  }
  const apiAccessTokenTtlMs = integer(process.env.API_ACCESS_TOKEN_MINUTES, 15) * 60 * 1000;
  const apiRefreshTokenTtlMs = integer(process.env.API_REFRESH_TOKEN_DAYS, 30) * 24 * 60 * 60 * 1000;
  if (apiRefreshTokenTtlMs <= apiAccessTokenTtlMs) {
    throw new Error("API_REFRESH_TOKEN_DAYS must be longer than API_ACCESS_TOKEN_MINUTES");
  }
  const apnsKeyId = String(process.env.APNS_KEY_ID || "").trim();
  const apnsTeamId = String(process.env.APNS_TEAM_ID || "").trim();
  const apnsTopic = String(process.env.APNS_TOPIC || "").trim();
  const apnsPrivateKeyBase64 = String(process.env.APNS_PRIVATE_KEY_BASE64 || "").trim();
  const apnsCredentials = [apnsKeyId, apnsTeamId, apnsPrivateKeyBase64];
  const pushModeInput = String(process.env.PUSH_MODE || "").trim().toLowerCase();
  const inferredPushMode = apnsCredentials.some(Boolean) || apnsTopic ? "direct" : "disabled";
  const pushMode = pushModeInput || (process.env.PUSH_RELAY_URL ? "relay" : inferredPushMode);
  if (!["disabled", "relay", "direct"].includes(pushMode)) {
    throw new Error("PUSH_MODE must be disabled, relay, or direct");
  }
  if (pushMode === "relay" && (apnsCredentials.some(Boolean) || apnsTopic)) {
    throw new Error("Relay mode must not contain APNs credentials; remove APNS_KEY_ID, APNS_TEAM_ID, APNS_TOPIC, and APNS_PRIVATE_KEY_BASE64");
  }
  if (pushMode === "direct" && (!apnsCredentials.every(Boolean) || !apnsTopic)) {
    throw new Error("Direct push mode requires APNS_KEY_ID, APNS_TEAM_ID, APNS_TOPIC, and APNS_PRIVATE_KEY_BASE64");
  }
  const relayUrlInput = String(process.env.PUSH_RELAY_URL || "").trim();
  let relayUrl = "";
  if (pushMode === "relay") {
    if (!relayUrlInput) throw new Error("Relay push mode requires PUSH_RELAY_URL");
    let parsed;
    try { parsed = new URL(relayUrlInput); }
    catch { throw new Error("PUSH_RELAY_URL must be a valid absolute URL"); }
    const localHttp = parsed.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(parsed.hostname);
    if (parsed.protocol !== "https:" && !localHttp) throw new Error("PUSH_RELAY_URL must use HTTPS");
    if (parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
      throw new Error("PUSH_RELAY_URL must be an origin without credentials, a path, query, or fragment");
    }
    relayUrl = parsed.origin;
  }
  const webauthnRpId = String(process.env.WEBAUTHN_RP_ID || "").trim().toLowerCase();
  const webauthnOriginInput = String(process.env.WEBAUTHN_ORIGIN || "").trim();
  const operatorPrivacyPolicyUrlInput = String(process.env.PRIVACY_POLICY_URL || "").trim();
  if (Boolean(webauthnRpId) !== Boolean(webauthnOriginInput)) {
    throw new Error("Passkeys require both WEBAUTHN_RP_ID and WEBAUTHN_ORIGIN");
  }
  let webauthnOrigin = "";
  if (webauthnOriginInput) {
    if (!/^[a-z0-9.-]+$/.test(webauthnRpId) || webauthnRpId.startsWith(".") || webauthnRpId.endsWith(".")) {
      throw new Error("WEBAUTHN_RP_ID must be a hostname without a scheme or port");
    }
    let parsed;
    try { parsed = new URL(webauthnOriginInput); }
    catch { throw new Error("WEBAUTHN_ORIGIN must be a valid origin"); }
    const localHttp = parsed.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(parsed.hostname);
    if (parsed.protocol !== "https:" && !localHttp) throw new Error("WEBAUTHN_ORIGIN must use HTTPS");
    if (parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
      throw new Error("WEBAUTHN_ORIGIN must not contain credentials, a path, query, or fragment");
    }
    if (parsed.hostname !== webauthnRpId && !parsed.hostname.endsWith(`.${webauthnRpId}`)) {
      throw new Error("WEBAUTHN_RP_ID must match WEBAUTHN_ORIGIN or one of its parent domains");
    }
    webauthnOrigin = parsed.origin;
  }
  let operatorPrivacyPolicyUrl = "";
  if (operatorPrivacyPolicyUrlInput) {
    let parsed;
    try { parsed = new URL(operatorPrivacyPolicyUrlInput); }
    catch { throw new Error("PRIVACY_POLICY_URL must be a valid absolute URL"); }
    const localHttp = parsed.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(parsed.hostname);
    if (parsed.protocol !== "https:" && !localHttp) throw new Error("PRIVACY_POLICY_URL must use HTTPS");
    if (parsed.username || parsed.password || parsed.hash) {
      throw new Error("PRIVACY_POLICY_URL must not contain credentials or a fragment");
    }
    operatorPrivacyPolicyUrl = parsed.href;
  }
  let apnsPrivateKey = "";
  if (pushMode === "direct" && apnsPrivateKeyBase64) {
    try { apnsPrivateKey = Buffer.from(apnsPrivateKeyBase64, "base64").toString("utf8"); }
    catch { throw new Error("APNS_PRIVATE_KEY_BASE64 is invalid"); }
    if (!apnsPrivateKey.includes("BEGIN PRIVATE KEY")) {
      throw new Error("APNS_PRIVATE_KEY_BASE64 does not contain an Apple .p8 private key");
    }
  }
  return {
    production,
    port: integer(process.env.PORT, 4173),
    host: process.env.HOST || "127.0.0.1",
    dataDir: process.env.DATA_DIR || new URL("../data", import.meta.url),
    appSecret,
    secureCookies: boolean(process.env.SESSION_COOKIE_SECURE, production),
    trustProxy: boolean(process.env.TRUST_PROXY, false),
    operatorPrivacyPolicyUrl,
    sessionTtlMs: integer(process.env.SESSION_TTL_HOURS, 12) * 60 * 60 * 1000,
    apiAccessTokenTtlMs,
    apiRefreshTokenTtlMs,
    apiMaxDeviceSessions: integer(process.env.API_MAX_DEVICE_SESSIONS, 10),
    proxmoxTimeoutMs: integer(process.env.PROXMOX_REQUEST_TIMEOUT_MS, 12_000),
    syncIntervalMs: integer(process.env.RESOURCE_SYNC_SECONDS, 60) * 1000,
    isoMaxUploadBytes: integer(process.env.ISO_MAX_UPLOAD_MB, 8192) * 1024 * 1024,
    isoUploadTimeoutMs: integer(process.env.ISO_UPLOAD_TIMEOUT_MINUTES, 120) * 60 * 1000,
    emailSmtpTimeoutMs: integer(process.env.EMAIL_SMTP_TIMEOUT_SECONDS, 10) * 1000,
    emailQueueIntervalMs: integer(process.env.EMAIL_QUEUE_INTERVAL_SECONDS, 5) * 1000,
    push: {
      mode: pushMode,
      enabled: pushMode !== "disabled",
      relay: {
        url: relayUrl,
        timeoutMs: integer(process.env.PUSH_RELAY_TIMEOUT_SECONDS, 10) * 1000,
      },
      direct: {
        keyId: apnsKeyId,
        teamId: apnsTeamId,
        topic: apnsTopic,
        privateKey: apnsPrivateKey,
        timeoutMs: integer(process.env.APNS_TIMEOUT_SECONDS, 10) * 1000,
      },
    },
    webauthn: {
      enabled: Boolean(webauthnRpId && webauthnOrigin),
      rpId: webauthnRpId,
      origin: webauthnOrigin,
      rpName: String(process.env.WEBAUTHN_RP_NAME || "Nimbus Direct").trim() || "Nimbus Direct",
    },
    allowDemoData,
    demoReadOnly,
    bootstrap: {
      email: process.env.BOOTSTRAP_ADMIN_EMAIL,
      password: process.env.BOOTSTRAP_ADMIN_PASSWORD,
      displayName: process.env.BOOTSTRAP_ADMIN_NAME || "Administrator",
      customerId: process.env.BOOTSTRAP_CUSTOMER_ID || "",
      customerName: process.env.BOOTSTRAP_CUSTOMER_NAME || "Demo customer",
      customerEmail: process.env.BOOTSTRAP_CUSTOMER_EMAIL || "",
      customerPassword: process.env.BOOTSTRAP_CUSTOMER_PASSWORD || "",
      customerDisplayName: process.env.BOOTSTRAP_CUSTOMER_DISPLAY_NAME || "Customer",
      supportEmail: process.env.BOOTSTRAP_SUPPORT_EMAIL || "",
      planName: process.env.BOOTSTRAP_PLAN_NAME || "Managed infrastructure",
    },
  };
}
