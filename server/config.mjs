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
  return {
    production,
    port: integer(process.env.PORT, 4173),
    host: process.env.HOST || "127.0.0.1",
    dataDir: process.env.DATA_DIR || new URL("../data", import.meta.url),
    appSecret,
    secureCookies: boolean(process.env.SESSION_COOKIE_SECURE, production),
    trustProxy: boolean(process.env.TRUST_PROXY, false),
    sessionTtlMs: integer(process.env.SESSION_TTL_HOURS, 12) * 60 * 60 * 1000,
    proxmoxTimeoutMs: integer(process.env.PROXMOX_REQUEST_TIMEOUT_MS, 12_000),
    syncIntervalMs: integer(process.env.RESOURCE_SYNC_SECONDS, 60) * 1000,
    allowDemoData: boolean(process.env.ALLOW_DEMO_DATA, false),
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
