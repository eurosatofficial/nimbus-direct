import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);
const PASSWORD_COST = 32768;

export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

export function hashToken(token, secret = "") {
  return secret ? createHmac("sha256", secret).update(token).digest("base64url") : createHash("sha256").update(token).digest("base64url");
}

function encryptionKey(secret) {
  if (typeof secret !== "string" || secret.length < 32) {
    throw new Error("Credential encryption requires an APP_SECRET of at least 32 characters");
  }
  return createHash("sha256").update(`nimbus-direct:v1:${secret}`).digest();
}

export function encryptSecret(value, secret) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(secret), iv);
  const encrypted = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1.${iv.toString("base64url")}.${tag.toString("base64url")}.${encrypted.toString("base64url")}`;
}

export function decryptSecret(value, secret) {
  const [version, encodedIv, encodedTag, encodedCiphertext] = String(value || "").split(".");
  if (version !== "v1" || !encodedIv || !encodedTag || !encodedCiphertext) throw new Error("Stored credential is malformed");
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey(secret), Buffer.from(encodedIv, "base64url"));
  decipher.setAuthTag(Buffer.from(encodedTag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(encodedCiphertext, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

export async function hashPassword(password) {
  if (typeof password !== "string" || password.length < 12 || password.length > 256) {
    throw Object.assign(new Error("Passwords must contain between 12 and 256 characters"), {
      status: 400,
      code: "invalid_password",
    });
  }
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, 64, { N: PASSWORD_COST, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${PASSWORD_COST}$8$1$${salt.toString("base64url")}$${Buffer.from(derived).toString("base64url")}`;
}

export async function verifyPassword(password, encoded) {
  try {
    const [algorithm, cost, r, p, salt, expected] = encoded.split("$");
    if (algorithm !== "scrypt") return false;
    const expectedBuffer = Buffer.from(expected, "base64url");
    const actual = await scrypt(password, Buffer.from(salt, "base64url"), expectedBuffer.length, {
      N: Number(cost), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024,
    });
    return timingSafeEqual(expectedBuffer, Buffer.from(actual));
  } catch {
    return false;
  }
}

export function safeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

export function parseCookies(header = "") {
  return Object.fromEntries(header.split(";").map((part) => {
    const index = part.indexOf("=");
    if (index < 0) return ["", ""];
    return [decodeURIComponent(part.slice(0, index).trim()), decodeURIComponent(part.slice(index + 1).trim())];
  }).filter(([key]) => key));
}

export function sessionCookieName(secure) {
  return secure ? "__Host-nimbus_session" : "nimbus_session";
}

export function sessionCookie(value, { secure, maxAge, name = sessionCookieName(secure) }) {
  const attributes = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${Math.max(0, Math.floor(maxAge / 1000))}`,
  ];
  if (secure) attributes.push("Secure");
  return attributes.join("; ");
}

export function securityHeaders() {
  return {
    "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
  };
}

export function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}
