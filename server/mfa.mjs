import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function problem(message, code = "invalid_mfa_code", status = 400) {
  return Object.assign(new Error(message), { code, status });
}

export function encodeBase32(value) {
  const bytes = Buffer.from(value);
  let bits = 0;
  let accumulator = 0;
  let encoded = "";
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      encoded += BASE32_ALPHABET[(accumulator >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) encoded += BASE32_ALPHABET[(accumulator << (5 - bits)) & 31];
  return encoded;
}

export function decodeBase32(value) {
  const input = String(value || "").toUpperCase().replace(/[\s=-]/g, "");
  if (!input || [...input].some((character) => !BASE32_ALPHABET.includes(character))) {
    throw problem("The authenticator secret is invalid", "invalid_mfa_secret", 500);
  }
  let bits = 0;
  let accumulator = 0;
  const decoded = [];
  for (const character of input) {
    accumulator = (accumulator << 5) | BASE32_ALPHABET.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      decoded.push((accumulator >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(decoded);
}

export function generateTotp(secret, {
  timestamp = Date.now(),
  period = 30,
  digits = 6,
  algorithm = "sha1",
} = {}) {
  const counter = Math.floor(Number(timestamp) / 1000 / period);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac(algorithm, decodeBase32(secret)).update(message).digest();
  const offset = digest[digest.length - 1] & 15;
  const binary = ((digest[offset] & 127) << 24)
    | ((digest[offset + 1] & 255) << 16)
    | ((digest[offset + 2] & 255) << 8)
    | (digest[offset + 3] & 255);
  return String(binary % (10 ** digits)).padStart(digits, "0");
}

export function normalizeMfaCode(value) {
  return String(value || "").toUpperCase().replace(/[\s-]/g, "");
}

export function verifyTotp(secret, code, { timestamp = Date.now(), window = 1 } = {}) {
  const normalized = normalizeMfaCode(code);
  if (!/^\d{6}$/.test(normalized)) return false;
  for (let offset = -Math.max(0, window); offset <= Math.max(0, window); offset += 1) {
    const expected = generateTotp(secret, { timestamp: Number(timestamp) + offset * 30_000 });
    const expectedBuffer = Buffer.from(expected);
    const actualBuffer = Buffer.from(normalized);
    if (expectedBuffer.length === actualBuffer.length && timingSafeEqual(expectedBuffer, actualBuffer)) return true;
  }
  return false;
}

export function createTotpEnrollment(email, { issuer = "Nimbus Direct" } = {}) {
  const secret = encodeBase32(randomBytes(20));
  const label = `${issuer}:${String(email || "").trim().toLowerCase()}`;
  const query = new URLSearchParams({
    secret,
    issuer,
    algorithm: "SHA1",
    digits: "6",
    period: "30",
  });
  return {
    secret,
    uri: `otpauth://totp/${encodeURIComponent(label)}?${query}`,
  };
}

export function generateRecoveryCodes(count = 10) {
  return Array.from({ length: Math.max(1, Math.min(20, Number(count) || 10)) }, () => {
    const bytes = randomBytes(10);
    let code = "";
    for (let index = 0; index < 10; index += 1) code += RECOVERY_ALPHABET[bytes[index] % RECOVERY_ALPHABET.length];
    return `${code.slice(0, 5)}-${code.slice(5)}`;
  });
}
