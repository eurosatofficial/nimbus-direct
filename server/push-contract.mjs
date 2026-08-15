import {
  createHash,
  createPublicKey,
  sign as signValue,
  verify as verifyValue,
} from "node:crypto";

export const OFFICIAL_APNS_TOPIC = "de.liamjayden.nimbusdirect";
export const MAX_APNS_PAYLOAD_BYTES = 4096;

function problem(message, code, status = 400) {
  return Object.assign(new Error(message), { code, status });
}

function text(value, { field, maximum, fallback = "", required = false } = {}) {
  const clean = String(value ?? fallback).trim();
  if (required && !clean) throw problem(`${field} is required`, `invalid_${field}`);
  if (clean.length > maximum) throw problem(`${field} is too long`, `invalid_${field}`);
  return clean;
}

export function validatePushDelivery(input, { allowSandbox = true } = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw problem("Push payload must be an object", "invalid_push_payload");
  }
  const deviceToken = String(input.deviceToken || "").trim().toLowerCase();
  if (!/^[a-f0-9]{64,200}$/.test(deviceToken)) {
    throw problem("APNs device token is invalid", "invalid_device_token");
  }
  const environment = String(input.environment || "production").trim().toLowerCase();
  if (!["production", "sandbox"].includes(environment) || (environment === "sandbox" && !allowSandbox)) {
    throw problem("APNs environment is not allowed", "invalid_apns_environment");
  }
  const delivery = {
    deviceToken,
    environment,
    title: text(input.title, { field: "title", maximum: 160, fallback: "Nimbus Direct", required: true }),
    body: text(input.body ?? input.message, { field: "body", maximum: 1000, required: true }),
    type: text(input.type, { field: "type", maximum: 64, fallback: "notification" }),
    notificationId: text(input.notificationId, { field: "notification_id", maximum: 128 }) || null,
    resourceId: text(input.resourceId, { field: "resource_id", maximum: 180 }) || null,
    collapseId: text(input.collapseId, { field: "collapse_id", maximum: 64 }) || null,
  };
  const payload = buildApnsPayload(delivery);
  if (Buffer.byteLength(payload) > MAX_APNS_PAYLOAD_BYTES) {
    throw problem("APNs payload exceeds 4096 bytes", "push_payload_too_large", 413);
  }
  return { ...delivery, payload };
}

export function buildApnsPayload(notification) {
  return JSON.stringify({
    aps: {
      alert: { title: notification.title, body: notification.body },
      sound: "default",
      "mutable-content": 0,
    },
    type: notification.type || "notification",
    resourceId: notification.resourceId || null,
    notificationId: notification.notificationId || null,
  });
}

export function publicKeyInstallationId(publicKey) {
  let key;
  try { key = createPublicKey(publicKey); }
  catch { throw problem("Installation public key is invalid", "invalid_installation_key"); }
  if (key.asymmetricKeyType !== "ed25519") {
    throw problem("Installation key must use Ed25519", "invalid_installation_key");
  }
  const fingerprint = createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("base64url");
  return `ndi_${fingerprint}`;
}

export function relayBodyHash(body) {
  return createHash("sha256").update(body).digest("base64url");
}

export function relayCanonicalRequest({ method, path, timestamp, nonce, body }) {
  return `${String(method).toUpperCase()}\n${path}\n${timestamp}\n${nonce}\n${relayBodyHash(body)}`;
}

export function signRelayRequest(privateKey, request) {
  return signValue(null, Buffer.from(relayCanonicalRequest(request)), privateKey).toString("base64url");
}

export function verifyRelayRequest(publicKey, signature, request) {
  try {
    if (!/^[A-Za-z0-9_-]{80,120}$/.test(String(signature || ""))) return false;
    return verifyValue(
      null,
      Buffer.from(relayCanonicalRequest(request)),
      publicKey,
      Buffer.from(signature, "base64url"),
    );
  } catch {
    return false;
  }
}

export function classifyApnsResponse({ status, reason = "", apnsId = null } = {}) {
  const apnsStatus = Number(status || 0);
  const code = String(reason || (apnsStatus ? `HTTP_${apnsStatus}` : "UnknownAPNsResponse"));
  if (apnsStatus === 200) {
    return {
      success: true,
      code: "success",
      category: "success",
      retryable: false,
      disableDevice: false,
      apnsStatus,
      apnsId,
    };
  }
  if (["BadDeviceToken", "DeviceTokenNotForTopic", "Unregistered"].includes(code) || apnsStatus === 410) {
    return {
      success: false,
      code,
      category: "invalid_device",
      retryable: false,
      disableDevice: true,
      apnsStatus,
      apnsId,
    };
  }
  if (["InvalidProviderToken", "ExpiredProviderToken"].includes(code) || apnsStatus === 403) {
    return {
      success: false,
      code,
      category: "provider_authentication",
      retryable: code === "ExpiredProviderToken",
      disableDevice: false,
      apnsStatus,
      apnsId,
    };
  }
  if (apnsStatus === 429 || code === "TooManyRequests") {
    return {
      success: false,
      code,
      category: "rate_limited",
      retryable: true,
      disableDevice: false,
      apnsStatus,
      apnsId,
    };
  }
  if (apnsStatus >= 500 || ["InternalServerError", "ServiceUnavailable", "Shutdown"].includes(code)) {
    return {
      success: false,
      code,
      category: "temporary_failure",
      retryable: true,
      disableDevice: false,
      apnsStatus,
      apnsId,
    };
  }
  return {
    success: false,
    code,
    category: "apns_rejected",
    retryable: false,
    disableDevice: false,
    apnsStatus,
    apnsId,
  };
}

export function relayFailure(code, {
  category = "relay_error",
  retryable = false,
  disableDevice = false,
  relayStatus = 0,
} = {}) {
  return {
    success: false,
    code,
    category,
    retryable,
    disableDevice,
    relayStatus,
    apnsStatus: 0,
    apnsId: null,
  };
}
