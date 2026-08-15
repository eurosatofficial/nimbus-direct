import { generateKeyPairSync, randomBytes } from "node:crypto";
import {
  publicKeyInstallationId,
  relayFailure,
  signRelayRequest,
  validatePushDelivery,
} from "./push-contract.mjs";

function createCredential() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  return {
    installationId: publicKeyInstallationId(publicKeyPem),
    publicKey: publicKeyPem,
    privateKey: privateKeyPem,
    registeredAt: null,
  };
}

function responseFailure(status, code = "relay_rejected") {
  if (status === 401 || status === 403) {
    return relayFailure(code, { category: "relay_authentication", relayStatus: status });
  }
  if (status === 429) {
    return relayFailure(code, { category: "rate_limited", retryable: true, relayStatus: status });
  }
  if (status >= 500) {
    return relayFailure(code, { category: "temporary_failure", retryable: true, relayStatus: status });
  }
  return relayFailure(code, { category: "relay_rejected", relayStatus: status });
}

export function createPushRelayClient({
  store,
  relayUrl,
  timeoutMs = 10_000,
  softwareVersion = "unknown",
  fetchClient = globalThis.fetch,
  now = () => Date.now(),
} = {}) {
  if (typeof fetchClient !== "function") throw new Error("Push relay requires a fetch implementation");
  const baseUrl = String(relayUrl || "").replace(/\/$/, "");
  let credential = store.getPushRelayCredential();
  if (!credential) {
    credential = createCredential();
    store.savePushRelayCredential(credential);
  }
  let registrationPromise = null;

  async function signedPost(path, payload) {
    const url = new URL(path, `${baseUrl}/`);
    const body = JSON.stringify(payload);
    const timestamp = String(Math.floor(now() / 1000));
    const nonce = randomBytes(18).toString("base64url");
    const signature = signRelayRequest(credential.privateKey, {
      method: "POST",
      path: url.pathname,
      timestamp,
      nonce,
      body,
    });
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchClient(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-nimbus-installation": credential.installationId,
          "x-nimbus-timestamp": timestamp,
          "x-nimbus-nonce": nonce,
          "x-nimbus-signature": signature,
        },
        body,
        signal: controller.signal,
      });
      let result = {};
      try { result = await response.json(); } catch { result = {}; }
      return { status: response.status, result };
    } finally {
      clearTimeout(timeout);
    }
  }

  async function register() {
    if (registrationPromise) return registrationPromise;
    registrationPromise = (async () => {
      try {
        const { status, result } = await signedPost("v1/installations/register", {
          installationId: credential.installationId,
          publicKey: credential.publicKey,
          softwareVersion: String(softwareVersion || "unknown").slice(0, 40),
        });
        if (status >= 200 && status < 300 && result.registered === true) {
          store.markPushRelayRegistered(credential.installationId);
          credential = { ...credential, registeredAt: now() };
          return { success: true };
        }
        return responseFailure(status, result.error || "relay_registration_rejected");
      } catch (error) {
        return relayFailure(error?.name === "AbortError" ? "relay_timeout" : "relay_unavailable", {
          category: "temporary_failure",
          retryable: true,
        });
      } finally {
        registrationPromise = null;
      }
    })();
    return registrationPromise;
  }

  async function send(input) {
    let delivery;
    try {
      delivery = validatePushDelivery(input);
    } catch (error) {
      return relayFailure(error.code || "invalid_push_payload", { category: "invalid_request" });
    }
    if (!credential.registeredAt) {
      const registration = await register();
      if (!registration.success) return registration;
    }
    const payload = {
      deviceToken: delivery.deviceToken,
      environment: delivery.environment,
      title: delivery.title,
      body: delivery.body,
      type: delivery.type,
      notificationId: delivery.notificationId,
      resourceId: delivery.resourceId,
      collapseId: delivery.collapseId,
    };
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const { status, result } = await signedPost("v1/push", payload);
        if (status >= 200 && status < 300 && result.delivery && typeof result.delivery.success === "boolean") {
          return result.delivery;
        }
        if (status === 401 && result.error === "unknown_installation" && attempt === 0) {
          store.clearPushRelayRegistration(credential.installationId);
          credential = { ...credential, registeredAt: null };
          const registration = await register();
          if (!registration.success) return registration;
          continue;
        }
        return responseFailure(status, result.error || "relay_rejected");
      } catch (error) {
        return relayFailure(error?.name === "AbortError" ? "relay_timeout" : "relay_unavailable", {
          category: "temporary_failure",
          retryable: true,
        });
      }
    }
    return relayFailure("relay_authentication_failed", { category: "relay_authentication" });
  }

  return {
    installationId: credential.installationId,
    register,
    send,
  };
}
