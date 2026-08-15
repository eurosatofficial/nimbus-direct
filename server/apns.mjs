import { createSign } from "node:crypto";
import { connect } from "node:http2";
import { classifyApnsResponse, validatePushDelivery } from "./push-contract.mjs";

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

export function createApnsProviderToken({ keyId, teamId, privateKey }, now = () => Date.now()) {
  const header = base64url(JSON.stringify({ alg: "ES256", kid: keyId }));
  const payload = base64url(JSON.stringify({ iss: teamId, iat: Math.floor(now() / 1000) }));
  const signer = createSign("sha256");
  signer.update(`${header}.${payload}`);
  signer.end();
  const signature = signer.sign({ key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return `${header}.${payload}.${signature}`;
}

export function createApnsClient({
  keyId,
  teamId,
  topic,
  privateKey,
  timeoutMs = 10_000,
  allowSandbox = true,
  connectClient = connect,
  now = () => Date.now(),
} = {}) {
  let cachedToken = null;
  let cachedAt = 0;

  function providerToken() {
    if (!cachedToken || now() - cachedAt >= 50 * 60_000) {
      cachedToken = createApnsProviderToken({ keyId, teamId, privateKey }, now);
      cachedAt = now();
    }
    return cachedToken;
  }

  async function send(input) {
    let notification;
    try {
      notification = validatePushDelivery(input, { allowSandbox });
    } catch (error) {
      return {
        success: false,
        code: error.code || "invalid_push_payload",
        category: "invalid_request",
        retryable: false,
        disableDevice: false,
        apnsStatus: 0,
        apnsId: null,
      };
    }

    const authority = notification.environment === "sandbox"
      ? "https://api.sandbox.push.apple.com"
      : "https://api.push.apple.com";
    let client;
    try {
      client = connectClient(authority);
      return await new Promise((resolve) => {
        let settled = false;
        const finish = (result) => {
          if (settled) return;
          settled = true;
          clearTimeout(timeout);
          if (client && !client.closed && !client.destroyed) client.close();
          resolve(result);
        };
        const timeout = setTimeout(() => {
          if (client && !client.destroyed) client.destroy();
          finish({
            success: false,
            code: "apns_timeout",
            category: "temporary_failure",
            retryable: true,
            disableDevice: false,
            apnsStatus: 0,
            apnsId: null,
          });
        }, timeoutMs);
        client.once("error", () => finish({
          success: false,
          code: "apns_transport_error",
          category: "temporary_failure",
          retryable: true,
          disableDevice: false,
          apnsStatus: 0,
          apnsId: null,
        }));

        let authorization;
        try { authorization = `bearer ${providerToken()}`; }
        catch {
          finish({
            success: false,
            code: "InvalidProviderToken",
            category: "provider_authentication",
            retryable: false,
            disableDevice: false,
            apnsStatus: 0,
            apnsId: null,
          });
          return;
        }

        const request = client.request({
          ":method": "POST",
          ":path": `/3/device/${notification.deviceToken}`,
          authorization,
          "apns-topic": topic,
          "apns-push-type": "alert",
          "apns-priority": "10",
          ...(notification.collapseId ? { "apns-collapse-id": notification.collapseId } : {}),
        });
        let status = 0;
        let apnsId = null;
        let responseBody = "";
        request.setEncoding("utf8");
        request.on("response", (headers) => {
          status = Number(headers[":status"] || 0);
          apnsId = headers["apns-id"] ? String(headers["apns-id"]) : null;
        });
        request.on("data", (chunk) => {
          if (responseBody.length < 16_384) responseBody += chunk;
        });
        request.on("end", () => {
          let reason = "";
          try { reason = JSON.parse(responseBody || "{}").reason || ""; } catch { reason = ""; }
          finish(classifyApnsResponse({ status, reason, apnsId }));
        });
        request.on("error", () => finish({
          success: false,
          code: "apns_transport_error",
          category: "temporary_failure",
          retryable: true,
          disableDevice: false,
          apnsStatus: 0,
          apnsId: null,
        }));
        request.end(notification.payload);
      });
    } catch {
      if (client && !client.destroyed) client.destroy();
      return {
        success: false,
        code: "apns_transport_error",
        category: "temporary_failure",
        retryable: true,
        disableDevice: false,
        apnsStatus: 0,
        apnsId: null,
      };
    }
  }

  return { send };
}
