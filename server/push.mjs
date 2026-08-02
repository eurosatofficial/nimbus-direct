import { createSign } from "node:crypto";
import { connect } from "node:http2";

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function apnsToken({ keyId, teamId, privateKey }) {
  const header = base64url(JSON.stringify({ alg: "ES256", kid: keyId }));
  const payload = base64url(JSON.stringify({
    iss: teamId,
    iat: Math.floor(Date.now() / 1000),
  }));
  const signer = createSign("sha256");
  signer.update(`${header}.${payload}`);
  signer.end();
  const signature = signer.sign({ key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return `${header}.${payload}.${signature}`;
}

export function createPushService({
  store,
  config,
  log = () => {},
  connectClient = connect,
} = {}) {
  let cachedToken = null;
  let cachedAt = 0;

  function providerToken() {
    if (!cachedToken || Date.now() - cachedAt >= 50 * 60_000) {
      cachedToken = apnsToken(config);
      cachedAt = Date.now();
    }
    return cachedToken;
  }

  async function sendDevice(device, notification) {
    if (!config.enabled) return { sent: false, reason: "not_configured" };
    const authority = device.environment === "sandbox"
      ? "https://api.sandbox.push.apple.com"
      : "https://api.push.apple.com";
    const client = connectClient(authority);
    const payload = JSON.stringify({
      aps: {
        alert: {
          title: String(notification.title || "Nimbus Direct").slice(0, 160),
          body: String(notification.message || "").slice(0, 1000),
        },
        sound: "default",
        "mutable-content": 0,
      },
      type: notification.type || "notification",
      resourceId: notification.resourceId || null,
      notificationId: notification.notificationId || null,
    });
    try {
      return await new Promise((resolvePromise, rejectPromise) => {
        const timeout = setTimeout(() => {
          client.destroy();
          rejectPromise(Object.assign(new Error("APNs request timed out"), { code: "apns_timeout" }));
        }, config.timeoutMs);
        const request = client.request({
          ":method": "POST",
          ":path": `/3/device/${device.token}`,
          authorization: `bearer ${providerToken()}`,
          "apns-topic": config.topic,
          "apns-push-type": "alert",
          "apns-priority": "10",
          ...(notification.collapseId ? { "apns-collapse-id": String(notification.collapseId).slice(0, 64) } : {}),
        });
        let status = 0;
        let responseBody = "";
        request.setEncoding("utf8");
        request.on("response", (headers) => { status = Number(headers[":status"] || 0); });
        request.on("data", (chunk) => { responseBody += chunk; });
        request.on("end", () => {
          clearTimeout(timeout);
          client.close();
          let reason = "";
          try { reason = JSON.parse(responseBody || "{}").reason || ""; } catch { reason = ""; }
          if (status === 200) {
            store.markPushDeviceSent(device.id);
            resolvePromise({ sent: true });
            return;
          }
          if (status === 410 || ["BadDeviceToken", "DeviceTokenNotForTopic", "Unregistered"].includes(reason)) {
            store.disablePushDevice(device.id, reason || `http_${status}`);
          }
          rejectPromise(Object.assign(new Error(reason || `APNs HTTP ${status}`), {
            code: "apns_rejected",
            status,
            reason,
          }));
        });
        request.on("error", (error) => {
          clearTimeout(timeout);
          client.destroy();
          rejectPromise(error);
        });
        request.end(payload);
      });
    } finally {
      if (!client.closed && !client.destroyed) client.close();
    }
  }

  async function sendUser(userId, notification) {
    if (!config.enabled) return { attempted: 0, sent: 0 };
    const devices = store.listPushDevices(userId);
    const results = await Promise.allSettled(devices.map((device) => sendDevice(device, notification)));
    results.forEach((result, index) => {
      if (result.status === "rejected") {
        log("error", "push_delivery_failed", {
          userId,
          deviceId: devices[index].id,
          error: result.reason?.code || result.reason?.message,
        });
      }
    });
    return {
      attempted: devices.length,
      sent: results.filter((result) => result.status === "fulfilled" && result.value.sent).length,
    };
  }

  return {
    configured: Boolean(config.enabled),
    sendUser,
  };
}
