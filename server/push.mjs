import { createApnsClient } from "./apns.mjs";
import { createPushRelayClient } from "./push-relay-client.mjs";
import { relayFailure } from "./push-contract.mjs";

export function createPushService({
  store,
  config = { mode: "disabled", enabled: false },
  log = () => {},
  connectClient,
  fetchClient,
  softwareVersion = "1.7.3",
  deliveryClient,
} = {}) {
  const mode = config.mode || (config.enabled ? "direct" : "disabled");
  let client = deliveryClient || null;
  if (!client && mode === "direct") {
    client = createApnsClient({ ...config.direct, connectClient });
  }
  if (!client && mode === "relay") {
    client = createPushRelayClient({
      store,
      relayUrl: config.relay.url,
      timeoutMs: config.relay.timeoutMs,
      softwareVersion,
      fetchClient,
    });
  }

  async function sendDevice(device, notification) {
    if (!client || mode === "disabled") {
      return relayFailure("push_disabled", { category: "disabled" });
    }
    let result;
    try {
      result = await client.send({
        deviceToken: device.token,
        environment: device.environment,
        title: notification.title || "Nimbus Direct",
        body: notification.message || notification.body || "",
        type: notification.type || "notification",
        resourceId: notification.resourceId || null,
        notificationId: notification.notificationId || null,
        collapseId: notification.collapseId || null,
      });
    } catch {
      result = relayFailure("push_delivery_error", {
        category: "temporary_failure",
        retryable: true,
      });
    }
    if (result.success) store.markPushDeviceSent(device.id);
    if (result.disableDevice) store.disablePushDevice(device.id, result.code || "invalid_device");
    return result;
  }

  async function sendUser(userId, notification) {
    if (!client || mode === "disabled") return { attempted: 0, sent: 0 };
    const devices = store.listPushDevices(userId);
    const results = await Promise.all(devices.map((device) => sendDevice(device, notification)));
    results.forEach((result, index) => {
      if (!result.success) {
        log(result.retryable ? "error" : "info", "push_delivery_failed", {
          userId,
          deviceId: devices[index].id,
          mode,
          code: result.code,
          category: result.category,
          retryable: Boolean(result.retryable),
        });
      }
    });
    return {
      attempted: devices.length,
      sent: results.filter((result) => result.success).length,
    };
  }

  return {
    configured: Boolean(client && mode !== "disabled"),
    mode,
    sendDevice,
    sendUser,
  };
}
