import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { generateKeyPairSync } from "node:crypto";
import { createApnsClient } from "../server/apns.mjs";
import { createPushService } from "../server/push.mjs";
import { createPushRelayClient } from "../server/push-relay-client.mjs";
import { publicKeyInstallationId, verifyRelayRequest } from "../server/push-contract.mjs";

test("push service removes only devices rejected as invalid", async () => {
  const disabled = [];
  const sent = [];
  const store = {
    listPushDevices: () => [
      { id: "valid", token: "ab".repeat(32), environment: "production" },
      { id: "old", token: "cd".repeat(32), environment: "production" },
    ],
    markPushDeviceSent: (id) => sent.push(id),
    disablePushDevice: (id, reason) => disabled.push([id, reason]),
  };
  let calls = 0;
  const push = createPushService({
    store,
    config: { mode: "relay", enabled: true },
    deliveryClient: {
      send: async () => (++calls === 1
        ? { success: true, code: "success", category: "success", retryable: false, disableDevice: false }
        : { success: false, code: "Unregistered", category: "invalid_device", retryable: false, disableDevice: true }),
    },
  });
  assert.equal(push.configured, true);
  assert.deepEqual(await push.sendUser("user-1", { title: "Test", message: "Hello" }), { attempted: 2, sent: 1 });
  assert.deepEqual(sent, ["valid"]);
  assert.deepEqual(disabled, [["old", "Unregistered"]]);
});

test("push disabled mode performs no delivery and requires no Apple credentials", async () => {
  let listed = false;
  const push = createPushService({
    store: { listPushDevices: () => { listed = true; return []; } },
    config: { mode: "disabled", enabled: false, direct: {}, relay: {} },
  });
  assert.equal(push.configured, false);
  assert.deepEqual(await push.sendUser("user-1", { message: "Never sent" }), { attempted: 0, sent: 0 });
  assert.equal(listed, false);
});

test("direct APNs mode preserves structured invalid-token responses", async () => {
  const client = new EventEmitter();
  client.closed = false;
  client.destroyed = false;
  client.close = () => { client.closed = true; };
  client.destroy = () => { client.destroyed = true; };
  client.request = () => {
    const request = new EventEmitter();
    request.setEncoding = () => {};
    request.end = () => queueMicrotask(() => {
      request.emit("response", { ":status": 410, "apns-id": "apns-id" });
      request.emit("data", JSON.stringify({ reason: "Unregistered" }));
      request.emit("end");
    });
    return request;
  };
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const apns = createApnsClient({
    keyId: "KEY123",
    teamId: "TEAM123",
    topic: "com.example.custom-nimbus",
    privateKey: pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    connectClient: () => client,
  });
  const result = await apns.send({
    deviceToken: "ef".repeat(32), environment: "production", title: "Test", body: "Test",
  });
  assert.equal(result.success, false);
  assert.equal(result.code, "Unregistered");
  assert.equal(result.category, "invalid_device");
  assert.equal(result.disableDevice, true);
});

test("relay client self-registers with a signed installation identity", async () => {
  let saved = null;
  let registered = false;
  const requests = [];
  const store = {
    getPushRelayCredential: () => saved,
    savePushRelayCredential: (value) => { saved = { ...value }; },
    markPushRelayRegistered: () => { registered = true; },
    clearPushRelayRegistration: () => { registered = false; },
  };
  const fetchClient = async (url, options) => {
    const body = String(options.body);
    const payload = JSON.parse(body);
    requests.push({ url: String(url), options, payload });
    const publicKey = payload.publicKey || requests[0].payload.publicKey;
    assert.equal(options.headers["x-nimbus-installation"], publicKeyInstallationId(publicKey));
    assert.equal(verifyRelayRequest(publicKey, options.headers["x-nimbus-signature"], {
      method: "POST",
      path: new URL(url).pathname,
      timestamp: options.headers["x-nimbus-timestamp"],
      nonce: options.headers["x-nimbus-nonce"],
      body,
    }), true);
    if (String(url).endsWith("/register")) {
      return new Response(JSON.stringify({ registered: true }), { status: 201, headers: { "content-type": "application/json" } });
    }
    return new Response(JSON.stringify({ delivery: {
      success: true, code: "success", category: "success", retryable: false,
      disableDevice: false, apnsStatus: 200, apnsId: "test-id",
    } }), { status: 200, headers: { "content-type": "application/json" } });
  };
  const client = createPushRelayClient({
    store,
    relayUrl: "https://push.example.test/",
    fetchClient,
    softwareVersion: "1.7.1",
  });
  const result = await client.send({
    deviceToken: "ab".repeat(32), environment: "production", title: "Hello", body: "World",
  });
  assert.equal(result.success, true);
  assert.equal(registered, true);
  assert.equal(requests.length, 2);
  assert.equal(requests[1].payload.topic, undefined);
  assert.equal(requests[1].payload.privateKey, undefined);
  assert.equal(JSON.stringify(requests).includes("APNS_KEY"), false);
});
