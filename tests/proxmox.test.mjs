import test from "node:test";
import assert from "node:assert/strict";
import { ProxmoxClient, ProxmoxError } from "../server/proxmox.mjs";
import { ProxmoxRegistry } from "../server/proxmox-registry.mjs";

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify({ data }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function mockClient(routes, calls = []) {
  const fetchImpl = async (url, options = {}) => {
    const parsed = new URL(url);
    const key = `${parsed.pathname}${parsed.search}`.replace("/api2/json", "");
    calls.push({ key, options });
    const route = routes[key];
    if (route === undefined) throw new Error(`Unexpected mock request: ${key}`);
    return typeof route === "function" ? route({ url: parsed, options, key }) : route;
  };
  return new ProxmoxClient({
    baseUrl: "https://pve.example.test:8006/",
    tokenId: "panel@pve!portal",
    tokenSecret: "test-secret",
    timeoutMs: 1000,
    fetchImpl,
  });
}

test("registry builds a client only for an explicitly configured cluster", () => {
  const registry = new ProxmoxRegistry({
    getConnection: (clusterId) => clusterId === "production"
      ? { baseUrl: "https://pve.example.test", tokenId: "panel", tokenSecret: "secret" }
      : null,
  });
  assert.equal(registry.forCluster("production").configured, true);
  assert.equal(registry.forCluster("unknown").configured, false);
});

test("request sends the API token only in the authorization header", async () => {
  const calls = [];
  const client = mockClient({ "/version": jsonResponse({ version: "9.0" }) }, calls);
  assert.deepEqual(await client.request("/version"), { version: "9.0" });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.headers.Authorization, "PVEAPIToken=panel@pve!portal=test-secret");
  assert.equal(calls[0].options.redirect, "error");
  assert.equal(calls[0].key.includes("test-secret"), false);
});

test("request maps authentication, timeout, and missing-configuration failures", async () => {
  const authClient = mockClient({ "/version": jsonResponse(null, 401) });
  await assert.rejects(
    () => authClient.request("/version"),
    (error) => error instanceof ProxmoxError && error.code === "proxmox_auth_failed" && error.upstreamStatus === 401,
  );

  const timeoutClient = new ProxmoxClient({
    baseUrl: "https://pve.example.test:8006",
    tokenId: "id",
    tokenSecret: "secret",
    fetchImpl: async () => { throw Object.assign(new Error("timed out"), { name: "TimeoutError" }); },
  });
  await assert.rejects(() => timeoutClient.request("/version"), (error) => error.code === "proxmox_timeout" && error.status === 504);

  const emptyClient = new ProxmoxClient();
  await assert.rejects(() => emptyClient.request("/version"), (error) => error.code === "proxmox_not_configured" && error.status === 503);

  const insecureClient = new ProxmoxClient({ baseUrl: "http://pve.example.test:8006", tokenId: "id", tokenSecret: "secret" });
  await assert.rejects(() => insecureClient.request("/version"), (error) => error.code === "proxmox_https_required" && error.status === 503);
});

test("guest inventory uses cluster resources without any Proxmox pool lookup", async () => {
  const calls = [];
  const client = mockClient({
    "/cluster/resources?type=vm": jsonResponse([
      { type: "qemu", vmid: 100, node: "pve-a", name: "web", status: "running", maxcpu: 4, maxmem: 8 * 1024 ** 3, mem: 2 * 1024 ** 3, cpu: 0.125, pool: "customer-acme" },
      { type: "qemu", vmid: 101, node: "pve-a", name: "outside", status: "running", maxcpu: 2, maxmem: 4 * 1024 ** 3, pool: "customer-acme" },
      { type: "lxc", vmid: 200, node: "pve-b", name: "worker", status: "stopped", maxcpu: 1, maxmem: 1024 ** 3 },
    ]),
  }, calls);

  const instances = await client.listVirtualMachines();
  assert.deepEqual(instances.map((instance) => instance.id), ["qemu-100", "qemu-101", "lxc-200"]);
  assert.equal(instances[0].cpu, 13);
  assert.equal(instances[0].memory, 8);
  assert.equal(instances[0].memoryUsed, 2);
  assert.equal(calls.some((call) => call.key.startsWith("/pools")), false);
});

test("network inspection normalizes QEMU and LXC data and removes local addresses", async () => {
  const client = mockClient({
    "/nodes/pve-a/qemu/100/agent/network-get-interfaces": jsonResponse({
      result: [{
        name: "eth0",
        "hardware-address": "00:11:22:33:44:55",
        "ip-addresses": [
          { "ip-address": "127.0.0.1", "ip-address-type": "ipv4", prefix: 8 },
          { "ip-address": "10.0.0.20", "ip-address-type": "ipv4", prefix: 24 },
          { "ip-address": "fe80::1", "ip-address-type": "ipv6", prefix: 64 },
        ],
      }],
    }),
    "/nodes/pve-b/lxc/200/interfaces": jsonResponse([
      { name: "eth0", hwaddr: "00:aa:bb:cc:dd:ee", inet: "10.0.0.21/24", inet6: "2001:db8::21/64" },
    ]),
  });

  const qemu = await client.getNetwork({ type: "qemu", vmid: 100, node: "pve-a", status: "running" });
  assert.equal(qemu.primaryIp, "10.0.0.20");
  assert.deepEqual(qemu.addresses.map((entry) => entry.address), ["10.0.0.20"]);

  const lxc = await client.getNetwork({ type: "lxc", vmid: 200, node: "pve-b", status: "running" });
  assert.equal(lxc.primaryIp, "10.0.0.21");
  assert.deepEqual(new Set(lxc.addresses.map((entry) => entry.address)), new Set(["10.0.0.21", "2001:db8::21"]));

  assert.equal((await client.getNetwork({ status: "stopped" })).status, "stopped");
});

test("history aggregates CPU by vCPU weight and memory by total capacity", async () => {
  const client = mockClient({
    "/nodes/pve/qemu/100/rrddata?timeframe=day&cf=AVERAGE": jsonResponse([
      { time: 100, cpu: 0.5, maxcpu: 4, mem: 4, maxmem: 8, netin: 10, netout: 20 },
      { time: 200, cpu: 0.25, maxcpu: 4, mem: 6, maxmem: 8, netin: 30, netout: 40 },
    ]),
    "/nodes/pve/lxc/200/rrddata?timeframe=day&cf=AVERAGE": jsonResponse([
      { time: 100, cpu: 0, maxcpu: 1, mem: 1, maxmem: 2, netin: 5, netout: 10 },
      { time: 200, cpu: 0.5, maxcpu: 1, mem: 1, maxmem: 2, netin: 15, netout: 20 },
    ]),
  });
  const instances = [
    { type: "qemu", vmid: 100, node: "pve", vcpu: 4 },
    { type: "lxc", vmid: 200, node: "pve", vcpu: 1 },
  ];
  const history = await client.getHistory(instances, "day");
  assert.equal(history.available, true);
  assert.equal(history.points[0].cpu, 40);
  assert.equal(history.points[0].memory, 50);
  assert.equal(history.points[0].netIn, 15);
  assert.equal(history.points[0].timestamp, 100_000);
  await assert.rejects(() => client.getRrd(instances[0], "decade"), (error) => error.code === "invalid_timeframe");
});

test("instance details expose only allowlisted config and real snapshots", async () => {
  const client = mockClient({
    "/nodes/pve/qemu/100/config?current=1": jsonResponse({
      name: "web",
      cores: 4,
      memory: 8192,
      description: "Customer web server",
      cipassword: "must-not-leak",
      sshkeys: "must-not-leak",
      args: "must-not-leak",
    }),
    "/nodes/pve/qemu/100/agent/network-get-interfaces": jsonResponse({ result: [] }),
    "/nodes/pve/qemu/100/snapshot": jsonResponse([
      { name: "current" },
      { name: "before-upgrade", description: "Known good", snaptime: 100, vmstate: true },
    ]),
  });

  const details = await client.getInstanceDetails({ id: "qemu-100", type: "qemu", vmid: 100, node: "pve", status: "running" });
  assert.deepEqual(details.config, { name: "web", description: "Customer web server", cores: 4, memory: 8192 });
  assert.equal(details.snapshots.length, 1);
  assert.equal(details.snapshots[0].createdAt, 100_000);
  assert.equal(details.snapshots[0].includesMemory, true);
});

test("backup inventory is tenant-filtered and distinguishes denied access from empty data", async () => {
  const instances = [
    { id: "qemu-100", vmid: 100, name: "web" },
    { id: "lxc-200", vmid: 200, name: "worker" },
  ];
  const client = mockClient({
    "/cluster/resources?type=storage": jsonResponse([{ storage: "backup-acme", node: "pve" }]),
    "/nodes/pve/storage/backup-acme/content?content=backup&vmid=100": jsonResponse([
      { volid: "backup:100", vmid: 100, ctime: 200, size: 1024, format: "pbs-vm", protected: 1, verification: { state: "ok" } },
      { volid: "backup:999", vmid: 999, ctime: 300, size: 2048 },
    ]),
    "/nodes/pve/storage/backup-acme/content?content=backup&vmid=200": jsonResponse(null, 403),
  });
  const backups = await client.getBackups(instances, "backup-acme");
  assert.equal(backups.available, true);
  assert.equal(backups.coverage, 50);
  assert.deepEqual(backups.items.map((item) => item.vmid), [100]);
  assert.equal(backups.items[0].verified, "ok");

  const deniedClient = mockClient({
    "/cluster/resources?type=storage": jsonResponse([{ storage: "backup-acme", node: "pve" }]),
    "/nodes/pve/storage/backup-acme/content?content=backup&vmid=100": jsonResponse(null, 403),
    "/nodes/pve/storage/backup-acme/content?content=backup&vmid=200": jsonResponse(null, 403),
  });
  const denied = await deniedClient.getBackups(instances, "backup-acme");
  assert.equal(denied.configured, true);
  assert.equal(denied.available, false);
  assert.equal(denied.reason, "proxmox_permission_denied");

  assert.deepEqual(await client.getBackups(instances, ""), {
    configured: false,
    available: false,
    items: [],
    coverage: 0,
    lastBackupAt: null,
  });
});

test("power actions use server-derived resource coordinates and return Proxmox tasks", async () => {
  const calls = [];
  const upid = "UPID:pve:0001:qmstart:100:panel@pve!portal:";
  const client = mockClient({
    "/nodes/pve/qemu/100/status/start": jsonResponse(upid),
    [`/nodes/pve/tasks/${encodeURIComponent(upid)}/status`]: jsonResponse({ status: "stopped", exitstatus: "OK" }),
  }, calls);
  const vm = { node: "pve", type: "qemu", vmid: 100 };
  assert.equal(await client.performAction(vm, "start"), upid);
  assert.equal(calls[0].options.method, "POST");
  assert.deepEqual(await client.getTaskStatus("pve", upid), { status: "stopped", exitstatus: "OK" });
  await assert.rejects(() => client.performAction(vm, "destroy"), (error) => error.code === "invalid_action");
});
