/**
 * Server-side Proxmox VE client. Credentials never leave the application
 * process. Every caller must first scope resources to the authenticated
 * panel's local customer-resource assignment ledger. No Proxmox pools are
 * used for tenancy.
 */

import { createHash, randomBytes } from "node:crypto";
import { isIP } from "node:net";

export class ProxmoxError extends Error {
  constructor(message, { code = "proxmox_request_failed", status = 502, upstreamStatus = null } = {}) {
    super(message);
    this.name = "ProxmoxError";
    this.code = code;
    this.status = status;
    this.upstreamStatus = upstreamStatus;
  }
}

function finite(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function round(value, precision = 1) {
  const scale = 10 ** precision;
  return Math.round(finite(value) * scale) / scale;
}

function percent(used, total) {
  const capacity = finite(total);
  return capacity > 0 ? round(Math.max(0, finite(used)) / capacity * 100, 1) : 0;
}

function parseStorageList(value) {
  return [...new Set(String(value || "").split(",").map((entry) => entry.trim()).filter(Boolean))];
}

function normalizeOperationsStorage(storage, nodeOverride = null) {
  const node = String(nodeOverride || storage?.node || "");
  const storageId = String(storage?.storage || "");
  if (!node || !storageId) return null;
  const usedBytes = finite(storage.disk ?? storage.used);
  const totalBytes = finite(storage.maxdisk ?? storage.total);
  const availableBytes = Math.max(0, finite(storage.avail, totalBytes - usedBytes));
  return {
    node,
    storageId,
    status: String(storage.status || (storage.enabled === 0 ? "disabled" : storage.active === 0 ? "inactive" : "available")).toLowerCase(),
    type: String(storage.plugintype || storage.type || "unknown"),
    shared: Boolean(storage.shared),
    content: parseStorageList(storage.content),
    usedBytes,
    totalBytes,
    availableBytes,
    usagePercent: percent(usedBytes, totalBytes),
  };
}

function uniqueOperationsStorages(storages) {
  return [...new Map(storages.filter(Boolean).map((storage) => [`${storage.node}\0${storage.storageId}`, storage])).values()];
}

const nonPersistentFilesystemTypes = new Set([
  "autofs", "binfmt_misc", "cgroup", "cgroup2", "configfs", "debugfs",
  "devpts", "devtmpfs", "efivarfs", "fusectl", "hugetlbfs", "iso9660",
  "mqueue", "nsfs", "overlay", "proc", "pstore", "rpc_pipefs",
  "securityfs", "squashfs", "sysfs", "tmpfs", "tracefs",
]);

function normalizeQemuFilesystemUsage(payload) {
  const filesystems = Array.isArray(payload?.result) ? payload.result : Array.isArray(payload) ? payload : [];
  const persistent = new Map();
  for (const filesystem of filesystems) {
    const type = String(filesystem?.type || "").toLowerCase();
    if (nonPersistentFilesystemTypes.has(type) || type.startsWith("cgroup")) continue;
    const disks = Array.isArray(filesystem?.disk) ? filesystem.disk : [];
    if (!disks.length) continue;
    const totalBytes = Number(filesystem?.["total-bytes"]);
    const rawUsedBytes = Number(filesystem?.["used-bytes"]);
    if (!Number.isFinite(totalBytes) || totalBytes <= 0 || !Number.isFinite(rawUsedBytes)) continue;
    const usedBytes = Math.min(totalBytes, Math.max(0, rawUsedBytes));
    const name = String(filesystem?.name || "").trim();
    const diskIdentity = disks.map((disk) =>
      [disk?.serial, disk?.dev, disk?.["bus-type"], disk?.bus, disk?.target, disk?.unit]
        .filter((part) => part !== null && part !== undefined && String(part).length)
        .join(":"))
      .filter(Boolean)
      .sort()
      .join("|");
    const identity = name || diskIdentity || String(filesystem?.mountpoint || "").trim();
    if (!identity) continue;
    const current = persistent.get(identity);
    if (!current || totalBytes > current.totalBytes) persistent.set(identity, { usedBytes, totalBytes });
  }
  if (!persistent.size) return null;
  const totals = [...persistent.values()].reduce((sum, filesystem) => ({
    usedBytes: sum.usedBytes + filesystem.usedBytes,
    totalBytes: sum.totalBytes + filesystem.totalBytes,
  }), { usedBytes: 0, totalBytes: 0 });
  return { ...totals, filesystems: persistent.size };
}

function safeIsoFilename(value) {
  const name = String(value || "").replace(/[^A-Za-z0-9_.-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 180);
  if (!name.toLowerCase().endsWith(".iso")) throw new ProxmoxError("ISO filename must end in .iso", { code: "invalid_iso_filename", status: 400 });
  return name;
}

function bootOrderDevices(value) {
  const match = String(value || "").match(/(?:^|,)order=([^,]+)/);
  if (!match) return [];
  return match[1].split(";").map((entry) => entry.trim()).filter((entry) => /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(entry));
}

function bootableQemuDevices(config = {}) {
  const configured = bootOrderDevices(config.boot);
  if (configured.length) return configured;
  const bootDisk = String(config.bootdisk || "");
  const disks = Object.entries(config)
    .filter(([key, value]) =>
      /^(ide|sata|scsi|virtio)\d+$/.test(key)
      && !String(value).split(",").includes("media=cdrom")
      && String(value).split(",")[0] !== "none")
    .map(([key]) => key);
  const networks = Object.keys(config).filter((key) => /^net\d+$/.test(key));
  return [...new Set([bootDisk, ...disks, ...networks].filter((entry) => /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(entry)))];
}

function qemuSerialDisplay(value) {
  const display = typeof value === "object" && value !== null ? value.type : value;
  const type = String(display || "").split(",", 1)[0].trim().toLowerCase();
  return /^serial[0-3]$/.test(type) ? type : null;
}

async function mapLimit(items, limit, mapper) {
  const result = new Array(items.length);
  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      const index = cursor++;
      result[index] = await mapper(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return result;
}

function usableAddress(address) {
  const value = String(address || "").split("%")[0];
  return isIP(value) !== 0
    && value !== "0.0.0.0"
    && value !== "127.0.0.1"
    && value !== "::"
    && value !== "::1"
    && !value.startsWith("169.254.")
    && !value.toLowerCase().startsWith("fe80:");
}

function normalizeAddresses(entries = []) {
  const seen = new Set();
  const addresses = [];
  for (const entry of entries) {
    const raw = typeof entry === "string" ? entry : entry?.["ip-address"] || entry?.address;
    if (!raw) continue;
    const [address, inlinePrefix] = String(raw).split("/");
    if (!usableAddress(address) || seen.has(address)) continue;
    seen.add(address);
    addresses.push({
      address,
      family: entry?.["ip-address-type"] || (address.includes(":") ? "ipv6" : "ipv4"),
      prefix: finite(entry?.prefix ?? inlinePrefix, 0) || null,
    });
  }
  return addresses.sort((left, right) => (left.family === "ipv4" ? -1 : 1) - (right.family === "ipv4" ? -1 : 1));
}

function normalizeInterface(entry = {}) {
  const addresses = normalizeAddresses([
    ...(Array.isArray(entry["ip-addresses"]) ? entry["ip-addresses"] : []),
    entry.inet,
    entry.inet6,
  ].filter(Boolean));
  return {
    name: String(entry.name || entry.ifname || "interface"),
    mac: entry["hardware-address"] || entry.hwaddr || null,
    addresses,
  };
}

function summarizeNetwork(interfaces, status = "available", source = "guest") {
  const safeInterfaces = interfaces.map(normalizeInterface).filter((entry) => entry.name !== "lo" || entry.addresses.length);
  const addresses = safeInterfaces.flatMap((entry) => entry.addresses.map((address) => ({ ...address, interface: entry.name })));
  return {
    status,
    source,
    primaryIp: addresses.find((entry) => entry.family === "ipv4")?.address || addresses[0]?.address || null,
    addresses,
    interfaces: safeInterfaces,
  };
}

function propertyMap(value) {
  return Object.fromEntries(String(value || "").split(",").map((entry) => {
    const separator = entry.indexOf("=");
    return separator > 0
      ? [entry.slice(0, separator).trim(), entry.slice(separator + 1).trim()]
      : [entry.trim(), ""];
  }).filter(([key]) => key));
}

function configuredNetwork(config = {}, type = "qemu", status = "configured") {
  const interfaces = Object.entries(config).flatMap(([key, value]) => {
    if (type === "qemu" && /^ipconfig\d+$/.test(key)) {
      const properties = propertyMap(value);
      return [{
        name: key.replace(/^ipconfig/, "net"),
        inet: properties.ip,
        inet6: properties.ip6,
      }];
    }
    if (type === "lxc" && /^net\d+$/.test(key)) {
      const properties = propertyMap(value);
      return [{
        name: properties.name || key,
        hwaddr: properties.hwaddr,
        inet: properties.ip,
        inet6: properties.ip6,
      }];
    }
    return [];
  });
  return summarizeNetwork(interfaces, status, "configuration");
}

function safeConfig(config = {}) {
  const allowed = ["name", "description", "tags", "onboot", "protection", "cores", "sockets", "memory", "ostype", "arch", "bios", "agent", "startup", "hostname", "unprivileged"];
  return Object.fromEntries(allowed.filter((key) => config[key] !== undefined).map((key) => [key, config[key]]));
}

function safeSnapshotName(value) {
  const name = String(value || "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/.test(name)) {
    throw new ProxmoxError("Snapshot name is invalid", { code: "invalid_snapshot_name", status: 400 });
  }
  return name;
}

function normalizeSnapshots(snapshots) {
  return (Array.isArray(snapshots) ? snapshots : [])
    .filter((snapshot) => snapshot?.name && snapshot.name !== "current")
    .map((snapshot) => ({
      name: String(snapshot.name),
      description: String(snapshot.description || "").slice(0, 500),
      parent: snapshot.parent ? String(snapshot.parent) : null,
      createdAt: snapshot.snaptime ? Number(snapshot.snaptime) * 1000 : null,
      includesMemory: Boolean(snapshot.vmstate),
    }))
    .sort((left, right) => Number(right.createdAt || 0) - Number(left.createdAt || 0));
}

export class ProxmoxClient {
  constructor({ baseUrl, tokenId, tokenSecret, timeoutMs = 12_000, fetchImpl = fetch } = {}) {
    this.baseUrl = baseUrl?.replace(/\/+$/, "");
    this.tokenId = tokenId;
    this.tokenSecret = tokenSecret;
    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl;
  }

  get configured() {
    return Boolean(this.baseUrl && this.tokenId && this.tokenSecret);
  }

  async request(path, options = {}) {
    if (!this.configured) throw new ProxmoxError("Proxmox API is not configured for this cluster", { code: "proxmox_not_configured", status: 503 });
    let target;
    try {
      target = new URL(`${this.baseUrl}/api2/json${path}`);
    } catch {
      throw new ProxmoxError("The configured Proxmox URL is invalid", { code: "proxmox_invalid_url", status: 503 });
    }
    if (target.protocol !== "https:") {
      throw new ProxmoxError("The Proxmox URL must use HTTPS", { code: "proxmox_https_required", status: 503 });
    }
    let response;
    try {
      response = await this.fetchImpl(target, {
        ...options,
        redirect: "error",
        signal: options.signal || AbortSignal.timeout(this.timeoutMs),
        headers: {
          Authorization: `PVEAPIToken=${this.tokenId}=${this.tokenSecret}`,
          "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
          ...options.headers,
        },
      });
    } catch (error) {
      if (error instanceof ProxmoxError) throw error;
      if (error?.cause instanceof ProxmoxError) throw error.cause;
      if (error?.name === "TimeoutError" || error?.name === "AbortError" || error?.code === "UND_ERR_CONNECT_TIMEOUT") {
        throw new ProxmoxError("Proxmox did not respond before the timeout", { code: "proxmox_timeout", status: 504 });
      }
      throw new ProxmoxError("Nimbus could not establish a secure connection to Proxmox", { code: "proxmox_unreachable", status: 502 });
    }

    if (!response.ok) {
      const mapping = {
        401: ["Proxmox rejected the configured API token", "proxmox_auth_failed", 502],
        403: ["The Proxmox token lacks a required permission", "proxmox_permission_denied", 502],
        404: ["The requested Proxmox resource was not found", "proxmox_resource_not_found", 502],
      }[response.status];
      const [message, code, status] = mapping || ["Proxmox returned an unexpected response", "proxmox_upstream_error", 502];
      throw new ProxmoxError(message, { code, status, upstreamStatus: response.status });
    }

    let body;
    try {
      body = await response.json();
    } catch {
      throw new ProxmoxError("Proxmox returned malformed JSON", { code: "proxmox_invalid_response", status: 502 });
    }
    if (!body || !("data" in body)) throw new ProxmoxError("Proxmox returned an incomplete response", { code: "proxmox_invalid_response", status: 502 });
    return body.data;
  }

  async listVirtualMachines() {
    const resources = await this.request("/cluster/resources?type=vm");
    if (!Array.isArray(resources)) throw new ProxmoxError("Proxmox returned an invalid resource list", { code: "proxmox_invalid_response" });
    const checkedAt = Date.now();
    const inventory = resources
      .filter((vm) => ["qemu", "lxc"].includes(vm?.type) && vm?.vmid !== undefined && vm?.node)
      .map((vm) => {
        const reportedUsedBytes = finite(vm.disk);
        const storageUsageAvailable = vm.type === "lxc" || reportedUsedBytes > 0;
        return {
          id: `${vm.type}-${vm.vmid}`,
          vmid: vm.vmid,
          name: vm.name || `vm-${vm.vmid}`,
          node: vm.node,
          type: vm.type,
          status: vm.status,
          vcpu: finite(vm.maxcpu),
          memory: round(finite(vm.maxmem) / 1024 / 1024 / 1024, 1),
          memoryUsed: round(finite(vm.mem) / 1024 / 1024 / 1024, 1),
          cpu: Math.round(finite(vm.cpu) * 100),
          uptime: finite(vm.uptime),
          storage: round(finite(vm.maxdisk) / 1024 / 1024 / 1024, 1),
          storageUsed: storageUsageAvailable ? round(reportedUsedBytes / 1024 / 1024 / 1024, 1) : null,
          ip: null,
          metadata: {
            haState: vm.hastate || null,
            template: Boolean(vm.template),
            tags: vm.tags || "",
            storageUsage: storageUsageAvailable
              ? { available: true, source: vm.type === "lxc" ? "proxmox_lxc" : "proxmox_inventory", collectedAt: checkedAt }
              : { available: false, source: null, checkedAt, reason: vm.status === "running" ? "guest_agent_unavailable" : "guest_stopped" },
          },
          color: "purple",
        };
      });
    return mapLimit(inventory, 4, async (vm) => {
      if (vm.type !== "qemu" || vm.status !== "running") return vm;
      try {
        const payload = await this.request(`/nodes/${encodeURIComponent(vm.node)}/qemu/${vm.vmid}/agent/get-fsinfo`);
        const usage = normalizeQemuFilesystemUsage(payload);
        if (!usage) return vm;
        return {
          ...vm,
          storage: Math.max(vm.storage, round(usage.totalBytes / 1024 / 1024 / 1024, 1)),
          storageUsed: round(usage.usedBytes / 1024 / 1024 / 1024, 1),
          metadata: {
            ...vm.metadata,
            storageUsage: {
              available: true,
              source: "qemu_guest_agent",
              filesystems: usage.filesystems,
              collectedAt: checkedAt,
            },
          },
        };
      } catch (error) {
        return {
          ...vm,
          metadata: {
            ...vm.metadata,
            storageUsage: {
              available: false,
              source: null,
              checkedAt,
              reason: error?.code === "proxmox_permission_denied" ? "permission_required" : "guest_agent_unavailable",
            },
          },
        };
      }
    });
  }

  async getOperationsMetrics() {
    const [nodeResult, clusterStorageResult] = await Promise.allSettled([
      this.request("/cluster/resources?type=node"),
      this.request("/cluster/resources?type=storage"),
    ]);
    const errors = {};
    let nodes = null;
    let storages = null;
    let storagesAuthoritative = false;

    if (nodeResult.status === "fulfilled") {
      if (!Array.isArray(nodeResult.value)) {
        errors.nodes = "proxmox_invalid_response";
      } else {
        nodes = nodeResult.value.filter((node) => node?.node).map((node) => {
          const memoryUsedBytes = finite(node.mem);
          const memoryTotalBytes = finite(node.maxmem);
          const rootUsedBytes = finite(node.disk);
          const rootTotalBytes = finite(node.maxdisk);
          return {
            node: String(node.node),
            status: String(node.status || "unknown").toLowerCase(),
            cpuPercent: round(finite(node.cpu) * 100, 1),
            cpuCores: round(finite(node.maxcpu), 1),
            memoryUsedBytes,
            memoryTotalBytes,
            memoryPercent: percent(memoryUsedBytes, memoryTotalBytes),
            rootUsedBytes,
            rootTotalBytes,
            rootPercent: percent(rootUsedBytes, rootTotalBytes),
            uptime: finite(node.uptime),
          };
        });
      }
    } else {
      errors.nodes = nodeResult.reason?.code || "proxmox_request_failed";
    }

    if (nodes?.length) {
      const nodeStorageResults = await mapLimit(nodes, 4, async ({ node }) => {
        try {
          const value = await this.request(`/nodes/${encodeURIComponent(node)}/storage?enabled=1`);
          return Array.isArray(value)
            ? { ok: true, node, value }
            : { ok: false, code: "proxmox_invalid_response" };
        } catch (error) {
          return { ok: false, code: error?.code || "proxmox_request_failed" };
        }
      });
      if (nodeStorageResults.every((result) => result.ok)) {
        storages = uniqueOperationsStorages(nodeStorageResults.flatMap((result) =>
          result.value.map((storage) => normalizeOperationsStorage(storage, result.node))))
          .filter((storage) => storage.status !== "disabled");
        storagesAuthoritative = true;
      }
    }

    // Older Proxmox releases and narrowly scoped tokens may not allow the
    // per-node inventory endpoint. The cluster resource list remains a safe
    // fallback, but it is not preferred because it can omit node-local stores.
    if (storages === null) {
      if (clusterStorageResult.status === "fulfilled" && Array.isArray(clusterStorageResult.value)) {
        storages = uniqueOperationsStorages(clusterStorageResult.value.map((storage) => normalizeOperationsStorage(storage)))
          .filter((storage) => storage.status !== "disabled");
      } else if (clusterStorageResult.status === "fulfilled") {
        errors.storages = "proxmox_invalid_response";
      } else {
        errors.storages = clusterStorageResult.reason?.code || "proxmox_request_failed";
      }
    }

    return {
      nodes,
      storages,
      storagesAuthoritative,
      errors,
      collectedAt: Date.now(),
    };
  }

  async testConnection() {
    const [version, nodes] = await Promise.all([this.request("/version"), this.request("/nodes")]);
    return {
      version: version?.version || null,
      release: version?.release || null,
      nodes: Array.isArray(nodes) ? nodes.map((node) => ({ name: node.node, status: node.status })) : [],
    };
  }

  async getNetwork(vm) {
    const configuredFallback = async (status) => {
      try {
        const config = await this.request(`/nodes/${encodeURIComponent(vm.node)}/${vm.type}/${vm.vmid}/config?current=1`);
        const network = configuredNetwork(config, vm.type, status);
        return network.addresses.length ? network : null;
      } catch {
        return null;
      }
    };
    if (vm.status !== "running") {
      return (await configuredFallback("stopped"))
        || { status: "stopped", source: null, primaryIp: null, addresses: [], interfaces: [] };
    }
    let unavailableStatus = vm.type === "lxc" ? "network_unavailable" : "guest_agent_unavailable";
    try {
      if (vm.type === "lxc") {
        const result = await this.request(`/nodes/${encodeURIComponent(vm.node)}/lxc/${vm.vmid}/interfaces`);
        const live = summarizeNetwork(Array.isArray(result) ? result : [], "available", "guest");
        if (live.addresses.length) return live;
      } else {
        const result = await this.request(`/nodes/${encodeURIComponent(vm.node)}/qemu/${vm.vmid}/agent/network-get-interfaces`);
        const live = summarizeNetwork(Array.isArray(result?.result) ? result.result : [], "available", "guest_agent");
        if (live.addresses.length) return live;
      }
    } catch (error) {
      unavailableStatus = error.code === "proxmox_permission_denied"
        ? "permission_required"
        : vm.type === "lxc" ? "network_unavailable" : "guest_agent_unavailable";
    }
    return (await configuredFallback("configured"))
      || { status: unavailableStatus, source: null, primaryIp: null, addresses: [], interfaces: [] };
  }

  async getNetworks(instances) {
    const rows = await mapLimit(instances, 5, async (vm) => {
      try {
        return { id: vm.id, ...(await this.getNetwork(vm)) };
      } catch {
        return { id: vm.id, status: "unavailable", source: null, primaryIp: null, addresses: [], interfaces: [] };
      }
    });
    return Object.fromEntries(rows.map((entry) => [entry.id, entry]));
  }

  async getRrd(vm, timeframe = "day") {
    const valid = new Set(["hour", "day", "week", "month", "year"]);
    if (!valid.has(timeframe)) throw new ProxmoxError("Unsupported history timeframe", { code: "invalid_timeframe", status: 400 });
    const result = await this.request(`/nodes/${encodeURIComponent(vm.node)}/${vm.type}/${vm.vmid}/rrddata?timeframe=${timeframe}&cf=AVERAGE`);
    return Array.isArray(result) ? result : [];
  }

  async getHistory(instances, timeframe = "day") {
    const datasets = await mapLimit(instances, 4, async (vm) => {
      try { return { vm, points: await this.getRrd(vm, timeframe), ok: true }; }
      catch (error) { return { vm, points: [], ok: false, error: error.code || "proxmox_request_failed" }; }
    });
    const buckets = new Map();
    for (const { vm, points } of datasets) {
      for (const point of points) {
        const timestamp = finite(point.time);
        if (!timestamp) continue;
        const bucket = buckets.get(timestamp) || { timestamp, cpuWeighted: 0, cpuWeight: 0, memoryUsed: 0, memoryTotal: 0, netIn: 0, netOut: 0 };
        if (Number.isFinite(Number(point.cpu))) {
          const weight = Math.max(1, finite(point.maxcpu, vm.vcpu || 1));
          bucket.cpuWeighted += finite(point.cpu) * weight;
          bucket.cpuWeight += weight;
        }
        bucket.memoryUsed += finite(point.mem);
        bucket.memoryTotal += finite(point.maxmem);
        bucket.netIn += finite(point.netin);
        bucket.netOut += finite(point.netout);
        buckets.set(timestamp, bucket);
      }
    }
    const all = [...buckets.values()].sort((a, b) => a.timestamp - b.timestamp).map((point) => ({
      timestamp: point.timestamp * 1000,
      cpu: round(point.cpuWeight ? point.cpuWeighted / point.cpuWeight * 100 : 0, 1),
      memory: round(point.memoryTotal ? point.memoryUsed / point.memoryTotal * 100 : 0, 1),
      netIn: Math.round(point.netIn),
      netOut: Math.round(point.netOut),
    }));
    const stride = Math.max(1, Math.ceil(all.length / 120));
    const points = all.filter((_, index) => index % stride === 0 || index === all.length - 1);
    const sampledInstances = datasets.filter((dataset) => dataset.ok).length;
    const reason = sampledInstances === 0
      ? (instances.length ? "history_access_unavailable" : "no_instances")
      : (points.length > 1 ? null : "insufficient_history_data");
    return {
      timeframe,
      points,
      available: points.length > 1,
      partial: sampledInstances < instances.length,
      sampledInstances,
      totalInstances: instances.length,
      ...(reason ? { reason } : {}),
    };
  }

  async getInstanceDetails(vm) {
    const [config, network, snapshots] = await Promise.all([
      this.request(`/nodes/${encodeURIComponent(vm.node)}/${vm.type}/${vm.vmid}/config?current=1`).then(safeConfig),
      this.getNetwork(vm),
      this.listSnapshots(vm).catch(() => []),
    ]);
    return {
      instance: vm,
      config,
      network,
      snapshots,
    };
  }

  async listSnapshots(vm) {
    const snapshots = await this.request(`/nodes/${encodeURIComponent(vm.node)}/${vm.type}/${vm.vmid}/snapshot`);
    return normalizeSnapshots(snapshots);
  }

  async listIsoStorageCandidates() {
    const nodes = await this.request("/nodes");
    const nodeNames = (Array.isArray(nodes) ? nodes : []).filter((node) => node?.node).map((node) => node.node);
    const responses = await mapLimit(nodeNames, 4, async (node) => {
      try {
        const storages = await this.request(`/nodes/${encodeURIComponent(node)}/storage?content=iso&enabled=1`);
        return (Array.isArray(storages) ? storages : []).filter((storage) => {
          const content = String(storage.content || "").split(",").map((entry) => entry.trim());
          return storage.storage && (!storage.content || content.includes("iso")) && storage.active !== 0 && storage.enabled !== 0;
        }).map((storage) => ({ node, ...storage }));
      } catch {
        return [];
      }
    });
    const grouped = new Map();
    for (const storage of responses.flat()) {
      const current = grouped.get(storage.storage) || {
        storageId: storage.storage,
        type: storage.type || storage.plugintype || "file",
        shared: Boolean(storage.shared),
        nodes: [],
        totalBytes: 0,
        availableBytes: 0,
      };
      current.shared ||= Boolean(storage.shared);
      current.nodes.push(storage.node);
      current.totalBytes = Math.max(current.totalBytes, finite(storage.total));
      current.availableBytes = Math.max(current.availableBytes, finite(storage.avail));
      grouped.set(storage.storage, current);
    }
    return [...grouped.values()].sort((left, right) => left.storageId.localeCompare(right.storageId));
  }

  async requireIsoStorage(node, storageId) {
    const storages = await this.request(`/nodes/${encodeURIComponent(node)}/storage?content=iso&enabled=1`);
    const storage = (Array.isArray(storages) ? storages : []).find((entry) => entry.storage === storageId);
    const content = String(storage?.content || "").split(",").map((entry) => entry.trim());
    if (!storage || (storage.content && !content.includes("iso")) || storage.active === 0 || storage.enabled === 0) {
      throw new ProxmoxError("The selected ISO storage is not active on this node", { code: "iso_storage_unavailable", status: 409 });
    }
    return {
      storageId,
      node,
      type: storage.type || storage.plugintype || "file",
      shared: Boolean(storage.shared),
      totalBytes: finite(storage.total),
      availableBytes: finite(storage.avail),
    };
  }

  async uploadIso({ node, storageId, fileName, source, expectedBytes, signal }) {
    const normalizedName = safeIsoFilename(fileName);
    const boundary = `----NimbusDirect${randomBytes(18).toString("hex")}`;
    const prefix = Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="content"\r\n\r\niso\r\n`
      + `--${boundary}\r\nContent-Disposition: form-data; name="filename"; filename="${normalizedName}"\r\n`
      + "Content-Type: application/octet-stream\r\n\r\n",
      "utf8",
    );
    const suffix = Buffer.from(`\r\n--${boundary}--\r\n`, "utf8");
    const hash = createHash("sha256");
    let receivedBytes = 0;
    const multipart = (async function* streamMultipart() {
      yield prefix;
      for await (const chunk of source) {
        receivedBytes += chunk.length;
        if (receivedBytes > expectedBytes) {
          throw new ProxmoxError("The upload exceeded its declared size", { code: "iso_upload_size_mismatch", status: 400 });
        }
        hash.update(chunk);
        yield chunk;
      }
      if (receivedBytes !== expectedBytes) {
        throw new ProxmoxError("The upload did not match its declared size", { code: "iso_upload_size_mismatch", status: 400 });
      }
      yield suffix;
    })();
    const result = await this.request(`/nodes/${encodeURIComponent(node)}/storage/${encodeURIComponent(storageId)}/upload`, {
      method: "POST",
      body: multipart,
      duplex: "half",
      signal,
      headers: {
        "Content-Type": `multipart/form-data; boundary=${boundary}`,
        "Content-Length": String(prefix.length + expectedBytes + suffix.length),
      },
    });
    return { result, bytes: receivedBytes, sha256: hash.digest("hex"), fileName: normalizedName };
  }

  async getQemuCdroms(vm) {
    if (vm.type !== "qemu") throw new ProxmoxError("ISO media is available only for QEMU virtual machines", { code: "iso_qemu_only", status: 400 });
    const config = await this.request(`/nodes/${encodeURIComponent(vm.node)}/qemu/${vm.vmid}/config?current=1`);
    return Object.entries(config || {}).filter(([key, value]) =>
      /^(ide|sata|scsi)\d+$/.test(key) && String(value).split(",").includes("media=cdrom"))
      .map(([slot, value]) => {
        const volumeId = String(value).split(",")[0];
        return { slot, volumeId: volumeId === "none" ? null : volumeId };
      });
  }

  async mountIso(vm, volumeId) {
    if (vm.type !== "qemu") throw new ProxmoxError("ISO media is available only for QEMU virtual machines", { code: "iso_qemu_only", status: 400 });
    const config = await this.request(`/nodes/${encodeURIComponent(vm.node)}/qemu/${vm.vmid}/config?current=1`);
    const cdroms = Object.entries(config || {}).filter(([key, value]) =>
      /^(ide|sata|scsi)\d+$/.test(key) && String(value).split(",").includes("media=cdrom"));
    const occupied = cdroms.find(([, value]) => String(value).split(",")[0] !== "none");
    if (occupied) throw new ProxmoxError("A CD/DVD image is already mounted. Eject it first.", { code: "cdrom_in_use", status: 409 });
    const existingEmpty = cdroms.find(([, value]) => String(value).split(",")[0] === "none")?.[0];
    const candidates = ["ide2", "sata5", "sata4", "ide3"];
    const slot = existingEmpty || candidates.find((candidate) => config?.[candidate] === undefined);
    if (!slot) throw new ProxmoxError("No free virtual CD/DVD slot is available", { code: "cdrom_slot_unavailable", status: 409 });
    const body = new URLSearchParams({ [slot]: `${volumeId},media=cdrom` });
    await this.request(`/nodes/${encodeURIComponent(vm.node)}/qemu/${vm.vmid}/config`, { method: "PUT", body });
    return { slot, volumeId };
  }

  async ejectIso(vm, { slot, volumeId }) {
    if (vm.type !== "qemu") throw new ProxmoxError("ISO media is available only for QEMU virtual machines", { code: "iso_qemu_only", status: 400 });
    if (!/^(ide|sata|scsi)\d+$/.test(String(slot))) throw new ProxmoxError("The recorded CD/DVD slot is invalid", { code: "cdrom_slot_invalid", status: 409 });
    const config = await this.request(`/nodes/${encodeURIComponent(vm.node)}/qemu/${vm.vmid}/config?current=1`);
    const currentVolume = String(config?.[slot] || "").split(",")[0];
    if (currentVolume !== volumeId) throw new ProxmoxError("The VM CD/DVD configuration changed outside Nimbus", { code: "cdrom_state_changed", status: 409 });
    const body = new URLSearchParams({ [slot]: "none,media=cdrom" });
    await this.request(`/nodes/${encodeURIComponent(vm.node)}/qemu/${vm.vmid}/config`, { method: "PUT", body });
    return { slot, ejected: true };
  }

  async prepareIsoBootOnce(vm, { slot, volumeId }) {
    if (vm.type !== "qemu") throw new ProxmoxError("ISO boot is available only for QEMU virtual machines", { code: "iso_qemu_only", status: 400 });
    if (!/^(ide|sata|scsi)\d+$/.test(String(slot))) {
      throw new ProxmoxError("The recorded CD/DVD slot is invalid", { code: "cdrom_slot_invalid", status: 409 });
    }
    const config = await this.request(`/nodes/${encodeURIComponent(vm.node)}/qemu/${vm.vmid}/config`);
    const cdrom = String(config?.[slot] || "").split(",");
    if (cdrom[0] !== volumeId || !cdrom.includes("media=cdrom")) {
      throw new ProxmoxError("The mounted ISO changed outside Nimbus", { code: "cdrom_state_changed", status: 409 });
    }
    const originalBoot = config?.boot === undefined || config?.boot === null ? null : String(config.boot);
    const devices = [String(slot), ...bootableQemuDevices(config).filter((device) => device !== slot)];
    const armedBoot = `order=${devices.join(";")}`;
    return { slot: String(slot), originalBoot, armedBoot };
  }

  async applyIsoBootOnce(vm, armedBoot) {
    if (vm.type !== "qemu") throw new ProxmoxError("ISO boot is available only for QEMU virtual machines", { code: "iso_qemu_only", status: 400 });
    if (!String(armedBoot || "").startsWith("order=") || String(armedBoot).length > 2048) {
      throw new ProxmoxError("The generated boot order is invalid", { code: "invalid_boot_order", status: 409 });
    }
    const body = new URLSearchParams({ boot: armedBoot });
    await this.request(`/nodes/${encodeURIComponent(vm.node)}/qemu/${vm.vmid}/config`, { method: "PUT", body });
  }

  async armIsoBootOnce(vm, mount) {
    const prepared = await this.prepareIsoBootOnce(vm, mount);
    await this.applyIsoBootOnce(vm, prepared.armedBoot);
    return prepared;
  }

  async restoreIsoBootOnce(vm, { originalBoot = null, armedBoot }) {
    if (vm.type !== "qemu") throw new ProxmoxError("ISO boot is available only for QEMU virtual machines", { code: "iso_qemu_only", status: 400 });
    const config = await this.request(`/nodes/${encodeURIComponent(vm.node)}/qemu/${vm.vmid}/config`);
    const currentBoot = config?.boot === undefined || config?.boot === null ? null : String(config.boot);
    if (currentBoot === originalBoot) return { restored: true, alreadyRestored: true };
    if (currentBoot !== armedBoot) {
      throw new ProxmoxError("The VM boot order changed outside Nimbus", { code: "boot_order_changed", status: 409 });
    }
    const body = originalBoot === null
      ? new URLSearchParams({ delete: "boot" })
      : new URLSearchParams({ boot: originalBoot });
    await this.request(`/nodes/${encodeURIComponent(vm.node)}/qemu/${vm.vmid}/config`, { method: "PUT", body });
    return { restored: true, alreadyRestored: false };
  }

  async deleteIso({ node, storageId, volumeId }) {
    return this.request(`/nodes/${encodeURIComponent(node)}/storage/${encodeURIComponent(storageId)}/content/${encodeURIComponent(volumeId)}`, { method: "DELETE" });
  }

  async getBackups(instances, storageValue) {
    const storageIds = parseStorageList(storageValue);
    if (!storageIds.length) return { configured: false, available: false, items: [], coverage: 0, lastBackupAt: null };
    let storageResources;
    try {
      storageResources = await this.request("/cluster/resources?type=storage");
    } catch (error) {
      return { configured: true, available: false, reason: error.code, items: [], coverage: 0, lastBackupAt: null };
    }
    const targets = [];
    const seenTargets = new Set();
    for (const resource of Array.isArray(storageResources) ? storageResources : []) {
      if (!storageIds.includes(resource.storage) || !resource.node) continue;
      const key = `${resource.node}/${resource.storage}`;
      if (!seenTargets.has(key)) { seenTargets.add(key); targets.push({ node: resource.node, storage: resource.storage }); }
    }
    if (!targets.length) return { configured: true, available: false, reason: "storage_not_visible", items: [], coverage: 0, lastBackupAt: null };
    const allowedVmids = new Set(instances.map((vm) => String(vm.vmid)));
    const queries = targets.flatMap((target) => instances.map((vm) => ({ ...target, vmid: vm.vmid, resourceId: vm.id, instanceName: vm.name })));
    const responses = await mapLimit(queries, 4, async (query) => {
      try {
        const data = await this.request(`/nodes/${encodeURIComponent(query.node)}/storage/${encodeURIComponent(query.storage)}/content?content=backup&vmid=${query.vmid}`);
        return {
          ok: true,
          items: (Array.isArray(data) ? data : []).map((backup) => ({ ...backup, storage: query.storage, node: query.node, resourceId: query.resourceId, instanceName: query.instanceName })),
        };
      } catch (error) {
        return { ok: false, error: error.code || "proxmox_request_failed", items: [] };
      }
    });
    const successfulResponses = responses.filter((entry) => entry.ok);
    if (!successfulResponses.length) {
      return {
        configured: true,
        available: false,
        reason: responses[0]?.error || "backup_access_denied",
        items: [],
        coverage: 0,
        lastBackupAt: null,
      };
    }
    const deduped = new Map();
    for (const backup of successfulResponses.flatMap((entry) => entry.items)) {
      if (!allowedVmids.has(String(backup.vmid))) continue;
      const key = backup.volid || `${backup.storage}/${backup.vmid}/${backup.ctime}`;
      if (!deduped.has(key)) deduped.set(key, {
        id: key,
        volid: backup.volid || null,
        vmid: backup.vmid,
        resourceId: backup.resourceId,
        instanceName: backup.instanceName,
        storage: backup.storage,
        format: backup.format || null,
        size: finite(backup.size ?? backup["approximate-size"]),
        createdAt: backup.ctime ? backup.ctime * 1000 : null,
        protected: Boolean(backup.protected),
        verified: backup.verification?.state || null,
      });
    }
    const items = [...deduped.values()].sort((a, b) => finite(b.createdAt) - finite(a.createdAt));
    const covered = new Set(items.map((item) => String(item.vmid)));
    return {
      configured: true,
      available: true,
      partial: successfulResponses.length < responses.length,
      items,
      coverage: instances.length ? Math.round(covered.size / instances.length * 100) : 0,
      coveredInstances: covered.size,
      totalInstances: instances.length,
      lastBackupAt: items[0]?.createdAt || null,
    };
  }

  async performAction(vm, action) {
    const actionMap = {
      start: "start", stop: "stop", shutdown: "shutdown", reboot: "reboot", reset: "reset",
      suspend: "suspend", resume: "resume",
    };
    const endpoint = actionMap[action];
    if (!endpoint) throw new ProxmoxError("Unsupported instance action", { code: "invalid_action", status: 400 });
    return this.request(`/nodes/${encodeURIComponent(vm.node)}/${vm.type}/${vm.vmid}/status/${endpoint}`, { method: "POST", body: "" });
  }

  async createSnapshot(vm, { name, description = "", includeMemory = false }) {
    const snapname = safeSnapshotName(name);
    if (includeMemory && vm.type !== "qemu") {
      throw new ProxmoxError("Memory state is available only for QEMU snapshots", { code: "snapshot_memory_qemu_only", status: 400 });
    }
    const body = new URLSearchParams({ snapname, description: String(description).trim().slice(0, 500) });
    if (vm.type === "qemu") body.set("vmstate", includeMemory ? "1" : "0");
    return this.request(`/nodes/${encodeURIComponent(vm.node)}/${vm.type}/${vm.vmid}/snapshot`, { method: "POST", body });
  }

  async restoreSnapshot(vm, name) {
    return this.request(`/nodes/${encodeURIComponent(vm.node)}/${vm.type}/${vm.vmid}/snapshot/${encodeURIComponent(safeSnapshotName(name))}/rollback`, { method: "POST", body: "" });
  }

  async deleteSnapshot(vm, name) {
    return this.request(`/nodes/${encodeURIComponent(vm.node)}/${vm.type}/${vm.vmid}/snapshot/${encodeURIComponent(safeSnapshotName(name))}`, { method: "DELETE" });
  }

  async updateConfig(vm, values) {
    const allowlist = vm.type === "qemu"
      ? new Set(["cores", "memory", "onboot", "description", "name"])
      : new Set(["cores", "memory", "onboot", "description", "hostname"]);
    const safe = Object.fromEntries(Object.entries(values || {}).filter(([key]) => allowlist.has(key)));
    if (!Object.keys(safe).length) throw new ProxmoxError("No supported configuration values were supplied", { code: "invalid_config_change", status: 400 });
    const body = new URLSearchParams(Object.entries(safe).map(([key, value]) => [key, String(value)]));
    return this.request(`/nodes/${encodeURIComponent(vm.node)}/${vm.type}/${vm.vmid}/config`, { method: "PUT", body });
  }

  async createConsoleTicket(vm) {
    let consoleType = vm.type === "lxc" ? "terminal" : "graphical";
    let serial = null;
    if (vm.type === "qemu") {
      try {
        const config = await this.request(`/nodes/${encodeURIComponent(vm.node)}/qemu/${vm.vmid}/config?current=1`);
        serial = qemuSerialDisplay(config?.vga);
        if (serial) consoleType = "terminal";
      } catch {
        // A regular QEMU display remains safely usable through noVNC when
        // display metadata is unavailable to a narrowly scoped API token.
      }
    }
    const body = new URLSearchParams();
    if (consoleType === "graphical") body.set("websocket", "1");
    if (serial) body.set("serial", serial);
    const proxy = consoleType === "terminal" ? "termproxy" : "vncproxy";
    const result = await this.request(`/nodes/${encodeURIComponent(vm.node)}/${vm.type}/${vm.vmid}/${proxy}`, { method: "POST", body });
    if (!result?.ticket || !result?.port) throw new ProxmoxError("Proxmox returned an invalid console ticket", { code: "proxmox_console_invalid", status: 502 });
    return {
      ticket: result.ticket,
      port: Number(result.port),
      user: result.user || null,
      consoleType,
      serial,
    };
  }

  async getTaskStatus(node, upid) {
    return this.request(`/nodes/${encodeURIComponent(node)}/tasks/${encodeURIComponent(upid)}/status`);
  }
}
