/**
 * Server-side Proxmox VE client. Credentials never leave the application
 * process. Every caller must first scope resources to the authenticated
 * panel's local customer-resource assignment ledger. No Proxmox pools are
 * used for tenancy.
 */

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

function parseStorageList(value) {
  return [...new Set(String(value || "").split(",").map((entry) => entry.trim()).filter(Boolean))];
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
  return value && value !== "0.0.0.0" && value !== "127.0.0.1" && value !== "::" && value !== "::1" && !value.startsWith("169.254.") && !value.toLowerCase().startsWith("fe80:");
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

function summarizeNetwork(interfaces, status = "available") {
  const safeInterfaces = interfaces.map(normalizeInterface).filter((entry) => entry.name !== "lo" || entry.addresses.length);
  const addresses = safeInterfaces.flatMap((entry) => entry.addresses.map((address) => ({ ...address, interface: entry.name })));
  return {
    status,
    primaryIp: addresses.find((entry) => entry.family === "ipv4")?.address || addresses[0]?.address || null,
    addresses,
    interfaces: safeInterfaces,
  };
}

function safeConfig(config = {}) {
  const allowed = ["name", "description", "tags", "onboot", "protection", "cores", "sockets", "memory", "ostype", "arch", "bios", "agent", "startup", "hostname", "unprivileged"];
  return Object.fromEntries(allowed.filter((key) => config[key] !== undefined).map((key) => [key, config[key]]));
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
    return resources.filter((vm) => ["qemu", "lxc"].includes(vm?.type) && vm?.vmid !== undefined && vm?.node).map((vm) => ({
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
      storageUsed: round(finite(vm.disk) / 1024 / 1024 / 1024, 1),
      ip: null,
      metadata: { haState: vm.hastate || null, template: Boolean(vm.template), tags: vm.tags || "" },
      color: "purple",
    }));
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
    if (vm.status !== "running") return { status: "stopped", primaryIp: null, addresses: [], interfaces: [] };
    try {
      if (vm.type === "lxc") {
        const result = await this.request(`/nodes/${encodeURIComponent(vm.node)}/lxc/${vm.vmid}/interfaces`);
        return summarizeNetwork(Array.isArray(result) ? result : []);
      }
      const result = await this.request(`/nodes/${encodeURIComponent(vm.node)}/qemu/${vm.vmid}/agent/network-get-interfaces`);
      return summarizeNetwork(Array.isArray(result?.result) ? result.result : []);
    } catch (error) {
      if (error.code === "proxmox_permission_denied") return { status: "permission_required", primaryIp: null, addresses: [], interfaces: [] };
      return { status: "guest_agent_unavailable", primaryIp: null, addresses: [], interfaces: [] };
    }
  }

  async getNetworks(instances) {
    const rows = await mapLimit(instances, 5, async (vm) => ({ id: vm.id, ...(await this.getNetwork(vm)) }));
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
      this.request(`/nodes/${encodeURIComponent(vm.node)}/${vm.type}/${vm.vmid}/snapshot`).catch(() => []),
    ]);
    return {
      instance: vm,
      config,
      network,
      snapshots: (Array.isArray(snapshots) ? snapshots : []).filter((snapshot) => snapshot.name !== "current").map((snapshot) => ({
        name: snapshot.name,
        description: snapshot.description || "",
        parent: snapshot.parent || null,
        createdAt: snapshot.snaptime ? snapshot.snaptime * 1000 : null,
        includesMemory: Boolean(snapshot.vmstate),
      })),
    };
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
    const snapname = String(name || "").trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/.test(snapname)) {
      throw new ProxmoxError("Snapshot name is invalid", { code: "invalid_snapshot_name", status: 400 });
    }
    const body = new URLSearchParams({ snapname, description: String(description).slice(0, 500), vmstate: includeMemory ? "1" : "0" });
    return this.request(`/nodes/${encodeURIComponent(vm.node)}/${vm.type}/${vm.vmid}/snapshot`, { method: "POST", body });
  }

  async restoreSnapshot(vm, name) {
    return this.request(`/nodes/${encodeURIComponent(vm.node)}/${vm.type}/${vm.vmid}/snapshot/${encodeURIComponent(name)}/rollback`, { method: "POST", body: "" });
  }

  async deleteSnapshot(vm, name) {
    return this.request(`/nodes/${encodeURIComponent(vm.node)}/${vm.type}/${vm.vmid}/snapshot/${encodeURIComponent(name)}`, { method: "DELETE" });
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
    const body = new URLSearchParams({ websocket: "1" });
    const result = await this.request(`/nodes/${encodeURIComponent(vm.node)}/${vm.type}/${vm.vmid}/vncproxy`, { method: "POST", body });
    if (!result?.ticket || !result?.port) throw new ProxmoxError("Proxmox returned an invalid console ticket", { code: "proxmox_console_invalid", status: 502 });
    return { ticket: result.ticket, port: Number(result.port), user: result.user || null };
  }

  async getTaskStatus(node, upid) {
    return this.request(`/nodes/${encodeURIComponent(node)}/tasks/${encodeURIComponent(upid)}/status`);
  }
}
