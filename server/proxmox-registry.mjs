import { ProxmoxClient } from "./proxmox.mjs";

/** Builds server-only clients from encrypted cluster credentials in the store. */
export class ProxmoxRegistry {
  constructor({ getConnection, timeoutMs = 12_000, fetchImpl = fetch }) {
    this.getConnection = getConnection;
    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl;
  }

  forCluster(clusterId) {
    const connection = this.getConnection(clusterId);
    return new ProxmoxClient({ ...(connection || {}), timeoutMs: this.timeoutMs, fetchImpl: this.fetchImpl });
  }
}
