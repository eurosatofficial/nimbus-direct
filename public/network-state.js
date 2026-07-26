export function mergeNetworkAddresses(resources = [], networkPayload = null) {
  const networks = networkPayload?.networks;
  if (!networks || typeof networks !== "object") return resources;
  for (const resource of resources) {
    if (!Object.hasOwn(networks, resource.id)) continue;
    const network = networks[resource.id] || {};
    const primaryIp = typeof network.primaryIp === "string" ? network.primaryIp.trim() : "";
    resource.ip = primaryIp || null;
    resource.networkStatus = network.status || null;
    resource.networkSource = network.source || null;
  }
  return resources;
}
