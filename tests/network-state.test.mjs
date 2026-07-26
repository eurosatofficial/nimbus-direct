import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { mergeNetworkAddresses } from "../public/network-state.js";

test("cached network discovery is reapplied to replacement dashboard resources", () => {
  const resources = [
    { id: "production:lxc:101", ip: null },
    { id: "production:qemu:201", ip: null },
  ];
  const network = {
    networks: {
      "production:lxc:101": { status: "available", source: "configuration", primaryIp: "10.0.0.101" },
      "production:qemu:201": { status: "available", source: "guest-agent", primaryIp: "10.0.0.201" },
    },
  };
  assert.equal(mergeNetworkAddresses(resources, network), resources);
  assert.equal(resources[0].ip, "10.0.0.101");
  assert.equal(resources[0].networkSource, "configuration");
  assert.equal(resources[1].ip, "10.0.0.201");
  assert.equal(resources[1].networkStatus, "available");
});

test("fresh discovery clears a stale address but leaves resources absent from the response untouched", () => {
  const resources = [
    { id: "production:qemu:201", ip: "10.0.0.201" },
    { id: "production:qemu:202", ip: "10.0.0.202" },
  ];
  mergeNetworkAddresses(resources, {
    networks: {
      "production:qemu:201": { status: "unavailable", source: "guest-agent", primaryIp: null },
    },
  });
  assert.equal(resources[0].ip, null);
  assert.equal(resources[0].networkStatus, "unavailable");
  assert.equal(resources[1].ip, "10.0.0.202");
});

test("dashboard loading automatically schedules address discovery and rerenders instance views", async () => {
  const source = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const dashboardStart = source.indexOf("async function loadDashboard()");
  const dashboardEnd = source.indexOf("async function loadNotifications()", dashboardStart);
  const dashboardLoader = source.slice(dashboardStart, dashboardEnd);
  assert.match(dashboardLoader, /mergeNetworkAddresses\(state\.dashboard\.resources, state\.network\)/);
  assert.match(dashboardLoader, /scheduleNetworkDiscovery\(\)/);
  assert.match(source, /\["overview", "instances", "network"\]\.includes\(state\.currentView\)/);
  assert.match(source, /return networkLoading && !known \? "Discovering…" : "Unavailable"/);
});
