-- Nimbus Direct Operations Center: persistent health telemetry and incident lifecycle.
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS operations_collection_status (
  cluster_id TEXT PRIMARY KEY REFERENCES proxmox_clusters(id) ON DELETE CASCADE,
  nodes_available INTEGER NOT NULL DEFAULT 0,
  storages_available INTEGER NOT NULL DEFAULT 0,
  nodes_error TEXT,
  storages_error TEXT,
  collected_at INTEGER,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS operations_node_metrics (
  cluster_id TEXT NOT NULL REFERENCES proxmox_clusters(id) ON DELETE CASCADE,
  node TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unknown',
  cpu_percent REAL NOT NULL DEFAULT 0,
  cpu_cores REAL NOT NULL DEFAULT 0,
  memory_used_bytes INTEGER NOT NULL DEFAULT 0,
  memory_total_bytes INTEGER NOT NULL DEFAULT 0,
  memory_percent REAL NOT NULL DEFAULT 0,
  root_used_bytes INTEGER NOT NULL DEFAULT 0,
  root_total_bytes INTEGER NOT NULL DEFAULT 0,
  root_percent REAL NOT NULL DEFAULT 0,
  uptime INTEGER NOT NULL DEFAULT 0,
  last_seen_at INTEGER,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(cluster_id,node)
) STRICT;

CREATE TABLE IF NOT EXISTS operations_storage_metrics (
  cluster_id TEXT NOT NULL REFERENCES proxmox_clusters(id) ON DELETE CASCADE,
  node TEXT NOT NULL,
  storage_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unknown',
  storage_type TEXT NOT NULL DEFAULT 'unknown',
  shared INTEGER NOT NULL DEFAULT 0,
  content TEXT NOT NULL DEFAULT '',
  used_bytes INTEGER NOT NULL DEFAULT 0,
  total_bytes INTEGER NOT NULL DEFAULT 0,
  available_bytes INTEGER NOT NULL DEFAULT 0,
  usage_percent REAL NOT NULL DEFAULT 0,
  last_seen_at INTEGER,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(cluster_id,node,storage_id)
) STRICT;

CREATE TABLE IF NOT EXISTS operations_incidents (
  id TEXT PRIMARY KEY,
  dedup_key TEXT NOT NULL UNIQUE,
  cluster_id TEXT REFERENCES proxmox_clusters(id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  source_type TEXT NOT NULL CHECK(source_type IN ('cluster','node','storage','task','resource')),
  source_id TEXT NOT NULL,
  incident_type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('warning','critical')),
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','acknowledged','resolved')),
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  acknowledged_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  acknowledged_at INTEGER,
  resolved_at INTEGER,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS operations_nodes_status_idx
  ON operations_node_metrics(cluster_id,status,updated_at);
CREATE INDEX IF NOT EXISTS operations_storage_usage_idx
  ON operations_storage_metrics(cluster_id,usage_percent DESC);
CREATE INDEX IF NOT EXISTS operations_incidents_status_idx
  ON operations_incidents(status,severity,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS operations_incidents_scope_idx
  ON operations_incidents(scope,status);
