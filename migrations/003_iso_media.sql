-- Nimbus Direct v3 customer ISO storage, ownership, and mount records.
CREATE TABLE IF NOT EXISTS iso_storage_policies (
  id TEXT PRIMARY KEY,
  cluster_id TEXT NOT NULL REFERENCES proxmox_clusters(id) ON DELETE CASCADE,
  storage_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
  max_upload_bytes INTEGER NOT NULL,
  customer_quota_bytes INTEGER NOT NULL,
  allow_delete INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(cluster_id,storage_id)
) STRICT;

CREATE TABLE IF NOT EXISTS iso_images (
  id TEXT PRIMARY KEY,
  customer_id TEXT REFERENCES customers(id) ON DELETE SET NULL,
  cluster_id TEXT NOT NULL REFERENCES proxmox_clusters(id) ON DELETE CASCADE,
  storage_policy_id TEXT REFERENCES iso_storage_policies(id) ON DELETE SET NULL,
  storage_id TEXT NOT NULL,
  node TEXT NOT NULL,
  volume_id TEXT NOT NULL,
  file_name TEXT NOT NULL,
  original_name TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  sha256 TEXT,
  status TEXT NOT NULL CHECK(status IN ('uploading','processing','ready','error','deleting','deleted')),
  operation_upid TEXT,
  error_code TEXT,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS iso_mounts (
  id TEXT PRIMARY KEY,
  iso_image_id TEXT NOT NULL REFERENCES iso_images(id) ON DELETE CASCADE,
  resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  drive_slot TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('active','ejected')),
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  mounted_at INTEGER NOT NULL,
  ejected_at INTEGER,
  created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS iso_images_customer_created_idx ON iso_images(customer_id,created_at DESC);
CREATE INDEX IF NOT EXISTS iso_images_policy_status_idx ON iso_images(storage_policy_id,status);
CREATE INDEX IF NOT EXISTS iso_mounts_resource_status_idx ON iso_mounts(resource_id,status);
CREATE INDEX IF NOT EXISTS iso_mounts_image_status_idx ON iso_mounts(iso_image_id,status);
