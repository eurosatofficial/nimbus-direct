-- Nimbus Direct v4 one-time ISO boot state and safe boot-order restoration.
CREATE TABLE IF NOT EXISTS iso_boot_overrides (
  id TEXT PRIMARY KEY,
  resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  iso_mount_id TEXT NOT NULL REFERENCES iso_mounts(id) ON DELETE CASCADE,
  drive_slot TEXT NOT NULL,
  original_boot TEXT,
  armed_boot TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('arming','armed','restoring','restored','cancelled','error')),
  error_code TEXT,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  armed_at INTEGER,
  restored_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS iso_boot_overrides_resource_created_idx
  ON iso_boot_overrides(resource_id,created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS iso_boot_overrides_active_idx
  ON iso_boot_overrides(resource_id)
  WHERE status IN ('arming','armed','restoring','error');
