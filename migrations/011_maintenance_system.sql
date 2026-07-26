-- Nimbus Direct maintenance system: targeted notices and immutable recipient snapshots.
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS maintenance_events (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('maintenance','incident')),
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('info','warning','critical')),
  status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','scheduled','active','resolved','cancelled')),
  starts_at INTEGER NOT NULL,
  ends_at INTEGER,
  notify_email INTEGER NOT NULL DEFAULT 1,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  published_at INTEGER,
  resolved_at INTEGER,
  cancelled_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK(ends_at IS NULL OR ends_at > starts_at)
) STRICT;

CREATE TABLE IF NOT EXISTS maintenance_targets (
  event_id TEXT NOT NULL REFERENCES maintenance_events(id) ON DELETE CASCADE,
  target_type TEXT NOT NULL CHECK(target_type IN ('all','cluster','node','resource','customer')),
  target_id TEXT NOT NULL,
  PRIMARY KEY(event_id,target_type,target_id)
) STRICT;

CREATE TABLE IF NOT EXISTS maintenance_deliveries (
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL REFERENCES maintenance_events(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email_job_id TEXT REFERENCES email_jobs(id) ON DELETE SET NULL,
  resolution_email_job_id TEXT REFERENCES email_jobs(id) ON DELETE SET NULL,
  read_at INTEGER,
  created_at INTEGER NOT NULL,
  UNIQUE(event_id,user_id)
) STRICT;

CREATE INDEX IF NOT EXISTS maintenance_events_status_schedule_idx
  ON maintenance_events(status,starts_at,ends_at);
CREATE INDEX IF NOT EXISTS maintenance_targets_lookup_idx
  ON maintenance_targets(target_type,target_id,event_id);
CREATE INDEX IF NOT EXISTS maintenance_deliveries_user_event_idx
  ON maintenance_deliveries(user_id,event_id);
