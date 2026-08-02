CREATE TABLE mobile_push_devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  token_encrypted TEXT NOT NULL,
  platform TEXT NOT NULL CHECK(platform IN ('ios')),
  environment TEXT NOT NULL CHECK(environment IN ('sandbox','production')),
  app_version TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
  failure_reason TEXT,
  last_registered_at INTEGER NOT NULL,
  last_sent_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE INDEX mobile_push_devices_user_status
  ON mobile_push_devices(user_id, status, updated_at DESC);
