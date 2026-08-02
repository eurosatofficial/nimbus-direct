PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS api_device_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  access_token_hash TEXT NOT NULL UNIQUE,
  device_name TEXT NOT NULL,
  platform TEXT NOT NULL CHECK(platform IN ('ios','android','desktop','other')),
  app_version TEXT,
  ip_address TEXT,
  user_agent TEXT,
  access_expires_at INTEGER NOT NULL,
  refresh_expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  rotated_at INTEGER,
  revoked_at INTEGER,
  revoked_reason TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS api_refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES api_device_sessions(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK(status IN ('active','rotated','revoked')),
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  used_at INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS api_device_sessions_user_idx
  ON api_device_sessions(user_id,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS api_device_sessions_access_idx
  ON api_device_sessions(access_token_hash,access_expires_at);
CREATE INDEX IF NOT EXISTS api_refresh_tokens_session_idx
  ON api_refresh_tokens(session_id,status,created_at DESC);
CREATE INDEX IF NOT EXISTS api_refresh_tokens_expiry_idx
  ON api_refresh_tokens(expires_at,status);
