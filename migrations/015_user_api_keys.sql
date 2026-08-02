-- User-managed integration keys with administrator-defined maximum permissions.
CREATE TABLE IF NOT EXISTS user_api_policies (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  enabled INTEGER NOT NULL DEFAULT 0,
  max_active_keys INTEGER NOT NULL DEFAULT 3 CHECK(max_active_keys BETWEEN 1 AND 50),
  max_lifetime_days INTEGER NOT NULL DEFAULT 365 CHECK(max_lifetime_days BETWEEN 1 AND 3650),
  allow_no_expiry INTEGER NOT NULL DEFAULT 0,
  all_visible_resources INTEGER NOT NULL DEFAULT 0,
  updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS user_api_policy_groups (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  group_id TEXT NOT NULL,
  PRIMARY KEY(user_id,group_id)
) STRICT;

CREATE TABLE IF NOT EXISTS user_api_policy_resources (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id,resource_id)
) STRICT;

CREATE TABLE IF NOT EXISTS user_api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  token_hint TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  expires_at INTEGER,
  last_used_at INTEGER,
  last_ip TEXT,
  revoked_at INTEGER,
  revoked_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  revoked_reason TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS user_api_key_groups (
  key_id TEXT NOT NULL REFERENCES user_api_keys(id) ON DELETE CASCADE,
  group_id TEXT NOT NULL,
  PRIMARY KEY(key_id,group_id)
) STRICT;

CREATE TABLE IF NOT EXISTS user_api_key_resources (
  key_id TEXT NOT NULL REFERENCES user_api_keys(id) ON DELETE CASCADE,
  resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  PRIMARY KEY(key_id,resource_id)
) STRICT;

CREATE INDEX IF NOT EXISTS user_api_keys_user_status_idx
  ON user_api_keys(user_id,status,created_at DESC);
CREATE INDEX IF NOT EXISTS user_api_keys_token_idx
  ON user_api_keys(token_hash,status);
