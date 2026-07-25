PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS user_mfa (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  totp_secret_encrypted TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  recovery_code_hashes TEXT NOT NULL DEFAULT '[]',
  setup_expires_at INTEGER,
  confirmed_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS mfa_login_challenges (
  id_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
) STRICT;

ALTER TABLE sessions ADD COLUMN ip_address TEXT;
ALTER TABLE sessions ADD COLUMN user_agent TEXT;

CREATE INDEX IF NOT EXISTS sessions_user_created_idx ON sessions(user_id,created_at DESC);
CREATE INDEX IF NOT EXISTS mfa_challenges_expires_idx ON mfa_login_challenges(expires_at);
