PRAGMA foreign_keys=ON;

ALTER TABLE users ADD COLUMN password_set INTEGER NOT NULL DEFAULT 1;
ALTER TABLE email_settings ADD COLUMN app_url TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS account_tokens (
  id_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL CHECK(purpose IN ('invitation','password_reset')),
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  requested_ip TEXT,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS account_tokens_user_purpose_idx
  ON account_tokens(user_id,purpose,created_at DESC);
CREATE INDEX IF NOT EXISTS account_tokens_expires_idx
  ON account_tokens(expires_at);
