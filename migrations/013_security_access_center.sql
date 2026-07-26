PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS security_policy (
  id TEXT PRIMARY KEY CHECK(id='default'),
  require_admin_mfa INTEGER NOT NULL DEFAULT 0,
  require_customer_mfa INTEGER NOT NULL DEFAULT 0,
  new_login_email INTEGER NOT NULL DEFAULT 0,
  updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

INSERT OR IGNORE INTO security_policy
  (id,require_admin_mfa,require_customer_mfa,new_login_email,created_at,updated_at)
VALUES
  ('default',0,0,0,unixepoch('now') * 1000,unixepoch('now') * 1000);

CREATE INDEX IF NOT EXISTS audit_action_created_idx
  ON audit_logs(action,created_at DESC);
