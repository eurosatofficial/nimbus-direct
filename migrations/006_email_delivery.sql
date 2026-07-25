-- Nimbus Direct 0.6: encrypted SMTP settings and a durable email delivery queue.
CREATE TABLE IF NOT EXISTS email_settings (
  id TEXT PRIMARY KEY CHECK(id='default'),
  enabled INTEGER NOT NULL DEFAULT 0,
  host TEXT NOT NULL,
  port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
  security TEXT NOT NULL CHECK(security IN ('tls','starttls')),
  username TEXT NOT NULL DEFAULT '',
  password_encrypted TEXT,
  from_name TEXT NOT NULL,
  from_email TEXT NOT NULL,
  reply_to TEXT NOT NULL DEFAULT '',
  last_test_at INTEGER,
  last_test_status TEXT CHECK(last_test_status IS NULL OR last_test_status IN ('success','failed')),
  last_test_error_code TEXT,
  updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS email_jobs (
  id TEXT PRIMARY KEY,
  to_email TEXT NOT NULL,
  subject TEXT NOT NULL,
  payload_encrypted TEXT NOT NULL,
  category TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','processing','sent','failed')),
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 4 CHECK(max_attempts BETWEEN 1 AND 10),
  next_attempt_at INTEGER NOT NULL,
  locked_at INTEGER,
  last_error_code TEXT,
  provider_message_id TEXT,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  sent_at INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS email_jobs_due_idx
  ON email_jobs(status,next_attempt_at,created_at);
CREATE INDEX IF NOT EXISTS email_jobs_created_idx
  ON email_jobs(created_at DESC);
