-- Nimbus Direct 0.7: assignment alert policies and private customer notifications.
CREATE TABLE IF NOT EXISTS resource_alert_policies (
  assignment_id TEXT PRIMARY KEY REFERENCES customer_resource_assignments(id) ON DELETE CASCADE,
  enabled INTEGER NOT NULL DEFAULT 0,
  alert_offline INTEGER NOT NULL DEFAULT 1,
  alert_cpu INTEGER NOT NULL DEFAULT 1,
  alert_memory INTEGER NOT NULL DEFAULT 1,
  alert_storage INTEGER NOT NULL DEFAULT 1,
  cpu_threshold INTEGER NOT NULL DEFAULT 90 CHECK(cpu_threshold BETWEEN 50 AND 100),
  memory_threshold INTEGER NOT NULL DEFAULT 90 CHECK(memory_threshold BETWEEN 50 AND 100),
  storage_threshold INTEGER NOT NULL DEFAULT 90 CHECK(storage_threshold BETWEEN 50 AND 100),
  sustain_seconds INTEGER NOT NULL DEFAULT 300 CHECK(sustain_seconds BETWEEN 60 AND 86400),
  cooldown_seconds INTEGER NOT NULL DEFAULT 3600 CHECK(cooldown_seconds BETWEEN 300 AND 604800),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS alert_states (
  assignment_id TEXT NOT NULL REFERENCES customer_resource_assignments(id) ON DELETE CASCADE,
  alert_type TEXT NOT NULL CHECK(alert_type IN ('offline','cpu','memory','storage')),
  status TEXT NOT NULL DEFAULT 'healthy' CHECK(status IN ('healthy','pending','firing')),
  condition_active INTEGER NOT NULL DEFAULT 0,
  first_observed_at INTEGER,
  last_value REAL,
  last_notified_at INTEGER,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(assignment_id,alert_type)
) STRICT;

CREATE TABLE IF NOT EXISTS notification_preferences (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  in_app_enabled INTEGER NOT NULL DEFAULT 1,
  email_enabled INTEGER NOT NULL DEFAULT 0,
  action_success INTEGER NOT NULL DEFAULT 1,
  action_failure INTEGER NOT NULL DEFAULT 1,
  infrastructure_alerts INTEGER NOT NULL DEFAULT 1,
  resolution_alerts INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS notification_events (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  resource_id TEXT REFERENCES resources(id) ON DELETE SET NULL,
  category TEXT NOT NULL CHECK(category IN ('action_success','action_failure','infrastructure_alert','resolution')),
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('info','success','warning','critical')),
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  dedup_key TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL REFERENCES notification_events(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  in_app_visible INTEGER NOT NULL DEFAULT 1,
  email_job_id TEXT REFERENCES email_jobs(id) ON DELETE SET NULL,
  read_at INTEGER,
  created_at INTEGER NOT NULL,
  UNIQUE(event_id,user_id)
) STRICT;

CREATE INDEX IF NOT EXISTS alert_states_status_idx
  ON alert_states(status,updated_at);
CREATE INDEX IF NOT EXISTS notification_events_customer_created_idx
  ON notification_events(customer_id,created_at DESC);
CREATE INDEX IF NOT EXISTS notification_events_resource_created_idx
  ON notification_events(resource_id,created_at DESC);
CREATE INDEX IF NOT EXISTS notifications_user_created_idx
  ON notifications(user_id,created_at DESC);
