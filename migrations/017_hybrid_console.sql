-- Records whether a one-time Proxmox console ticket belongs to noVNC or
-- termproxy. The backend also performs this migration defensively at startup.
ALTER TABLE console_sessions
  ADD COLUMN console_type TEXT NOT NULL DEFAULT 'graphical'
  CHECK(console_type IN ('graphical','terminal'));

ALTER TABLE console_sessions
  ADD COLUMN console_user TEXT;
