ALTER TABLE maintenance_events
  ADD COLUMN time_zone TEXT NOT NULL DEFAULT 'UTC';
