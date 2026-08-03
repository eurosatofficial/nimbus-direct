-- Nimbus Direct maintenance action locks. Existing notices remain informational.
PRAGMA foreign_keys=ON;

ALTER TABLE maintenance_events
  ADD COLUMN lock_groups TEXT NOT NULL DEFAULT '[]';
