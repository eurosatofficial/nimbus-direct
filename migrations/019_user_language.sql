ALTER TABLE users
  ADD COLUMN preferred_language TEXT NOT NULL DEFAULT 'en'
  CHECK(preferred_language IN ('en','de'));
