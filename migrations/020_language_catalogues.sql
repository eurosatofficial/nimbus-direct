ALTER TABLE users
  ADD COLUMN preferred_locale TEXT NOT NULL DEFAULT 'en';

UPDATE users
SET preferred_locale = preferred_language;
