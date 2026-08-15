-- Nimbus Direct 1.7.1: encrypted panel identity for central push-relay authentication.
-- Runtime startup creates this table idempotently; this file documents the schema
-- for operators who manage migrations separately.
CREATE TABLE IF NOT EXISTS push_relay_credentials (
  id TEXT PRIMARY KEY CHECK(id='default'),
  installation_id TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  private_key_encrypted TEXT NOT NULL,
  registered_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;
