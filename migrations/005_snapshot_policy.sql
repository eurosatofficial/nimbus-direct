-- Nimbus Direct 0.5: per-assignment snapshot retention guardrail.
ALTER TABLE customer_resource_assignments
  ADD COLUMN snapshot_limit INTEGER NOT NULL DEFAULT 3
  CHECK(snapshot_limit BETWEEN 1 AND 50);
