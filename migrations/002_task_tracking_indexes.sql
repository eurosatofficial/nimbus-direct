-- Nimbus Direct v2 task-list indexes.
-- Safe to apply to existing installations; runtime startup also applies these idempotently.
CREATE INDEX IF NOT EXISTS tasks_customer_created_idx ON api_tasks(customer_id,created_at DESC);
CREATE INDEX IF NOT EXISTS tasks_resource_created_idx ON api_tasks(resource_id,created_at DESC);
