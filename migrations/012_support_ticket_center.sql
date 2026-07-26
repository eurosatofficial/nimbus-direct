PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS support_tickets (
  id TEXT PRIMARY KEY,
  reference TEXT NOT NULL UNIQUE,
  customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  assigned_to TEXT REFERENCES users(id) ON DELETE SET NULL,
  resource_id TEXT REFERENCES resources(id) ON DELETE SET NULL,
  subject TEXT NOT NULL,
  category TEXT NOT NULL CHECK(category IN ('technical','network','account','billing','other')),
  priority TEXT NOT NULL CHECK(priority IN ('low','normal','high','urgent')),
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','waiting_support','waiting_customer','resolved','closed')),
  last_message_at INTEGER NOT NULL,
  resolved_at INTEGER,
  closed_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS support_ticket_messages (
  id TEXT PRIMARY KEY,
  ticket_id TEXT NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
  author_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  author_role TEXT NOT NULL CHECK(author_role IN ('admin','customer','system')),
  body TEXT NOT NULL,
  internal INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS support_ticket_reads (
  ticket_id TEXT NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  last_read_at INTEGER NOT NULL,
  PRIMARY KEY(ticket_id,user_id)
) STRICT;

CREATE INDEX IF NOT EXISTS support_tickets_customer_status_idx
  ON support_tickets(customer_id,status,last_message_at DESC);
CREATE INDEX IF NOT EXISTS support_tickets_assignee_status_idx
  ON support_tickets(assigned_to,status,last_message_at DESC);
CREATE INDEX IF NOT EXISTS support_ticket_messages_ticket_created_idx
  ON support_ticket_messages(ticket_id,created_at);
CREATE INDEX IF NOT EXISTS support_ticket_reads_user_idx
  ON support_ticket_reads(user_id,last_read_at);
