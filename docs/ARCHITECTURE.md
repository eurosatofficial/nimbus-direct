# Nimbus Direct architecture

Nimbus Direct is a self-hosted control plane for Proxmox VE. Proxmox remains the source of truth for guest runtime state. Nimbus is the source of truth for customers, users, direct guest assignments, and allowed operations.

The design never creates, reads, or depends on one Proxmox resource pool per customer.

## 1. Overall architecture

```text
Customer browser                    Administrator browser
        |                                    |
        +----------- HTTPS / secure cookie --+
                             |
                    Nimbus Direct server
                    +--------------------+
                    | authentication     |
                    | RBAC               |
                    | CSRF + rate limits |
                    +---------+----------+
                              |
                    authorization service
                    assignment + permission lookup
                              |
                 +------------+-------------+
                 |                          |
          SQLite control DB          Proxmox service layer
          - users                    - API token auth
          - customers                - response allowlists
          - assignments              - task normalization
          - permissions              - console tickets
          - audit/tasks                    |
                 |                   HTTPS :8006
                 |                          |
          background sync        Proxmox VE cluster(s)
                                  (no Nimbus node agent)
```

The server is the only component that knows the Proxmox service-account credentials. Every customer request resolves a resource from the database using the authenticated customer ID, requested Nimbus resource ID, active assignment, and required permission. Only the server-derived cluster, node, type, and VMID are sent to Proxmox.

## 2. Database schema

Core tables:

- `users`: login identity, password hash, role, status, optional customer membership.
- `customers`: customer account and support/plan metadata.
- `proxmox_clusters`: cluster name, HTTPS API URL, health, and sync state.
- `proxmox_credentials`: token ID and AES-256-GCM encrypted token secret.
- `proxmox_nodes`: synchronized node inventory.
- `resources`: synchronized QEMU/LXC coordinates and runtime metadata.
- `customer_resource_assignments`: exactly one current customer per resource, optional customer-facing name, and status.
- `assignment_permissions`: explicit allowed operations for one assignment.
- `sessions`: opaque, secret-bound server sessions and CSRF tokens.
- `audit_logs`: actor, customer, action, resource, source IP, detail, and time.
- `api_tasks`: Proxmox UPID tracking and idempotency.
- `console_sessions`: encrypted short-lived console tickets.

Important keys:

```text
resources UNIQUE(cluster_id, type, vmid)
customer_resource_assignments UNIQUE(resource_id)
assignment_permissions PRIMARY KEY(assignment_id, permission)
```

The canonical resource ID is `cluster-id:type:vmid`. The node is stored and updated during synchronization because a guest can move. Assignments reference the stable resource row, so a migration between nodes does not transfer or delete customer ownership.

## 3. Authentication and authorization

Authentication uses scrypt password hashing and opaque HTTP-only sessions. Administrators have platform scope. Customer users must belong to one active customer account.

Authorization is server-side and fail-closed:

```text
authenticated user
  -> active user and customer?
  -> resource exists?
  -> active assignment belongs to this customer?
  -> required assignment permission is allowed?
  -> use coordinates loaded from the resource row
  -> call Proxmox
```

Customers receive `404 resource_not_found` for missing, unassigned, cross-customer, or disallowed resources. This avoids confirming that another customer's VMID exists.

Administrators can manage the control plane and are not constrained by customer assignments. Administrative actions remain audited.

## 4. Proxmox API integration

Each configured cluster has one central, privilege-separated API token. Credentials are encrypted before database storage and decrypted only while constructing a server-side client.

The service layer uses the official `/api2/json` endpoints for:

- `GET /cluster/resources?type=vm` for QEMU/LXC discovery.
- `GET /nodes/{node}/{type}/{vmid}/config` for allowlisted configuration.
- `GET /nodes/{node}/{type}/{vmid}/rrddata` for usage history.
- `POST /nodes/{node}/{type}/{vmid}/status/{action}` for power actions.
- Guest-agent/LXC interface endpoints for network information.
- Snapshot list/create/rollback/delete endpoints.
- `POST .../vncproxy` for short-lived console tickets.
- `GET /nodes/{node}/tasks/{upid}/status` for asynchronous task status.

Raw upstream bodies never pass through to customers. Nimbus normalizes errors, allowlists configuration fields, and stores only required task identifiers.

Synchronization marks previously discovered resources as stale before applying fresh metadata. It does not delete resource rows or assignments when Proxmox is temporarily unavailable or a guest is missing from one response.

## 5. Administrator assignment workflow

1. Add a Proxmox cluster and encrypted service-account token.
2. Test the connection and synchronize the guest inventory.
3. Create a customer account and one or more Nimbus users.
4. Open **Control center → Inventory**.
5. Select any QEMU VM or LXC container from any node/cluster.
6. Choose the customer, optional display name, and allowed operations.
7. Save the local assignment.

Reassigning a resource updates the local assignment and permission rows. Removing it changes the assignment state to `unassigned`. Neither operation creates or modifies a Proxmox pool.

## 6. Customer dashboard

The dashboard returns only resources with an active assignment to the authenticated customer and `view_status` permission. It shows status, cluster, node, type/VMID, CPU, RAM, storage, uptime, IP, and recent activity.

Buttons are generated from assignment permissions for usability, but the same permission is checked again on the server. Power operations use idempotency keys and return either an immediate result or a tracked Proxmox task.

Console launch creates a short-lived, encrypted, one-time ticket record. The bundled noVNC 1.7 client connects to a same-origin WebSocket gateway; the gateway consumes the local launch token once, completes the authenticated Proxmox `vncwebsocket` upgrade server-side, and then pipes binary frames. The authenticated console page receives the scoped, short-lived VNC ticket in memory because Proxmox requires it as the noVNC password. The long-lived Proxmox API token never reaches the browser.

## 7. Security model

- TLS is required for every Proxmox API URL.
- Proxmox token secrets use AES-256-GCM encryption with a key derived from `APP_SECRET`.
- Passwords use scrypt; sessions are opaque, HTTP-only, SameSite=Strict, and Secure in production.
- State-changing requests require a session-bound CSRF token and same-origin check.
- Login and power actions have independent rate limits.
- Customer resource authorization is a database join, never a frontend decision.
- User-supplied VMID, node, type, or cluster coordinates are never forwarded.
- Configuration reads and writes use explicit field allowlists.
- Console tickets are encrypted, short-lived, and single-use.
- API task IDs are customer-scoped and idempotent.
- Security headers deny framing and unnecessary browser capabilities.
- Audit logs cover authentication, administration, assignment changes, power requests, configuration, snapshots, and console tickets.
- Docker runs unprivileged, read-only, without Linux capabilities or privilege escalation.

Recommended token privileges must be adjusted to the enabled feature set. A status/power/console MVP generally needs `VM.Audit`, `VM.PowerMgmt`, and `VM.Console`; add `VM.Snapshot`/`VM.Snapshot.Rollback`, selected `VM.Config.*`, and guest-agent audit privileges only when those features are enabled. Apply the role at `/vms` or explicit `/vms/{vmid}` paths and do not grant `Administrator`, `Sys.Modify`, user management, storage allocation, or host-shell privileges.

## 8. Practical MVP plan

### Phase 1 — implemented foundation

- Local customer and user accounts.
- Multiple encrypted Proxmox cluster credentials.
- Cluster-wide QEMU/LXC inventory synchronization without pool dependency.
- Direct assignment/reassignment/unassignment and per-resource permissions.
- Customer-only dashboard and power-action authorization.
- Status, resource usage, IP metadata, details, audit history, and task model.
- Snapshot/config services and a short-lived, one-time noVNC console gateway.
- Docker deployment, health/readiness endpoints, and automated security/isolation tests.

### Phase 2 — production hardening

- Replace in-process rate limiting with Redis when running multiple replicas.
- Add TOTP/WebAuthn MFA and account recovery policy.
- Add key rotation with credential re-encryption.
- Add a durable job runner for sync/task polling rather than one process timer.
- Add pagination and retention policies for large audit/task tables.
- Add per-cluster CA/fingerprint management and outbound network allowlisting.

### Phase 3 — controlled expansion

- Snapshot UI and restore confirmations.
- Selected configuration editors with quotas and change previews.
- Notifications, webhooks, maintenance windows, and support impersonation controls.
- PostgreSQL option and HA deployment.
- External identity providers and organization-level policy templates.

Before external production use, run a penetration test, perform restore drills, validate every role against the exact Proxmox release, and test every enabled operation with the least-privilege token.
