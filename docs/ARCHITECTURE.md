# Nimbus Direct architecture

Nimbus Direct is a self-hosted control plane for Proxmox VE. Proxmox remains the source of truth for guest runtime state. Nimbus is the source of truth for customers, users, direct guest assignments, and allowed operations.

The design never creates, reads, or depends on one Proxmox resource pool per customer.

## 1. Overall architecture

```text
Customer browser         Native mobile app         Administrator browser
        |                       |                            |
        +-- secure cookie ------+-- HTTPS / bearer token ----+
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
                 +------------+-------------+----------------+----------------+
                 |                          |                |                |
          SQLite control DB          Proxmox service layer  Email service  Push service
          - users                    - API token auth        - SMTP TLS
          - customers                - response allowlists  - retry queue
          - assignments/limits       - task normalization   - templates
          - permissions              - console tickets            |
          - ISO ownership            - streamed ISO upload      TLS SMTP
          - ISO/boot state           - guarded boot restore
          - SMTP/queued mail               |
          - alerts/notifications     HTTPS :8006
          - MFA/recovery codes
          - account-link hashes
          - API device sessions
          - refresh-token history
          - operations telemetry
          - operations incidents
          - encrypted relay identity
          - audit/tasks
                 |                          |
          background sync        Proxmox VE cluster(s)
                                  (no Nimbus node agent)
                                                                          |
                                                              signed HTTPS (relay mode)
                                                                          |
                                                              Nimbus Push Relay -> APNs
```

The server is the only component that knows the Proxmox service-account credentials. Every customer request resolves a resource from the database using the authenticated customer ID, requested Nimbus resource ID, active assignment, and required permission. Only the server-derived cluster, node, type, and VMID are sent to Proxmox.

## 2. Database schema

Core tables:

- `users`: login identity, password hash, password-onboarding state, role, status, optional customer membership.
- `user_mfa`: AES-256-GCM encrypted TOTP secret, enrollment/confirmation state, and one-way recovery-code hashes.
- `user_passkeys`: public WebAuthn credentials, authenticator counters, transports, backup state, and usage timestamps.
- `webauthn_challenges`: short-lived, purpose-bound, single-use registration and authentication challenges identified by keyed token hashes.
- `customers`: customer account and support/plan metadata.
- `proxmox_clusters`: cluster name, HTTPS API URL, health, and sync state.
- `proxmox_credentials`: token ID and AES-256-GCM encrypted token secret.
- `proxmox_nodes`: synchronized node inventory.
- `resources`: synchronized QEMU/LXC coordinates and runtime metadata.
- `customer_resource_assignments`: exactly one current customer per resource, optional customer-facing name, snapshot limit, and status.
- `assignment_permissions`: explicit allowed operations for one assignment.
- `sessions`: opaque, secret-bound server sessions, CSRF tokens, source IP, and bounded user-agent metadata.
- `api_device_sessions`: user/device identity, hashed current access token, fixed refresh expiry, activity metadata, and revocation state.
- `api_refresh_tokens`: hashed single-use refresh-token history for atomic rotation, expiry, revocation, and reuse detection.
- `user_api_policies`: administrator-defined per-user API enablement, key-count/lifetime ceilings, and no-expiry policy.
- `user_api_policy_groups` / `user_api_policy_resources`: maximum stable permission groups and optional resource allowlist for one account.
- `user_api_keys`: hash-only integration credentials, safe display hints, expiry, last-use metadata, and revocation history.
- `user_api_key_groups` / `user_api_key_resources`: the narrower groups and individual resources selected by the user for one key.
- `mfa_login_challenges`: hashed, five-minute, attempt-limited challenges that bridge password verification and session creation.
- `security_policy`: singleton administrator/customer MFA requirements, optional successful-login email setting, and update attribution.
- `account_tokens`: `APP_SECRET`-keyed token hash, invitation/password-reset purpose, target user, expiration, single-use/revocation state, creator, and bounded request IP. Raw tokens are never stored in this table.
- `audit_logs`: actor, customer, action, resource, source IP, detail, and time.
- `api_tasks`: server-only Proxmox UPID tracking, customer-scoped progress, and idempotency.
- `console_sessions`: encrypted short-lived console tickets.
- `iso_storage_policies`: an administrator-enabled Proxmox ISO storage, state, per-file ceiling, per-customer quota, and optional deletion policy.
- `iso_images`: customer ownership, cluster/storage/node coordinates, internal Proxmox volume ID, safe filename, size/hash, operation state, and server-only task UPID.
- `iso_mounts`: the ISO image, assigned resource, QEMU CD-ROM slot, and mount/eject lifecycle.
- `iso_boot_overrides`: the active mount, internally saved original/temporary boot values, restoration state, and lifecycle timestamps. Raw boot values are never returned to browsers.
- `email_settings`: singleton delivery state, SMTP endpoint/security mode, sender identity, public panel URL, encrypted password, and sanitized connection-test status.
- `email_jobs`: recipient, subject, category, encrypted pending content, retry state, sanitized error code, and delivery timestamps. Successfully delivered content is erased.
- `resource_alert_policies`: per-assignment enabled conditions, thresholds, duration, cooldown, and timestamps.
- `alert_states`: durable healthy/pending/firing state for each assignment and condition, including incident and last-notification timing.
- `notification_preferences`: independent in-panel/email and event-category choices for one customer login.
- `notification_events`: customer/resource-scoped action, alert, and recovery events with a unique deduplication key.
- `notifications`: private per-user delivery/read state and optional queued email reference.
- `operations_collection_status`: per-cluster node/storage telemetry coverage, sanitized failure codes, and collection time.
- `operations_node_metrics`: normalized node state, CPU, memory, root-storage, uptime, and last-good sample.
- `operations_storage_metrics`: normalized per-node storage availability, type/content, capacity, and last-good sample.
- `operations_incidents`: durable administrator-only cluster/node/storage/task/resource conditions with acknowledgement and automatic resolution state.
- `maintenance_events`: administrator-authored planned work or incidents, schedule, severity, lifecycle, and email intent.
- `maintenance_targets`: one notice's all/cluster/node/resource/customer audience before publication.
- `maintenance_deliveries`: immutable affected-user snapshot, read state, and optional initial/resolution email jobs.
- `support_tickets`: customer ownership, optional assigned resource, subject/category/priority, administrator assignment, workflow status, and lifecycle timestamps.
- `support_ticket_messages`: customer, administrator, system, and administrator-only internal messages for one ticket.
- `support_ticket_reads`: individual per-login read position for a customer-shared or administrator-visible ticket.
- `push_relay_credentials`: one automatically generated Ed25519 installation identity; its private key is encrypted with `APP_SECRET`, while registration state is local to the panel.

Important keys:

```text
resources UNIQUE(cluster_id, type, vmid)
customer_resource_assignments UNIQUE(resource_id)
assignment_permissions PRIMARY KEY(assignment_id, permission)
iso_storage_policies UNIQUE(cluster_id, storage_id)
iso_boot_overrides UNIQUE(resource_id) WHERE status is active
resource_alert_policies PRIMARY KEY(assignment_id)
alert_states PRIMARY KEY(assignment_id, alert_type)
notification_events UNIQUE(dedup_key)
notifications UNIQUE(event_id, user_id)
operations_node_metrics PRIMARY KEY(cluster_id, node)
operations_storage_metrics PRIMARY KEY(cluster_id, node, storage_id)
operations_incidents UNIQUE(dedup_key)
maintenance_targets PRIMARY KEY(event_id, target_type, target_id)
maintenance_deliveries UNIQUE(event_id, user_id)
support_tickets UNIQUE(reference)
support_ticket_reads PRIMARY KEY(ticket_id, user_id)
```

The canonical resource ID is `cluster-id:type:vmid`. The node is stored and updated during synchronization because a guest can move. Assignments reference the stable resource row, so a migration between nodes does not transfer or delete customer ownership.

## 3. Authentication and authorization

Authentication uses scrypt password hashing and opaque HTTP-only sessions. Optional TOTP authentication is compatible with standard authenticator apps. A password-valid account with MFA enabled receives only a short-lived challenge; Nimbus creates the real session only after a current six-digit code or an unused recovery code succeeds. TOTP secrets are encrypted with `APP_SECRET`, while recovery codes are normalized, secret-bound hashed, displayed once, and atomically consumed. Administrators have platform scope. Customer users must belong to one active customer account.

Optional WebAuthn passkeys provide a passwordless browser login. Nimbus requires
discoverable credentials and authenticator user verification, validates the
exact configured HTTPS origin and relying-party ID, consumes every registration
or authentication challenge once, and checks credential counters. SQLite stores
the credential public key and safe metadata only. The authenticator retains the
private key. A returned credential maps back to exactly one local Nimbus user;
the same account and customer-status checks still run before session creation.

Native clients authenticate against the same account and TOTP services but
receive an opaque short-lived `nmb_at_` bearer access token and a longer-lived
`nmb_rt_` refresh token. Both are stored only as `APP_SECRET`-bound hashes.
Refresh is an atomic single-use rotation: the old history row becomes
`rotated`, a new access/refresh pair is committed to the same device session,
and submitting a rotated token again revokes that entire device session. The
fixed refresh expiry cannot be extended by rotation. Password changes, account
or customer disablement/deletion, invitation/reset completion, administrator
2FA resets, and explicit session controls revoke native tokens alongside
browser sessions.

Bearer authentication changes only session verification. It enters the same
role, customer, assignment, permission, action-rate, task, and audit path used
by the browser. Cookie requests retain session-bound CSRF and same-origin
validation. Bearer requests do not use CSRF because credentials are supplied in
the `Authorization` header and Nimbus does not enable browser CORS.

The durable security policy can independently require MFA for administrator and customer roles. A password-valid account covered by policy but missing MFA receives a restricted enrollment session. The backend permits only the redacted dashboard plus TOTP setup/confirmation until enrollment succeeds; it denies administrative, resource, network, account, and other customer routes. Policy evaluation occurs on every request, and disabling MFA is rejected while the authenticated user's role remains covered.

Administrators can create a user in pending-password state and send a 30-minute invitation. Invitations and password resets share a purpose-bound, single-use account-token service. The email contains the raw random token inside an encrypted queued body; SQLite stores only its `APP_SECRET`-keyed hash. Resending invalidates the previous invitation, completion consumes every outstanding account token and revokes every session, and password recovery preserves TOTP configuration. Forgot-password responses are intentionally identical for eligible, unknown, disabled, and pending-invitation addresses. Account-link validation/completion and request generation use independent rate limits.

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
- `GET /cluster/resources?type=node` for normalized node pressure and availability.
- `GET /nodes/{node}/storage?enabled=1` for normalized enabled-storage availability and capacity, with the cluster resource list retained as a compatibility fallback.
- `GET /nodes/{node}/{type}/{vmid}/config` for allowlisted configuration.
- `GET /nodes/{node}/{type}/{vmid}/rrddata` for usage history.
- `POST /nodes/{node}/{type}/{vmid}/status/{action}` for power actions.
- Guest-agent/LXC interface endpoints for live network information, with allowlisted static QEMU Cloud-Init and LXC configuration fallback.
- Snapshot list/create/rollback/delete endpoints.
- `POST .../termproxy` for LXC and serial-display QEMU terminal tickets, or `POST .../vncproxy` for graphical QEMU console tickets.
- `GET /nodes/{node}/tasks/{upid}/status` for asynchronous task status.
- `GET /nodes/{node}/storage?content=iso&enabled=1` for administrator storage discovery and node availability checks.
- `POST /nodes/{node}/storage/{storage}/upload` for streamed multipart ISO upload.
- `PUT /nodes/{node}/qemu/{vmid}/config` for guarded CD-ROM mount/eject.
- `GET` and `PUT /nodes/{node}/qemu/{vmid}/config` for server-derived one-time ISO boot and compare-before-restore handling.
- `DELETE /nodes/{node}/storage/{storage}/content/{volume}` for optional ISO deletion.

Raw upstream bodies never pass through to customers. Nimbus normalizes errors, allowlists configuration fields, and stores only required task identifiers. Task API responses exclude the UPID and expose a small state model: running, successful, or failed.

Synchronization marks previously discovered resources as stale before applying fresh metadata. It does not delete resource rows or assignments when Proxmox is temporarily unavailable or a guest is missing from one response.

Operations telemetry is an optional parallel branch of synchronization. Node and storage calls are settled independently from guest inventory. A denied or failed optional call records only an allowlisted error code, keeps the last good metrics, and does not resolve incidents from a scope that was not successfully evaluated. Cluster reachability, stale assigned resources, and local task age remain evaluable without optional telemetry.

The incident reconciler uses stable server-generated keys. Current conditions create or update an open incident, administrator acknowledgement changes only its workflow state, and a later successful healthy sample resolves it automatically. Browser responses contain normalized values and never contain task UPIDs or raw Proxmox bodies.

ISO bytes are not buffered into the Nimbus data volume. The incoming request is size-checked and streamed as multipart data to Proxmox while Nimbus calculates SHA-256. Nimbus reserves quota in the local database before the stream begins. Upload/delete task UPIDs remain server-only, and a temporary Proxmox error changes operation state without deleting the ownership record.

One-time ISO boot never accepts a raw boot string, CD-ROM slot, volume ID, node, or VMID from the browser. Nimbus loads the active customer-owned mount, verifies the current Proxmox CD-ROM value, saves the exact prior `boot` property internally, and prepends only the verified slot. Restoration compares the current value with Nimbus's armed value before writing. An outside boot-order change therefore produces an error instead of being overwritten.

Email delivery is a separate service layer and never calls Proxmox. Administrators configure a TLS or STARTTLS SMTP endpoint and the public customer-facing panel URL in the control center. The password is encrypted at rest and omitted from every browser response. Normal messages enter a durable SQLite queue; the worker claims one record at a time, retries temporary network/provider failures with increasing delays, and converts provider errors into a small allowlisted code set. Pending text/HTML bodies—including invitation/reset links—are encrypted and erased after success. Connection and end-to-end message tests are rate-limited and audited.

Alert evaluation runs only after a successful resource synchronization. Each enabled assignment condition progresses through healthy, pending, and firing states. Conditions must remain active for the configured duration; an incident creates one deduplicated alert event and its transition back to normal creates one recovery event. Existing stopped guests are baselined without an alert, recent Nimbus stop/shutdown requests suppress expected offline events, and an API synchronization failure never alters alert state. Reassignment resets policy and incident state.

One customer event can fan out to multiple active users in that customer, but every delivery row and preference row belongs to one user. API reads and read-state mutations always filter by the authenticated user ID. Email delivery is opt-in and uses the same encrypted queue and branded template system as administrator test messages.

Native push is an optional delivery branch. In official relay mode, the panel
keeps its users' encrypted APNs device tokens and decides notification content
and timing. It signs the exact relay request with its local Ed25519 installation
key. The relay stores only the corresponding public key, status, bounded replay
nonces, and delivery counters. It validates signatures, clock skew, one-time
nonces, payload limits, token format, environment, and rate limits before using
the developer-owned APNs key with the fixed official topic
`de.liamjayden.nimbusdirect`. Notification content and device tokens are not
written to relay storage or logs. Structured APNs outcomes return to the panel,
which disables only invalid or unregistered device tokens. Direct mode keeps
the same panel-side notification path for custom app forks that use an
operator-owned Apple key and topic. Disabled mode makes no external push call.

Maintenance publication is a separate local authorization flow. Nimbus resolves an all/cluster/node/resource/customer target through current active assignments, converts the result to active customer users, and writes one delivery per affected user in the same transaction that marks the notice published. Customer reads query the delivery user ID rather than recalculating current ownership. A later reassignment therefore cannot transfer historical maintenance visibility or action locks. Drafts have no delivery rows. Scheduled/active state advances from server time, while cancellation and resolution remain administrator-only, CSRF-protected, and audited. For active deliveries, the central resource authorization path maps requested permissions into optional power, console, snapshot-change, or installation-media lock groups and rejects matching customer writes with HTTP 423 before any Proxmox request. Administrators bypass maintenance locks, and read-only operations remain available.

Support authorization is customer-account scoped rather than resource-pool scoped. Ticket creation takes the customer ID only from the authenticated session. An optional resource reference is accepted only when an active local assignment joins that resource to the same customer. Every list, thread, reply, close, reopen, and read-state operation repeats the customer check in the store layer; administrators receive platform scope. Internal notes are filtered in SQL before customer messages are serialized, and customer-facing ticket records report no internal-note count. Audit details contain ticket/message identifiers and workflow metadata, never conversation bodies.

## 5. Administrator assignment workflow

1. Add a Proxmox cluster and encrypted service-account token.
2. Test the connection and synchronize the guest inventory.
3. Create a customer account and one or more Nimbus users. Prefer emailed single-use invitations so administrators do not choose customer passwords.
4. Open **Control center → Inventory**.
5. Select any QEMU VM or LXC container from any node/cluster.
6. Choose the customer, optional display name, allowed operations, snapshot limit, and optional alert policy.
7. Save the local assignment.

Reassigning a resource updates the local assignment and permission rows. Removing it changes the assignment state to `unassigned`. Neither operation creates or modifies a Proxmox pool.

An active customer ISO mount or unresolved one-time boot override blocks reassignment or removal until it is safely restored/ejected. A customer account with non-deleted ISO ownership records cannot be deleted. These guards prevent media or recovery state from becoming silently orphaned or crossing a reassignment boundary.

Administrators open **Control center → Operations** to inspect cluster reachability, node pressure, storage capacity, stale assigned resources, failed/stuck tasks, active incidents, and recent automatic recoveries. A full refresh is independently rate-limited and audited. Acknowledgements record the administrator but cannot disable evaluation. All Operations Center routes require the server-side administrator role and are unavailable to customer sessions.

Administrators use **Control center → Maintenance** to draft and publish planned work or service incidents. A notice can target the whole platform, selected clusters/nodes, individual assigned resources, or customer accounts and optionally lock grouped customer actions. Publishing freezes the affected per-user audience, schedules optional branded email through the existing queue, and prevents later editing. Locks begin with the active window and disappear on resolution or expiry. Active or scheduled notices can be resolved, scheduled notices can be cancelled, and unpublished drafts can be deleted.

Administrators use the shared **Support** workspace for the global customer queue. They can assign one active administrator, change priority/status, add an administrator-only note, or send a public reply. Public replies and status changes can fan out through the encrypted email queue to active users of the ticket's customer. When a ticket is unassigned, customer activity notifies all active administrators; once assigned, only the owner is targeted.

## 6. Customer dashboard

The dashboard returns only resources with an active assignment to the authenticated customer and `view_status` permission. It shows status, cluster, node, type/VMID, CPU, RAM, storage, uptime, IP, and recent activity. LXC storage usage comes from the cluster inventory. Because Proxmox normally reports QEMU filesystem usage as zero in that inventory, synchronization enriches running QEMU guests through the official `get-fsinfo` Guest Agent endpoint, filters non-persistent and duplicate mounts, and stores one normalized value used by cards, details, and storage alerts. A failed Guest Agent read preserves the last valid value; a guest with no valid reading is labeled unavailable rather than zero.

Each resource opens a full detail workspace with status-aware power controls, normalized Proxmox RRD history, allowlisted configuration, guest-reported network addresses, and recent tasks. The Network workspace lazily discovers addresses only for resources visible to the current session, prefers live QEMU Guest Agent/LXC data, and falls back to configured static addresses without returning raw guest configuration. Buttons are generated from assignment permissions for usability, but the same permission is checked again on the server.

Power operations use idempotency keys and return either an immediate result or a tracked Proxmox task. The active browser polls for immediate feedback and the server synchronization cycle independently follows unfinished tasks, so completion state and notifications do not depend on an open page. Nimbus writes a system audit event when tasks finish, updates the expected local status after successful power tasks, and rejects overlapping actions while a recent task is still active.

For assignments with snapshot permissions, Snapshot Center lists normalized Proxmox recovery points and exposes create, restore, and delete independently. The backend enforces the assignment's 1-50 snapshot limit against live Proxmox inventory, validates snapshot names, requires exact-name confirmation for restore/delete, applies the shared action rate limit, tracks the returned UPID, and rejects overlapping resource tasks. Snapshot create/restore fails closed while customer ISO media or a one-time boot override is active.

Console launch creates a short-lived, encrypted, one-time ticket record containing the server-selected console type. LXC and QEMU guests whose display is explicitly `serial0` through `serial3` use Proxmox termproxy with the bundled xterm.js client; other QEMU guests use noVNC. The noVNC client includes mobile keyboard input, latched Ctrl/Alt/Super modifiers, special keys, Ctrl+Alt+Delete, bounded text paste, persistent display preferences, fullscreen, and disconnect. noVNC machine-power extensions are not exposed because they would bypass Nimbus assignment permissions, rate limits, task tracking, and auditing. Both clients connect to the same-origin WebSocket gateway, which consumes the local launch token once, completes the authenticated Proxmox `vncwebsocket` upgrade server-side, and then pipes binary frames. The authenticated console page receives the scoped ticket and, for termproxy, its username only in memory for the handshake. The long-lived Proxmox API token never reaches the browser.

For QEMU assignments with explicit media permissions, the detail page exposes a customer-private ISO library. The server derives the customer from the active VM assignment, scopes every ISO lookup to that customer and cluster, validates the enabled storage policy/quota, and then uses resource coordinates loaded from the database. Customers cannot supply a node, VMID, storage ID, or Proxmox volume ID. LXC media requests are rejected server-side.

With the separate `iso_boot` assignment permission, a mounted customer-owned ISO can be scheduled first for one Nimbus-tracked start, reboot, or reset. The completed power task triggers restoration of the exact saved boot property. The customer can cancel before boot or restore while ejecting; a failed compare remains visible and fail-closed for administrator review.

The Notification Center returns only deliveries for the authenticated login. Users independently enable in-panel/email delivery and action-success, action-failure, infrastructure-alert, and recovery categories. Backend-created event keys prevent task refreshes or repeated synchronization cycles from duplicating a notification.

The Maintenance Center likewise returns only delivery rows for the authenticated login, but maintenance visibility is an operational service record rather than an optional notification category. Active/upcoming notices appear on the overview and in the dedicated timeline even when email is disabled. Email fan-out respects the login's infrastructure/recovery opt-ins and uses the branded encrypted queue.

The Support Ticket Center is shared by active users within one customer account, while read state is private to each login. Customers can open a ticket, optionally link an actively assigned resource, reply, close, and reopen resolved/closed requests. They cannot choose another customer, see internal notes, assign administrators, or change workflow metadata. Ticket create/reply actions have independent user/IP rate limits and every mutation is CSRF-protected.

Account Settings includes passkey enrollment/rename/removal, TOTP enrollment, recovery-code replacement, password-and-code-protected disablement, and user-scoped session management. Starting passkey enrollment and removing a passkey require the current password. Enabling or disabling MFA revokes every other session. An administrator can reset another user's MFA or all passkeys only after re-entering the administrator password; either reset revokes all target sessions and cannot be used on the currently signed-in administrator. Security changes, passkey logins, and recovery-code logins are audited, and queued security notices use the existing encrypted SMTP path when enabled.

The administrator Security & Access Center aggregates active-account MFA coverage, passkey adoption, required-but-unprotected accounts, active sessions, recent successful/failed logins, and security-specific audit events. Failed password or passkey authentication writes an event only when Nimbus can safely associate it with a known account; an unknown attempt remains non-identifying. Optional successful-login messages and mandatory password-change/reset notices reuse the encrypted SMTP queue and contain no credential material.

The unauthenticated sign-in surface also handles invitations and password recovery. It removes the email token from browser history before sending it in a JSON request, validates the token's hash/purpose/expiry server-side, and never creates a session automatically after completion. Users sign in normally afterward, including the existing MFA step. Administrators can inspect pending/expired onboarding and resend or revoke links without seeing the token.

## 7. Security model

- TLS is required for every Proxmox API URL.
- Proxmox token secrets use AES-256-GCM encryption with a key derived from `APP_SECRET`.
- SMTP passwords and queued email bodies use the same authenticated encryption boundary and are never exposed by browser APIs or logs.
- Passwords use scrypt; TOTP secrets use AES-256-GCM; recovery codes are one-way hashed and single-use; WebAuthn stores only public credentials and keyed one-time challenge tokens.
- Invitation and password-reset tokens are random, purpose-bound, `APP_SECRET`-keyed hashes at rest, expire after 30 minutes, and are single-use.
- Sessions are opaque, HTTP-only, SameSite=Strict, and Secure in production; users can review and revoke only their own sessions.
- Native access tokens are opaque, short lived, and hashed at rest; refresh tokens rotate once, have a fixed maximum lifetime, and retain hashed history for reuse detection.
- Native devices and browser sessions share user-scoped review/revocation controls; password and account security events revoke both session types.
- Required-MFA policy is enforced server-side on every request; an unenrolled account cannot reach resources or administrative data.
- State-changing requests require a session-bound CSRF token and same-origin check.
- Password login, MFA verification, invitation delivery, password recovery, account-link validation, security-setting changes, and resource actions have independent rate limits.
- SMTP connection and delivery tests have a separate administrator/user/IP rate limit.
- Full Operations Center refreshes have a separate administrator/IP rate limit; incident acknowledgement is CSRF-protected and audited.
- Maintenance publication has an independent administrator/IP rate limit; every draft, publication, cancellation, and resolution is CSRF-protected and audited.
- Support ticket creation and replies have independent user/IP rate limits; every lookup repeats the customer boundary, and internal notes are administrator-only.
- ISO uploads have an independent per-user hourly rate limit, a hard application size ceiling, per-storage file limits, and per-customer quotas.
- Customer resource authorization is a database join, never a frontend decision.
- User-supplied VMID, node, type, or cluster coordinates are never forwarded.
- Configuration reads and writes use explicit field allowlists.
- Console tickets are encrypted, short-lived, and single-use.
- API task IDs are customer-scoped and idempotent.
- Notification delivery and read-state APIs are user-scoped; deduplication is server-generated.
- Maintenance delivery/read APIs and action locks are user-scoped, published audiences are immutable assignment-derived snapshots, and every locked mutation is rejected server-side before Proxmox is contacted.
- Support ticket APIs are customer-account scoped, support read state is user-scoped, and internal messages are excluded server-side for customers.
- Security headers deny framing and unnecessary browser capabilities.
- Audit logs cover authentication, administration, assignment changes, power requests, configuration, snapshots, console tickets, ISO uploads, mount/eject, one-time boot arm/restore/failure, deletion, and failed uploads.
- Docker runs unprivileged, read-only, without Linux capabilities or privilege escalation.
- SMTP transport requires certificate-verified TLS or STARTTLS; plaintext SMTP and verification bypasses are not supported.

Recommended token privileges must be adjusted to the enabled feature set. A status/power/console MVP generally needs `VM.Audit`, `VM.PowerMgmt`, and `VM.Console`; add `VM.Snapshot`/`VM.Snapshot.Rollback`, selected `VM.Config.*`, and guest-agent audit privileges only when those features are enabled. Operations node telemetry uses `Sys.Audit`; storage capacity telemetry uses `Datastore.Audit` only on intended storage paths. ISO upload/mount adds `VM.Config.CDROM` on managed VMs plus `Datastore.AllocateTemplate` on the specific ISO storage. One-time boot additionally uses `VM.Config.Options` on the managed VMs. Optional deletion currently adds the broader `Datastore.Allocate` privilege and should remain disabled unless required. Do not grant `Administrator`, `Sys.Modify`, user management, or host-shell privileges.

## 8. Practical MVP plan

### Phase 1 — implemented foundation

- Local customer and user accounts.
- Multiple encrypted Proxmox cluster credentials.
- Cluster-wide QEMU/LXC inventory synchronization without pool dependency.
- Direct assignment/reassignment/unassignment and per-resource permissions.
- Customer-only dashboard and power-action authorization.
- Status, resource usage, IP metadata, details, audit history, and task model.
- Full customer instance detail page with usage history, networking, status-aware controls, and live task progress.
- Snapshot Center with per-assignment limits, confirmations, tracked tasks, and audit events.
- Selected configuration services and a short-lived, one-time hybrid termproxy/noVNC console gateway.
- Customer-owned QEMU ISO upload, quota, mount/eject, guarded one-time boot restoration, optional deletion, and administrator storage policies.
- Encrypted SMTP configuration, administrator connection/message tests, durable delivery retries, and sanitized delivery history.
- Per-assignment resource alerts, private notification delivery, customer preferences, action completion events, and branded alert/recovery email.
- TOTP two-factor authentication, one-use recovery codes, active-session management, administrator-assisted reset, and security email notices.
- WebAuthn passkeys with discoverable credentials, required user verification, exact origin/RP binding, one-time challenges, credential counters, account management, and administrator-assisted reset.
- Administrator Security & Access Center with enforceable role-based MFA requirements, restricted enrollment sessions, account posture, failed-login audit events, and optional successful-login email.
- Administrator-issued customer invitations, self-service password recovery, resend/revoke controls, non-enumerating responses, and session-revoking completion.
- Administrator Operations Center with last-good node/storage telemetry, cluster/stale-assignment/task monitoring, persistent acknowledgement, and automatic recovery.
- Targeted maintenance/incident drafts, schedules, immutable per-user audiences, customer timeline/banner, read state, resolution, and branded email.
- Customer-scoped support tickets with resource validation, administrator queue/assignment, internal notes, per-login unread state, audit events, and branded email.
- Versioned Nimbus API v1 with native 2FA login, short-lived bearer access, rotating refresh tokens, device-session controls, shared assignment authorization, administrator aliases, and an OpenAPI 3.1 contract.
- Docker deployment, health/readiness endpoints, and automated security/isolation tests.

### Phase 2 — production hardening

- Replace in-process rate limiting with Redis when running multiple replicas.
- Add key rotation with credential re-encryption.
- Add a durable job runner for sync/task polling rather than one process timer.
- Add pagination and retention policies for large audit/task tables.
- Add per-cluster CA/fingerprint management and outbound network allowlisting.

### Phase 3 — controlled expansion

- Selected configuration editors with quotas and change previews.
- Alert policy templates, webhooks, and support impersonation controls.
- PostgreSQL option and HA deployment.
- External identity providers and organization-level policy templates.

Before external production use, run a penetration test, perform restore drills, validate every role against the exact Proxmox release, and test every enabled operation with the least-privilege token.
