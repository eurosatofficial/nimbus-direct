# Nimbus Direct

Nimbus Direct is a modern, self-hosted customer control panel for Proxmox VE. Administrators assign individual QEMU virtual machines and LXC containers to customer accounts in Nimbus's own database.

**No per-customer Proxmox resource pools are created or required. No agent, daemon, package, or custom software is installed on Proxmox nodes. Customers never receive Proxmox credentials.**

## What is included

- Administrator control center for clusters, customers, users, inventory, direct assignments, permissions, and audit logs.
- Customer dashboard scoped to active local assignments.
- Start, stop, shutdown, reboot, reset, suspend, and resume permission model.
- Server-side ownership and permission validation before every Proxmox call.
- Full QEMU/LXC detail workspace with status-aware controls, CPU/RAM/storage, uptime, safe configuration, network addresses, and Proxmox RRD history.
- Live customer-safe Proxmox task progress, completion feedback, duplicate-action prevention, and recent per-resource tasks.
- Customer-owned QEMU ISO libraries with direct-to-Proxmox streaming upload, per-customer quotas, mount/eject controls, optional deletion, and server-side ownership validation.
- Snapshot, selected configuration, and short-lived console-ticket service methods.
- Encrypted Proxmox token storage with AES-256-GCM.
- Scrypt passwords, opaque sessions, CSRF/origin checks, rate limits, security headers, and audit records.
- Background resource synchronization that preserves assignments during Proxmox failures.
- Docker deployment with a read-only, unprivileged container.
- Interactive demo mode and 22 automated isolation/security/integration tests.

The complete design—including schema, authorization sequence, API endpoints, least-privilege guidance, and phased MVP plan—is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Requirements

- Docker with Compose, or Node.js 24+ for local development.
- Proxmox VE reachable over HTTPS from the Nimbus container.
- One privilege-separated Proxmox API token per configured cluster.
- A valid TLS certificate or private CA supplied to the container. TLS verification must not be disabled.

## Quick demo

```bash
cp .env.example .env
```

Set a unique `APP_SECRET`, the bootstrap passwords, and keep `ALLOW_DEMO_DATA=true`. Then:

```bash
docker compose run --rm panel node scripts/setup.mjs
docker compose up -d --build
```

Open `http://127.0.0.1:4173`. The demo creates five simulated resources across several nodes and directly assigns three to the first customer. Remove the bootstrap passwords from `.env` after setup.

## Production setup

### 1. Configure Nimbus

Copy `.env.example` to `.env` and set at minimum:

```env
NODE_ENV=production
APP_SECRET=generate-a-unique-random-secret-of-at-least-32-characters
SESSION_COOKIE_SECURE=true
TRUST_PROXY=true
ALLOW_DEMO_DATA=false

BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_PASSWORD=use-a-unique-password-of-at-least-12-characters
```

Generate the application secret with a password manager or:

```bash
openssl rand -base64 48
```

The secret protects session hashes and encrypts stored Proxmox token secrets. Back it up in a secrets manager. Changing it invalidates sessions and makes existing encrypted cluster credentials unreadable until rotated.

### 2. Create a least-privilege Proxmox service account

Create a dedicated Proxmox user and privilege-separated API token. Enable only the features needed in Nimbus.

A practical role for status, usage, power, and console access is:

```text
VM.Audit VM.PowerMgmt VM.Console
```

Add only the permissions required by enabled optional features:

```text
VM.Snapshot VM.Snapshot.Rollback
VM.Config.CPU VM.Config.Memory VM.Config.Options
VM.GuestAgent.Audit
```

Apply the custom role to `/vms` when Nimbus should discover and manage all guests, or to explicit `/vms/{vmid}` paths for a smaller allowlist. Apply the intended role to both the backing user and the privilege-separated token so the token remains the intersection of both ACLs.

Do not grant `Administrator`, `Sys.Modify`, user management, host-shell access, or unrelated configuration permissions. Storage privileges are not needed unless the ISO feature is enabled as described below.

### 3. Initialize and start

```bash
docker compose build --pull panel
docker compose run --rm panel node scripts/setup.mjs
```

Remove `BOOTSTRAP_ADMIN_PASSWORD` and any customer bootstrap passwords from `.env`, then:

```bash
docker compose up -d
docker compose ps
docker compose logs --tail=100 panel
```

Put an HTTPS reverse proxy in front of Nimbus. Docker Compose publishes port `4173` on all host interfaces so it is reachable across internal/external host networking; restrict access to the reverse proxy or trusted networks with the host firewall. Preserve `Host`, `X-Forwarded-For`, and `X-Forwarded-Proto`.

### 4. Add Proxmox clusters

Sign in as the platform administrator and open **Control center → Clusters**.

For each cluster, enter:

- A local cluster ID and display name.
- The certificate-matching API URL, for example `https://pve.example.com:8006`.
- The API token ID, for example `nimbus@pve!panel`.
- The token secret.

Nimbus encrypts the token secret before writing it to SQLite. Test the connection, then synchronize the inventory.

### 5. Assign resources directly

1. Create a customer in **Control center → Customers**.
2. Create the customer's Nimbus user in **Control center → Users**.
3. Open **Control center → Inventory**.
4. Choose any QEMU VM or LXC container from any configured cluster or node.
5. Select the customer and allowed operations.
6. Save.

The assignment is effective immediately. Reassignment and removal update Nimbus only; Proxmox pools are untouched.

### 6. Enable customer ISO media (optional)

ISO media is available for QEMU virtual machines only. In Proxmox, enable `iso` content on the intended file-based storage. Add these narrowly scoped privileges to the Nimbus service account:

```text
# On the managed VM paths:
VM.Config.CDROM

# On /storage/{storage-id}:
Datastore.Audit Datastore.AllocateTemplate
```

`Datastore.AllocateTemplate` permits ISO upload. Keep customer deletion disabled unless it is genuinely required. Proxmox currently requires the broader `Datastore.Allocate` privilege to delete an ISO volume; that privilege can also affect other storage content. If deletion is enabled, grant it only on the specific ISO storage.

Then:

1. Open **Control center → ISO storage**.
2. Select a cluster and choose **Discover ISO storage**.
3. Enable a discovered storage and set the per-file maximum and per-customer quota.
4. Open **Control center → Inventory → Policy** for a QEMU VM.
5. Enable **View installation media**, **Upload ISO images**, and **Mount and eject ISO images**. Enable deletion only when the storage policy and Proxmox ACL intentionally allow it.

Customers will see **Installation media** on the VM detail page. Uploaded bytes stream through Nimbus directly into the official Proxmox upload endpoint; the Nimbus data volume stores ownership, quota, task, and audit metadata but not a second ISO file.

For Nginx, disable request buffering on the Nimbus proxy and size the body/timeouts for your configured maximum, for example:

```nginx
client_max_body_size 9g;
proxy_request_buffering off;
proxy_read_timeout 2h;
proxy_send_timeout 2h;
```

If another proxy or Cloudflare sits in front of Nimbus, its request-size and timeout limits must also allow the configured ISO size. Use a protected direct/internal Nimbus route for large uploads if that proxy cannot accept them.

## Internal Proxmox addresses and private CAs

Keep the TLS certificate hostname in the cluster API URL. To resolve it to an internal address only inside the container, configure the variables at the end of `.env.example` and use:

```bash
docker compose -f compose.yaml -f compose.internal.yaml up -d --build
```

Mount only the public CA certificate. Never copy a private CA key into Nimbus and never disable TLS verification.

## Data, backups, and upgrades

SQLite data is stored in the `nimbus-data` volume. Stop Nimbus before copying it, or use a SQLite-aware backup process. Back up both the database and `APP_SECRET`, store them separately, and test restoration.

The numbered schema is in `migrations/001_initial.sql`, with additive task indexes in `migrations/002_task_tracking_indexes.sql` and ISO ownership/policy tables in `migrations/003_iso_media.sql`. Runtime startup creates the equivalent schema idempotently, so this release does not require a manual migration command. Take a database backup before every update.

## Operations

- `GET /api/health`: liveness.
- `GET /api/ready`: initial setup status.
- JSON logs are written to stdout/stderr.
- Inventory synchronization defaults to 60 seconds (`RESOURCE_SYNC_SECONDS`).
- Missing guests are marked stale; their customer assignments are preserved.
- Proxmox tasks are stored using their UPID, but browser APIs return only normalized customer-safe task records. The instance page polls active tasks automatically and pauses overlapping power requests.
- ISO upload ceilings are controlled by `ISO_MAX_UPLOAD_MB` and `ISO_UPLOAD_TIMEOUT_MINUTES`; storage policies can impose lower limits and customer quotas.

## Console security

The panel pins the official noVNC 1.7 client. A console launch creates an encrypted, short-lived, single-use Proxmox `vncproxy` ticket. noVNC connects only to a same-origin Nimbus WebSocket URL; Nimbus consumes the local launch token, authenticates the upstream Proxmox `vncwebsocket` upgrade with the encrypted service-account credential, and pipes framebuffer data. Proxmox requires the short-lived VNC ticket as the noVNC password, so it is released only to the authenticated, still-authorized console page over HTTPS and held in browser memory for the handshake. The long-lived Proxmox API token never reaches the browser.

## Verification

```bash
npm run check
```

The suite verifies credential encryption, direct customer/resource/permission authorization, cross-customer denial, tampered-resource denial, assignment preservation across synchronization, token handling, password/session security, Proxmox request mapping, customer-scoped task/audit access, ISO ownership/quota isolation, streamed multipart upload, and guarded CD-ROM mount/eject behavior.

Before serving external customers, complete the Phase 2 hardening work in the architecture document, run a penetration test, validate least-privilege ACLs on your exact Proxmox release, and perform backup/restore drills.
