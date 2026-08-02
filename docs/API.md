# Nimbus Direct API v1

Nimbus Direct includes a first-party, versioned API for the planned mobile app
and other trusted Nimbus clients. It is not a direct Proxmox proxy.

Every VM or container request still passes through Nimbus's local:

1. authenticated-user lookup;
2. customer and account status checks;
3. direct resource-assignment lookup;
4. assignment-permission check;
5. action and resource-state validation;
6. rate limiting and audit logging;
7. official Proxmox API client.

A customer cannot select a Proxmox node or VMID for an action. The client sends
the opaque Nimbus `resourceId`; Nimbus obtains the cluster, node, resource type,
and VMID from its own authorized database record.

## Discovery and OpenAPI

The following endpoints do not require authentication:

```text
GET /api/v1
GET /api/v1/openapi.json
```

`/api/v1` reports the API version, token lifetimes, supported feature families,
and whether the installation is a public read-only demo. The OpenAPI 3.1
document is the source contract for mobile-client generation and API testing.

## Native authentication

Browser sessions continue to use the existing secure cookie and CSRF model.
Native applications use opaque tokens:

- Access token: `nmb_at_…`, short lived (15 minutes by default).
- Refresh token: `nmb_rt_…`, fixed device-session lifetime (30 days by default).
- Refresh tokens are single-use and rotate on every refresh.
- Reuse of an already rotated refresh token revokes the entire device session.
- Password changes, account disablement, customer deletion, 2FA reset, and
  account-link completion revoke affected native sessions.
- Raw access and refresh tokens are never stored in the Nimbus database.
  Nimbus stores only APP_SECRET-bound token hashes.

Configure the lifetimes and per-user device limit in `.env`:

```env
API_ACCESS_TOKEN_MINUTES=15
API_REFRESH_TOKEN_DAYS=30
API_MAX_DEVICE_SESSIONS=10
```

### Sign in

```bash
curl -sS https://panel.example.com/api/v1/auth/token \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "customer@example.com",
    "password": "private-account-password",
    "deviceName": "Liam iPhone",
    "platform": "ios",
    "appVersion": "1.0.0"
  }'
```

Without 2FA, Nimbus returns the access token, refresh token, expiration times,
public user record, and the new device-session record.

When 2FA is enabled, Nimbus returns HTTP `202`:

```json
{
  "mfaRequired": true,
  "challengeToken": "short-lived-opaque-challenge",
  "expiresAt": 1780000000000
}
```

Complete it with:

```bash
curl -sS https://panel.example.com/api/v1/auth/mfa \
  -H 'Content-Type: application/json' \
  -d '{
    "challengeToken": "short-lived-opaque-challenge",
    "code": "123456",
    "deviceName": "Liam iPhone",
    "platform": "ios",
    "appVersion": "1.0.0"
  }'
```

Authenticator codes and one-use recovery codes use the same validation as the
web login.

### Call an authenticated endpoint

```bash
curl -sS https://panel.example.com/api/v1/resources \
  -H 'Authorization: Bearer nmb_at_REPLACE_WITH_ACCESS_TOKEN'
```

Native bearer requests do not use a CSRF token. Nimbus does not enable
cross-origin browser access, so this is not a replacement for browser CSRF
protection. HTTPS is mandatory in production.

### Rotate tokens

```bash
curl -sS https://panel.example.com/api/v1/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refreshToken":"nmb_rt_REPLACE_WITH_REFRESH_TOKEN"}'
```

The response contains a new access token and a new refresh token. The client
must atomically replace both stored values. Only one refresh request should run
per device at a time. If a client submits the old refresh token again, Nimbus
assumes possible token theft and revokes that device session.

### Sign out and manage devices

```text
POST   /api/v1/auth/logout
GET    /api/v1/auth/session
GET    /api/v1/auth/devices
DELETE /api/v1/auth/devices/{sessionId}
```

The existing account session view also includes native devices. A user can
revoke browser sessions and mobile-device sessions from either client.

## Mobile credential storage

The mobile app should:

- keep the access token in memory when practical;
- store the refresh token only in iOS Keychain or Android Keystore-backed secure
  storage;
- never store tokens in logs, crash reports, analytics, plain preferences,
  `AsyncStorage`, screenshots, or clipboard history;
- replace the old refresh token atomically after every successful rotation;
- clear local credentials after `invalid_refresh_token`,
  `refresh_token_reused`, account disablement, or logout;
- pin no Proxmox certificate or credentials—the app connects only to Nimbus.

Nimbus access and refresh tokens must never be placed in query strings.

## Integration API keys

Integration keys are separate from native mobile sessions. They are intended
for Home Assistant, monitoring, automation, and private service integrations.
They use the prefix `nmb_key_` and the normal bearer header:

```bash
curl -sS https://panel.example.com/api/v1/resources \
  -H 'Authorization: Bearer nmb_key_REPLACE_WITH_SECRET'
```

The administrator first opens **Control center → Users → API access** for an
account and enables its maximum policy:

- maximum grouped permissions;
- maximum visible resources, or all resources currently visible to the user;
- maximum number of active keys;
- maximum key lifetime;
- whether a key without an expiry is allowed.

The user then opens **Settings → API keys**, chooses a key name, a subset of
those permission groups, individual VMs/LXCs, and an expiry. Nimbus calculates
and displays the final effective actions before asking for the current password
and, when enabled, a 2FA code. The raw secret is returned exactly once.

The authorization intersection is recalculated on every request:

```text
active user/customer
AND live direct assignment
AND assignment permission
AND administrator API policy group/resource
AND key group/resource
```

Reducing an administrator policy or changing/removing a direct assignment
therefore removes access immediately without rotating the key. Disabling API
access revokes all active keys. The database stores only an `APP_SECRET`-bound
hash and a safe display hint, never the raw key.

Permission groups currently include Server overview, Power management,
Snapshot management, Installation media, Console access, Notifications,
Maintenance information, and Support tickets. Administrators also have
separate customer, user, cluster, assignment, operations, maintenance,
support, email, security, ISO-policy, and audit groups.

Integration keys cannot create or manage other API keys, change passwords or
2FA, manage native sessions, or call an endpoint not explicitly mapped to one
of their groups. Customer keys can never expand beyond the account's directly
assigned resources.

Key-management endpoints:

```text
GET    /api/v1/api-keys
POST   /api/v1/api-keys/preview
POST   /api/v1/api-keys
GET    /api/v1/api-keys/{keyId}
DELETE /api/v1/api-keys/{keyId}
```

These endpoints require an interactive browser or native session; an
integration key is always rejected.

## Resource and task API

The principal customer routes are:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/me` | User, security state, sessions, and capabilities |
| `GET` | `/api/v1/dashboard` | Complete role-aware dashboard payload |
| `GET` | `/api/v1/resources` | Paginated and filterable authorized resources |
| `GET` | `/api/v1/resources/{resourceId}` | Resource details and safe configuration |
| `GET` | `/api/v1/resources/{resourceId}/network` | Current network information |
| `GET` | `/api/v1/resources/{resourceId}/history` | Proxmox RRD usage history |
| `POST` | `/api/v1/resources/{resourceId}/actions` | Permitted power action |
| `POST` | `/api/v1/resources/{resourceId}/console` | Short-lived console session |
| `GET` | `/api/v1/tasks` | Visible task history |
| `GET` | `/api/v1/tasks/{taskId}` | Refresh one task |

Power and other long-running operations may return HTTP `202` with a task.
Poll the returned task ID until `completed` is true. Clients should send a
unique `Idempotency-Key` header for retryable resource actions.

Assignment isolation deliberately returns `404 resource_not_found` when a
customer requests an unassigned resource. This avoids confirming that another
customer's resource exists.

Interactive administrator sessions can list and control every current
Proxmox-discovered VM and container, whether assigned or unassigned. Resource
responses carry the administrator's effective permissions so native clients
can render the available controls without borrowing a customer's assignment.
Stale resources missing from the latest successful inventory remain excluded.

The console-create response includes a browser `launchUrl`, a
`nativeLaunchUrl`, and a `console` descriptor whose `type` is `terminal` or
`graphical`. Native clients open only `nativeLaunchUrl` in an isolated web
view. Nimbus validates the still-active user, assignment, and console
permission, sets a 45-second path-restricted HttpOnly cookie, and redirects to
the same-origin console page. Nimbus automatically uses termproxy/xterm.js for
LXC and serial-display QEMU guests and noVNC for graphical QEMU guests. The
app's normal bearer token is never injected into JavaScript or a WebSocket
request.

## Snapshots and installation media

Snapshot routes:

```text
GET  /api/v1/resources/{resourceId}/snapshots
POST /api/v1/resources/{resourceId}/snapshots
POST /api/v1/resources/{resourceId}/snapshots/{snapshotName}/restore
POST /api/v1/resources/{resourceId}/snapshots/{snapshotName}/delete
```

Nimbus checks each assignment's snapshot permissions and limit before it calls
Proxmox.

QEMU installation-media routes:

```text
GET    /api/v1/resources/{resourceId}/media
POST   /api/v1/resources/{resourceId}/media/upload
POST   /api/v1/resources/{resourceId}/media/mount
POST   /api/v1/resources/{resourceId}/media/eject
POST   /api/v1/resources/{resourceId}/media/boot-once
POST   /api/v1/resources/{resourceId}/media/boot-once/cancel
DELETE /api/v1/resources/{resourceId}/media/{imageId}
```

Uploads use `application/octet-stream` with `policyId` in the query string and
the URL-encoded original name and exact byte count in `X-Nimbus-Filename` and
`X-Nimbus-Size`. Nimbus validates the optional `Content-Length`, calculates
SHA-256 while streaming, and forwards the ISO to Proxmox without keeping a
second copy.

ISO ownership, quota, storage policy, VM assignment, and permission checks stay
server side.

## Notifications, maintenance, and support

```text
GET   /api/v1/notifications
PATCH /api/v1/notifications/preferences
POST  /api/v1/notifications/read-all
POST  /api/v1/notifications/{deliveryId}/read
POST  /api/v1/push/devices
POST  /api/v1/push/devices/unregister

GET  /api/v1/maintenance
POST /api/v1/maintenance/{deliveryId}/read

GET   /api/v1/support/tickets
POST  /api/v1/support/tickets
GET   /api/v1/support/tickets/{ticketId}
PATCH /api/v1/support/tickets/{ticketId}
POST  /api/v1/support/tickets/{ticketId}/messages
POST  /api/v1/support/tickets/{ticketId}/read
POST  /api/v1/support/tickets/{ticketId}/close
POST  /api/v1/support/tickets/{ticketId}/reopen
```

Ticket lookups remain customer scoped. Administrator-only ticket fields and
internal notes are enforced on the server.

Push-device endpoints accept only normal native bearer sessions, never
integration API keys. An iOS registration supplies its APNs token, sandbox or
production environment, and app version. Nimbus stores a keyed hash plus an
encrypted token. APNs delivery is optional and reports `pushAvailable: false`
when the panel has no Apple signing key configured.

## Administrator API

The existing administrator API is available in the versioned namespace:

```text
/api/v1/admin/...
```

It provides clusters, customers, users, invitations, direct assignments,
assignment policies, ISO storage policies, email, security policy, Operations
Center, and Maintenance Center operations. The unversioned `/api/admin/...`
routes remain available to the current web interface.

Native administrator calls use the same bearer tokens and `admin` role check.
The complete operation list and request shapes are in `/api/v1/openapi.json`.

## Error model

Errors use JSON:

```json
{
  "error": "resource_not_found",
  "message": "Optional safe explanation",
  "requestId": "request-correlation-id"
}
```

Common status codes:

- `400`: invalid request;
- `401`: missing/expired access token, invalid credentials, or invalid refresh;
- `403`: authenticated but not permitted, mandatory 2FA enrollment, or public
  demo read-only enforcement;
- `404`: not found or hidden by tenant isolation;
- `409`: resource/task state conflict;
- `429`: rate limited; honor `Retry-After`;
- `500`/`502`/`503`: temporary Nimbus or Proxmox-side failure.

The response never contains a Proxmox API token, Proxmox service-account
password, unrestricted Proxmox response, or another customer's assignment.

## Deployment

No new Proxmox role or permission is required for the Nimbus API itself. API
clients can invoke only features already enabled for the central Nimbus
Proxmox service account.

For the internal-address installation, keep using:

```bash
docker compose \
  -f compose.yaml \
  -f compose.internal.yaml \
  up -d --build --force-recreate panel
```

The public container mapping remains only:

```yaml
ports:
  - "4173:4173"
```

Put Nimbus behind HTTPS. Native apps connect to the public Nimbus URL, while
Nimbus continues to reach Proxmox through the private routing and CA settings
from `compose.internal.yaml`.
