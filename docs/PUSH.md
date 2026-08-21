# Native push architecture

Nimbus Direct supports three explicit modes:

| Mode | Intended use | Apple credentials on panel |
| --- | --- | --- |
| `disabled` | No native push | None |
| `relay` | Official App Store app | Never |
| `direct` | Custom/forked app signed by its operator | Operator-owned key only |

When enabled, native pushes cover customer-authorized VM/LXC action outcomes,
customer infrastructure alerts and recoveries, administrator Operations Center
incidents and recoveries, published/resolved/cancelled maintenance, support
ticket creation/replies/status changes, and important account-security events.
Support recipients and maintenance audiences are resolved from the
same server-side tenant and delivery records used by the web panel. The actor
does not receive a duplicate support push for their own action, and private
internal notes never generate a customer push.

## Official relay mode

```env
PUSH_MODE=relay
PUSH_RELAY_URL=https://push.liamjayden.dev
PUSH_RELAY_TIMEOUT_SECONDS=10
```

The relay URL must be an HTTPS origin without a path, query, credentials, or
fragment. The real official origin is distributed by the Nimbus Direct app
developer. Do not copy an Apple key into the panel.

On first delivery the panel creates an Ed25519 key pair. Its private key is
encrypted in the panel SQLite database with `APP_SECRET`; only the public key
and derived installation ID are registered with the relay. Requests contain a
timestamp and random single-use nonce and sign this canonical value:

```text
HTTP method
request path
timestamp
nonce
base64url(SHA-256(exact request body))
```

The delivery body contains only the APNs token, production/sandbox environment,
title, body, notification type, and optional notification/resource/collapse
identifiers. The official APNs topic is not caller-selectable. The relay rejects
unsupported fields, malformed tokens, oversized payloads, stale/replayed
requests, revoked installations, and excess traffic.

## Direct mode for custom forks

Direct mode is not a way to send notifications to the official App Store app.
It is for a separately signed fork whose operator owns its Apple credentials:

```env
PUSH_MODE=direct
APNS_KEY_ID=XXXXXXXXXX
APNS_TEAM_ID=YOURTEAMID
APNS_TOPIC=com.example.custom-nimbus
APNS_PRIVATE_KEY_BASE64=BASE64_ENCODED_OPERATOR_OWNED_P8
APNS_TIMEOUT_SECONDS=10
```

The topic must match that custom app's bundle identifier. Never use or request
the Nimbus Direct developer's `.p8` key.

## Outcomes and cleanup

Both delivery paths normalize APNs results into success, invalid device,
provider authentication, rate limited, temporary failure, or permanent
rejection. `BadDeviceToken`, `DeviceTokenNotForTopic`, and `Unregistered`
disable the affected local device registration. Other failures do not silently
remove it. Logs contain panel user/device row IDs and outcome codes, not APNs
tokens, private keys, notification titles, or bodies.

The relay registration can be key-rotated or revoked through signed lifecycle
endpoints. The developer-operated relay is distributed and deployed separately;
it is deliberately not included in the Nimbus panel repository or release
archive. Normal operators do not deploy that service.
