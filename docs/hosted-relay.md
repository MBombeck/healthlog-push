# The hosted relay

The hosted relay at `https://push.healthlog.dev` serves the HealthLog app from the App Store. It is free, run
by one person on a best-effort basis, and meant for households: one person or a family running their own
HealthLog server. Organisations run their own relay ([self-hosting.md](self-hosting.md)). The
[terms](terms.md) are short, and the [privacy notice](privacy.md) lists everything the relay sees and stores.

## Switching it on

Using the relay is voluntary and takes two steps. The operator of a HealthLog server switches the relay on
for that server, then every person decides in their own app. The app creates its keys and asks for a binding
only after that consent.

The relay only carries what a registered server sends to its own bound devices. The operator never sends
anything through it: no announcements, no update notices, no messages of any kind.

## Contact

- relay@healthlog.dev: operation
- abuse@healthlog.dev: abuse and suspension appeals
- privacy@healthlog.dev: data protection

## Limits

Defaults of the hosted relay (`DefaultLimits` in `internal/relay/config.go`, `DefaultRegistrationLimits` in
`internal/limits/limits.go`). Every `429` names its scope (`device`, `activity`, `instance`, `tier` or `global`) and
carries a retry hint spread by plus or minus 30 %: the `retryAfter` field, and on a refusal of the whole
request also the `Retry-After` header. Clients take the hint only from the signed `retryAfter` (capped at one
day), never from the unsigned header. Request-rate and binding-quota refusals include the instance's limits.

| Limit | probation | standard | Refusal |
|---|---|---|---|
| Active device bindings per instance | 20 | 50; 80 automatically after 30 quiet days above 80 % use; up to 150 by the operator | `429 binding_quota` |
| Provisional bindings at the same time | 10 | 20 | `429 binding_quota` |
| New device bindings per day | 20 | 100 | `429 binding_quota` |
| Authenticated requests per minute | 20 | 60 | `429 instance_rate` |
| Pushes per instance per day | 500 | 10,000 | `429 instance_quota` |
| Pushes per instance per minute | 30 | 120 | `429 instance_rate` |
| Invalid tokens per instance per day | 20 | 100 | above it for 24 h: no new bindings, and provisional and soft-invalid bindings get `429 binding_quota` |
| Conflict challenges per instance per day | 20 | 20 | `409 binding_conflict` with reason `challenge_quota` |
| Failed signatures counted in metrics (token bucket, refills per minute) | 30 | 60 | none: limits only the counting, never refuses a request |

| Per device (every tier) | Value | Refusal |
|---|---|---|
| All classes per day | 300 | `429 device_quota` |
| Alerts | bucket of 20, refills 6 per hour, at most 100 per day | `429 device_quota` |
| Silent pushes per hour | 6 | `429 device_quota` |
| Live Activity starts per day (only with the Live Activity consent) | 12 | `429 device_quota` |
| Live Activity updates per activity (only with the Live Activity consent) | 12 per hour, 48 per day | `429 device_quota`, scope `activity` |
| Live Activity ends per day | 12 | `429 device_quota` |
| Soft-invalid binding | no push on the day it failed, then one probe a day | `429 binding_quota`, scope `device` |
| Challenges per token | 1 per token, instance and day | `409 binding_conflict`, `challenge_quota` |
| Verified app calls (opt-out, self-read, Live Activity withdrawal, challenge answer) | bucket of 10, refills 10 per hour | `429 device_quota` |

| Relay-wide | Value |
|---|---|
| Global push limit per minute | 5 times the busiest minute of the last 7 days, at least 600, at most 6,000 |
| Share of the global limit for standard instances | silent 70 %, Live Activity 85 %, alert 100 % |
| Pool of all probation instances per minute | 10 % of the global limit, at least 60, at most 600 |
| Registrations | 3 per day per IPv4 address or IPv6 /64, 10 per IPv6 /48, 30 per hour and 200 per day globally (ten times the global caps during a recovery window) |
| Failed app calls | token bucket of 100, refills 20 per second, shared by all callers; only failed attempts are charged |
| Connections | 2,000 in total, 8 per IPv4 address or IPv6 /64, 64 per IPv6 /48, 16 HTTP/2 streams per connection |
| Request bodies | `Content-Length` required on `POST` and `DELETE` (`411 length_required`); push batch at most 50 items and 128 KiB, other bodies 4 KiB; 32 MiB in flight in total (`503 overloaded`) |
| Response bodies | at most 64 KiB; clients refuse more than 256 KiB |
| Send queue | 4,096 jobs, 256 per instance; an empty queue always admits, otherwise a job is refused when the estimated wait exceeds 2 s |
| Signed time window | plus or minus 300 s |

After a restart, counts held in memory are gone. Until the next UTC midnight the relay therefore halves the
global registration caps and the per-device silent and Live Activity start and end limits; the
per-activity update counts start again from zero. The daily alert count of a
device, the daily push count of an instance and an instance's anomaly flag are stored and survive a restart.
The per-instance counts of new bindings and challenges and the 24-hour block after an exceeded invalid-token
budget do not; see the known limitations in [threat-model.md](threat-model.md#known-limitations).

## Identity keys

The public identity keys of `push.healthlog.dev` are unpadded base64url Ed25519 public keys. `current` and
`next` were published with v1.0.0, `emergency` with v1.0.2, each in the release notes and in
[`keys/push.healthlog.dev.json`](../keys/push.healthlog.dev.json) in the tagged tree. The HealthLog server ships
them as its hosted relay pins, the iOS app as its `HLPushRelayKeys` build setting.

| Key | Ed25519 public key (base64url) |
|---|---|
| `current` | `IU8JGZzcE-O4gp4q2BL2o6YYNJeHyDg8MNmAGL5_Ypo` |
| `next` | `kPhnCqIwrF_cyQIFTAgCHrWnPavdWkcwMB35oi_wCH0` |
| `emergency` | `dcrihMfqGY7srT95DZrVP7sKA-IS3oJPPhOVbbqTvBU` |

`emergency` is held separately from the relay host and from the operational keys and is never deployed to
the relay. It is used only if both other keys are lost
([key-ceremony.md](key-ceremony.md#lost-current-and-next)).

A new `next` key is published in the release notes of the release that ships it, before the relay switches
to it. Rotations are announced in [transparency.md](transparency.md) at least 7 days before the
relay signs with the new key. How the keys are made, kept and rotated is in
[key-ceremony.md](key-ceremony.md) and [operations.md](operations.md#relay-identity-key).
