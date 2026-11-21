# API reference

A concise reference for integrators, with one worked example per endpoint. The normative contract is
[spec/protocol.md](../spec/protocol.md) (protocol, signed texts, failure handling) and
[spec/relay-api.yaml](../spec/relay-api.yaml) (OpenAPI). Test vectors for the signed texts, token tags and
envelope frames are in [spec/vectors/v1.json](../spec/vectors/v1.json). Where this page and the spec
differ, the spec wins.

Values in the examples are placeholders: host `push.example.org`, instance id
`6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c`, times around `1795000000`. Signatures are 64 bytes (86 base64url
characters), public keys 32 bytes (43 characters).

## Conventions

- TLS 1.3 only. JSON bodies, decoded strictly: unknown fields, trailing data or a wrong type give
  `422 invalid_item`. Bodies are limited to 128 KiB for `POST /v1/push` and 4 KiB for everything else
  (`413 too_large`).
- Binary values are unpadded base64url. Device and activity tokens are hex (32 to 100 bytes). Token tags
  are lowercase hex of `SHA-256("hl-push-token" || token)[0:16]`.
- Signed texts are fields joined with a single `\n`, no trailing newline. Times are Unix seconds and must be
  within 300 seconds of the relay clock.
- Every response carries `Cache-Control: no-store`, `Strict-Transport-Security`,
  `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'`.

### Request signing (instance endpoints)

| Header | Content |
|---|---|
| `HL-Instance` | instance id (lowercase UUIDv4) |
| `HL-Timestamp` | Unix seconds, no leading zeros |
| `HL-Nonce` | 16 random bytes, base64url (22 characters), never reused |
| `HL-Signature` | Ed25519 signature by the instance key over the request text |
| `HL-Client` | `healthlog/1.49.0`; required when the relay sets a minimum server version |

```
hl-relay-v1
<host>
<instance id>
<METHOD>
<path with query, as sent>
<HL-Timestamp>
<HL-Nonce>
<lowercase hex SHA-256 of the body; of the empty string for no body>
```

The relay checks, in this order: body size, known instance, time window (and not before the relay's own
start), bad-signature budget, signature, tier, request rate, nonce replay, minimum client version.

### Response signing

Every response except `/privacy`, `/terms` and `/` has `HL-Relay-Signature`: an Ed25519 signature by the
relay identity key over

```
hl-relay-resp-v1
<host>
<HL-Nonce of the request, or "-" if it had none or it was malformed>
<HTTP status>
<lowercase hex SHA-256 of the body>
```

Verify it against the pinned keys (`current`, `next`) and treat a missing or wrong signature as a transport
error.

### Error envelope

```json
{ "error": "instance_rate", "scope": "instance", "retryAfter": 41, "limits": { "...": "..." } }
```

`error` is always present. `scope` (`device`, `instance`, `tier`, `global`), `retryAfter` (seconds, spread
by plus or minus 30 %), `relayTime` (on `stale_timestamp`), `reason` (suspension reason or conflict detail)
and `limits` appear when they apply. A refusal of a whole request with a retry hint also sets the
`Retry-After` header.

| Status | `error` values |
|---|---|
| 401 | `unknown_instance`, `bad_signature`, `stale_timestamp`, `replayed` |
| 403 | `instance_revoked`, `instance_suspended`, `invite_required`, `binding_refused`, `challenge_refused`, `activity_refused` (item) |
| 404 | `binding_unknown`, `not_found` |
| 409 | `binding_conflict`, `key_in_use` |
| 410 | `unregistered` (item) |
| 413 | `too_large`, `too_many_items` |
| 422 | `invalid_item`, `env_unsupported` |
| 426 | `min_server_version` |
| 429 | `instance_rate`, `instance_quota`, `binding_quota`, `device_quota`, `global` |
| 502 | `apns_rejected` (item) |
| 503 | `maintenance`, `relay_misconfigured`, `apns_unavailable`, `queue_full`, `registration_paused`, `storage_unavailable`, `overloaded` |

## Instances

### POST /v1/instances

Registers an instance key. No signature headers; the body proves possession of the key. Registering a key
that is already known returns its existing id (`200`).

Proof text: `hl-register-v1\n<host>\n<hex public key>\n<time>`, signed with the new key.

```http
POST /v1/instances HTTP/1.1
Host: push.example.org
Content-Type: application/json
HL-Nonce: q8Jr2mXc0Lw7Vd1sT5yNbA

{"publicKey":"<43 base64url>","client":"healthlog/1.49.0","time":1795000000,"proof":"<86 base64url>"}
```

```http
HTTP/1.1 201 Created
Content-Type: application/json
HL-Relay-Signature: <86 base64url>

{"instanceId":"6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c","tier":"probation","limits":{"devices":20,"provisional":10,"newBindingsPerDay":20,"requestsPerMinute":20,"pushesPerDay":500,"pushesPerMinute":30,"invalidTokensPerDay":20,"challengesPerDay":20,"badSignatureBurst":30}}
```

Add `"invite":"<code>"` while registration is invite-only. Refusals: `401 stale_timestamp` with
`relayTime`, `401 bad_signature`, `403 invite_required`, `403 instance_suspended` or `instance_revoked` for
a known key, `503 registration_paused` (closed, or registration limits reached).

### POST /v1/instances/self/rotate

Replaces the instance key, at most once per UTC day. The request is signed with the old key; the body is a
registration body for the new key, with the proof made by the new key.

```http
POST /v1/instances/self/rotate HTTP/1.1
Host: push.example.org
Content-Type: application/json
HL-Instance: 6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c
HL-Timestamp: 1795000000
HL-Nonce: q8Jr2mXc0Lw7Vd1sT5yNbA
HL-Signature: <86 base64url, by the old key>

{"publicKey":"<43 base64url, new key>","time":1795000000,"proof":"<86 base64url, by the new key>"}
```

```http
HTTP/1.1 200 OK

{"instanceId":"6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c","tier":"standard","limits":{"...":"..."}}
```

Refusals: `429 instance_rate` (already rotated today), `409 key_in_use`. `/v1/status` reports
`keyRotatedDay` for seven days after a rotation.

### DELETE /v1/instances/self

Deletes the instance and every binding it holds. Signed like every instance request, empty body.

```http
DELETE /v1/instances/self HTTP/1.1
HL-Instance: 6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c
HL-Timestamp: 1795000000
HL-Nonce: q8Jr2mXc0Lw7Vd1sT5yNbA
HL-Signature: <86 base64url>
```

```http
HTTP/1.1 204 No Content
HL-Relay-Signature: <86 base64url>
```

### GET /v1/status

The instance's view of the relay: service state (`ok`, `degraded`, `maintenance`, `misconfigured`), tier,
limits, device counts, the current notice, relay time and registration mode.

```http
GET /v1/status HTTP/1.1
HL-Instance: 6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c
HL-Timestamp: 1795000000
HL-Nonce: q8Jr2mXc0Lw7Vd1sT5yNbA
HL-Signature: <86 base64url>
```

```json
{"state":"ok","tier":"probation","limits":{"devices":20,"provisional":10,"newBindingsPerDay":20,"requestsPerMinute":20,"pushesPerDay":500,"pushesPerMinute":30,"invalidTokensPerDay":20,"challengesPerDay":20,"badSignatureBurst":30},"devices":{"active":2,"provisional":0,"limit":20},"notice":null,"relayTime":1795000000,"registration":"open"}
```

`reason` appears for a suspended instance, `keyRotatedDay` after a rotation. A notice looks like
`{"id":"planned_maintenance","level":"planned","until":1795259200}`.

## Bindings

### POST /v1/bindings

Binds a device token to the instance. The instance passes the statement that the app signed with its
binding key, unchanged.

Statement text: `hl-bind-v1\n<host>\n<instance id>\n<hex token tag>\ndevice\n<seq>\n<iat>`.

```http
POST /v1/bindings HTTP/1.1
Content-Type: application/json
HL-Instance: 6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c
HL-Timestamp: 1795000000
HL-Nonce: q8Jr2mXc0Lw7Vd1sT5yNbA
HL-Signature: <86 base64url>

{"token":"<64 hex>","env":"production","bindingKey":"<43 base64url>",
 "statement":{"instanceId":"6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c","tokenTag":"<32 hex>","kind":"device","seq":3,"iat":1794999990},
 "signature":"<86 base64url>","consent":{"textVersion":"2026-11-21","day":"2026-11-21"}}
```

```http
HTTP/1.1 201 Created

{"state":"provisional"}
```

- `201` for a binding new to this instance, `200` with the current state when the token is already bound to
  this instance (a repeated statement, or the same key with a higher `seq`). A binding becomes `active` with the first push Apple accepts.
- Moving a token from another instance needs a statement by the same binding key with a higher `seq`.
- A different binding key for a token whose binding was created or had an accepted push in the last seven
  days gives
  `409 {"error":"binding_conflict","reason":"challenge_sent"}`: the relay sends a challenge push to the
  token (see the next endpoint). `reason` is `challenge_quota` when the token already had a challenge today
  or the instance used its 20 for the day.
- Refusals: `403 binding_refused` (bad device signature, statement for another instance, `seq` not higher,
  pair or token blocked), `422 env_unsupported`, `429 binding_quota` with limits,
  `503 storage_unavailable`.

### DELETE /v1/bindings

Removes a binding the instance holds. Answers `204` whether or not the token was bound to this instance.

```http
DELETE /v1/bindings HTTP/1.1
Content-Type: application/json
HL-Instance: 6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c
HL-Timestamp: 1795000000
HL-Nonce: q8Jr2mXc0Lw7Vd1sT5yNbA
HL-Signature: <86 base64url>

{"token":"<64 hex>"}
```

```http
HTTP/1.1 204 No Content
```

### POST /v1/bindings/challenge (app)

Called by the app after it received a challenge push, whose payload is
`{"aps":{"content-available":1},"c":"<43 base64url>"}`. No instance headers. The answer must arrive within
30 minutes.

Signed text: `hl-challenge-v1\n<host>\n<challenge>\n<hex token tag>`, by the app's current binding key.

```http
POST /v1/bindings/challenge HTTP/1.1
Content-Type: application/json

{"bindingKey":"<43 base64url>","challenge":"<43 base64url>","tokenTag":"<32 hex>","signature":"<86 base64url>"}
```

```http
HTTP/1.1 200 OK

{"state":"provisional"}
```

The new key replaces the old binding; the previous holder gets `404 binding_unknown` on its next push.
Refusal: `403 challenge_refused` for an unknown or expired challenge, a different key or token, or a bad
signature.

### DELETE /v1/bindings/self (app)

The direct opt-out. Deletes the binding without the instance and blocks the pair of token and instance for
365 days.

Signed text: `hl-unbind-v1\n<host>\n<instance id>\n<hex token tag>\n<iat>`.

```http
DELETE /v1/bindings/self HTTP/1.1
Content-Type: application/json

{"token":"<64 hex>","bindingKey":"<43 base64url>",
 "statement":{"instanceId":"6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c","tokenTag":"<32 hex>","iat":1795000000},
 "signature":"<86 base64url>"}
```

```http
HTTP/1.1 204 No Content
```

Refusals: `404 binding_unknown` (no such binding, another instance, another key, or a bad signature),
`401 stale_timestamp`.

### GET /v1/bindings/self (app)

Everything the relay holds about the device's binding. Authenticated by headers.

Signed text: `hl-selfread-v1\n<host>\n<hex token tag>\n<iat>`.

```http
GET /v1/bindings/self HTTP/1.1
HL-Token: <64 hex>
HL-Binding-Key: <43 base64url>
HL-Iat: 1795000000
HL-Signature: <86 base64url>
```

```json
{"kind":"device","instanceId":"6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c","state":"active","env":"production","boundDay":"2026-11-02","lastUsedWeekOf":"2026-11-16","consentVersion":"2026-11-21","consentDay":"2026-11-02"}
```

`lastUsedWeekOf` is the Monday of the week of last use. Refusal: `404 binding_unknown`.

The three app endpoints share one relay-wide bucket (100, refilling 20 per second); over it they answer
`429 global`.

## Push

### POST /v1/push

Up to 50 items. The answer is `200` with one result per item, in request order, unless the whole batch is
refused (`503 maintenance`, `503 relay_misconfigured`, `503 apns_unavailable`, `413 too_many_items`,
`422 invalid_item` for an unparseable body). The relay waits at most 8 seconds for Apple; items still
open then return `503 apns_unavailable` with a retry hint.

| Field | Rules |
|---|---|
| `ref` | `[A-Za-z0-9._:-]{1,40}`, unique in the batch; the idempotency key for 10 minutes |
| `token` | the bound device token (hex) |
| `env` | `production` or `sandbox`, equal to the binding's |
| `class` | `alert`, `silent` or `liveactivity` |
| `ttlSeconds` | positive; clamped to 6 h (alert), 1 h (silent), 4 h (liveactivity) |
| `envelope` | alert and silent: exactly 1,075 bytes (version `0x01`, suite `0x01`, class byte, 32-byte encapsulated key, 1,024-byte ciphertext, 16-byte tag); not allowed for liveactivity |
| `collapse` | 22 base64url characters; required for alert, optional for silent, not allowed for liveactivity |
| `activity` | liveactivity only: the activity token and the statement the app signed when the activity started |

```http
POST /v1/push HTTP/1.1
Content-Type: application/json
HL-Instance: 6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c
HL-Timestamp: 1795000000
HL-Nonce: q8Jr2mXc0Lw7Vd1sT5yNbA
HL-Signature: <86 base64url>

{"items":[
 {"ref":"a1","token":"<64 hex>","env":"production","class":"alert","ttlSeconds":3600,
  "envelope":"<1434 base64url>","collapse":"<22 base64url>"},
 {"ref":"s1","token":"<64 hex>","env":"production","class":"silent","ttlSeconds":3600,
  "envelope":"<1434 base64url>"},
 {"ref":"l1","token":"<64 hex>","env":"production","class":"liveactivity","ttlSeconds":14400,
  "activity":{"token":"<hex activity token>","bindingKey":"<43 base64url>",
   "statement":{"instanceId":"6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c","tokenTag":"<32 hex>","laTokenTag":"<32 hex>","iat":1794990000},
   "signature":"<86 base64url>"}}
]}
```

The activity statement is `hl-activity-v1\n<host>\n<instance id>\n<hex token tag>\n<hex activity token
tag>\n<iat>`, signed by the binding key of the device's active binding; it may be up to 12 hours old.

```json
{"results":[
 {"ref":"a1","status":200,"result":"accepted"},
 {"ref":"s1","status":429,"error":"device_quota","scope":"device","retryAfter":1712},
 {"ref":"l1","status":200,"result":"accepted"}
],"notice":null,"relayTime":1795000000}
```

Item results:

| `status` | `result` or `error` | Meaning |
|---|---|---|
| 200 | `accepted` | Apple accepted the push |
| 200 | `soft_invalid` | Apple answered `BadDeviceToken` or `DeviceTokenNotForTopic` (in `reason`); the binding is marked and deleted on a second hit on another day |
| 200 | `activity_gone` | the Live Activity no longer exists |
| 403 | `activity_refused` | bad activity statement, other binding key, or the binding is still provisional |
| 404 | `binding_unknown` | the token is not bound to this instance |
| 410 | `unregistered` | Apple reports the token as gone; the binding was deleted |
| 422 | `invalid_item` | malformed item, duplicate `ref`, or `env` differs from the binding |
| 429 | `device_quota`, `instance_quota`, `instance_rate`, `binding_quota`, `global` | a limit, with `scope` and `retryAfter` |
| 502 | `apns_rejected` | Apple refused the request (reason in `reason`); nothing was deleted |
| 503 | `apns_unavailable`, `relay_misconfigured`, `maintenance`, `queue_full` | transient; retry within the push's lifetime |

A repeated `ref` within 10 minutes returns the first definite result with `"duplicate":true` and is not
sent again. Transient results are not kept, so a retry really retries.

## Receipts

### POST /v1/receipts

Counts only: of the pushes the relay accepted more than six hours ago, how many a device confirmed through
the envelope receipt. Once per instance per 50 minutes; `confirmed` must not exceed `accepted`, and
`accepted` is at most 100,000. The sums across instances drive the `delivery` field of `/healthz`.

```http
POST /v1/receipts HTTP/1.1
Content-Type: application/json
HL-Instance: 6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c
HL-Timestamp: 1795000000
HL-Nonce: q8Jr2mXc0Lw7Vd1sT5yNbA
HL-Signature: <86 base64url>

{"accepted":42,"confirmed":40}
```

```http
HTTP/1.1 204 No Content
```

Refusal: `429 instance_rate` when sent again within 50 minutes.

## Public pages

### GET /healthz

Signed; `200` when `status` is `ok`, otherwise `503`. No time stamps.

```json
{"status":"ok","db_writable":true,"apns_recent":true,"breaker":"closed","delivery":"ok"}
```

Field meanings: [operations.md](operations.md#health).

### GET /version

Signed.

```json
{"commit":"<git commit>","imageDigest":"sha256:<64 hex>","version":"v1.0.0"}
```

### GET /privacy, GET /terms, GET /

Plain text (`text/plain; charset=utf-8`): the privacy notice, the terms, and a short index with contact
addresses. Not signed. Any other path answers a signed `404 not_found`.
