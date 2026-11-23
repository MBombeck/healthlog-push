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

- TLS 1.3 (TLS 1.2 only for a certificate validation handshake that offers nothing but `acme-tls/1`). JSON
  bodies, decoded strictly: unknown fields, trailing data, a wrong type, a key that matches a field only when
  case is ignored (`Token` for `token`) and a key that appears twice in one object give `422 invalid_item`.
- `HL-Nonce` (16 random bytes, base64url, 22 characters, fresh for every request) is mandatory on every
  `/v1` request (the path `/v1` itself and everything under it), including registration and the app's
  direct calls; without a valid one the relay answers `400 nonce_required`. Only `GET /healthz` and
  `GET /version` may omit it.
- Only canonical paths are routed: a path that `path.Clean` would change (`/v1//push`, `/v1/push/`) gets a
  signed `404 not_found`. The relay never redirects.
- `POST` and `DELETE` must declare their body length in `Content-Length` (`0` for no body); a body of unknown
  length gets `411 length_required`. Bodies are limited to 128 KiB for `POST /v1/push` and 4 KiB for
  everything else (`413 too_large`, checked against the declared length before the body is read). When the
  bodies in flight across all connections would exceed 32 MiB, the relay answers `503 overloaded`.
- Response bodies are at most 64 KiB (65,536 bytes; a body that would be longer is answered `500 internal`).
  A client refuses a response body over 256 KiB without reading on.
- At most 16 concurrent streams per HTTP/2 connection.
- Binary values are unpadded base64url. Device and activity tokens are hex (32 to 100 bytes). Token tags
  are lowercase hex of `SHA-256("hl-push-token" || token)[0:16]`.
- Signed texts are fields joined with a single `\n`, no trailing newline. Times are Unix seconds and must be
  within 300 seconds of the relay clock.
- Every response carries `Cache-Control: no-store`, `Strict-Transport-Security`,
  `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'`. The HTML form of the
  human pages adds only its inline style to the policy, by hash.

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

Before any endpoint runs, the relay checks the nonce header and the declared body length. Then, in this
order: known instance and time window (and not before the relay's own start) from the headers, the body,
signature, tier, request rate, nonce replay, minimum client version. The signature is always verified: failed
attempts by others never cause a valid request to be refused. The per-instance `badSignatureBurst` bucket
only limits how often failures are counted in the metrics.

### Response signing

Every response except `/privacy`, `/terms`, their `.txt` forms, `/.well-known/security.txt` and `/` has `HL-Relay-Signature`: an Ed25519 signature by the
relay identity key over

```
hl-relay-resp-v2
<host>
<METHOD of the request>
<raw path with query, as sent>
<HL-Nonce of the request>
<HTTP status>
<lowercase hex SHA-256 of the body; of the empty string for no body>
```

Rebuild the text from your own request (method, raw path, nonce) and the response (status, raw body), verify
it against the pinned keys (`current`, `next`), and treat a missing or wrong signature as a transport error.
The nonce is `-` only for `/healthz` and `/version` called without one, and for the `400 nonce_required`
refusal; a client that sent a nonce treats a response bound to `-` as a transport error. The full rules are in
[spec/statements.md](../spec/statements.md#hl-relay-resp-v2).

### Error envelope

```json
{ "error": "instance_rate", "scope": "instance", "retryAfter": 41, "limits": { "...": "..." } }
```

`error` is always present. `scope` (`device`, `instance`, `tier`, `global`), `retryAfter` (seconds, spread
by plus or minus 30 %), `relayTime` (on `stale_timestamp`), `reason` (suspension reason or conflict detail)
and `limits` appear when they apply. A refusal of a whole request with a retry hint also sets the
`Retry-After` header, but that header is not signed: take retry hints only from the signed `retryAfter` and
cap them at 86,400 seconds.

| Status | `error` values |
|---|---|
| 400 | `nonce_required` |
| 401 | `unknown_instance`, `bad_signature`, `stale_timestamp`, `replayed` |
| 403 | `instance_revoked`, `instance_suspended`, `invite_required`, `binding_refused`, `challenge_refused`, `activity_refused` (item) |
| 404 | `binding_unknown`, `not_found` |
| 409 | `binding_conflict`, `key_in_use` |
| 410 | `unregistered` (item) |
| 411 | `length_required` |
| 413 | `too_large`, `too_many_items` |
| 422 | `invalid_item`, `env_unsupported` |
| 426 | `min_server_version` |
| 429 | `instance_rate`, `instance_quota`, `binding_quota`, `device_quota`, `global` |
| 502 | `apns_rejected` (item) |
| 500 | `internal` |
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
a known key, `503 registration_paused` (closed, or registration limits reached). In invite mode the code is
spent only when the registration succeeds. During a recovery window the global registration caps are ten
times higher; keys from the restored export get their old id and tier back, any other key starts in
`probation`.

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

Deletes the instance and every binding it holds. Signed like every instance request. The body must be empty
(`Content-Length: 0`); any body is `422 invalid_item`.

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

`keyRotatedDay` appears for seven days after a rotation. A suspended instance gets
`403 instance_suspended` with `reason` instead of a status. A notice looks like
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
- A different binding key for a bound token gives
  `409 {"error":"binding_conflict","reason":"challenge_sent"}`: the relay sends a challenge push to the
  token (see the next endpoint). Only the instance that holds the binding may replace it with a new key
  directly, and only when the binding was created or had its last accepted push seven or more days ago;
  every other instance always gets the challenge.
- After a direct opt-out the binding key is pinned to the token for 365 days. While the token is unbound,
  a binding with any other key (and, after a restore from the export, with any key) also gives
  `409 binding_conflict` with a challenge push; only the device can resolve it. A binding with the pinned
  key goes ahead.
- `reason` is `challenge_quota` when this instance already challenged the token today or used its 20 for
  the day (one challenge per token, instance and day), and `challenge_unsent` (with `retryAfter`) when the
  challenge push could not be queued; the quota is then given back.
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

### POST /v1/bindings/liveactivity

Passes on the device's separate consent to Live Activity start and update over the relay. Start and update
carry their content state in the clear (ActivityKit cannot decrypt), so with this consent the relay and
Apple see when a dose is due and its state; without it the instance can only end an activity. The instance
forwards what the app signed, unchanged.

Signed text: `hl-la-consent-v1\n<host>\n<instance id>\n<hex token tag>\n<text version>\n<iat>`, by the
binding key of the binding.

```http
POST /v1/bindings/liveactivity HTTP/1.1
Content-Type: application/json
HL-Instance: 6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c
HL-Timestamp: 1795000000
HL-Nonce: q8Jr2mXc0Lw7Vd1sT5yNbA
HL-Signature: <86 base64url>

{"token":"<64 hex>","bindingKey":"<43 base64url>",
 "consent":{"textVersion":"2026-11-21","day":"2026-11-21","iat":1794999990},
 "signature":"<86 base64url>"}
```

```http
HTTP/1.1 200 OK

{"liveActivity":"granted"}
```

- The relay stores the text version and the day with the binding. They live and die with it: a rebind by
  the same key to the same instance keeps them, a binding with another key or a move to another instance
  drops them, and every deletion of the binding deletes them.
- `consent.iat` must be within 300 seconds of the relay clock; a repeated consent replaces the stored one.
- Refusals: `401 stale_timestamp` (with `relayTime`), `403 binding_refused` (bad signature),
  `404 binding_unknown` (the token is not bound to this instance, or another binding key),
  `422 invalid_item`, `503 storage_unavailable`.

### DELETE /v1/bindings/liveactivity

The person switched Live Activities over the relay off in the app; the instance drops the consent. The
binding stays. Answers `204` whether or not the token was bound to this instance or had a consent.

```http
DELETE /v1/bindings/liveactivity HTTP/1.1
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
HL-Nonce: q8Jr2mXc0Lw7Vd1sT5yNbA

{"bindingKey":"<43 base64url>","challenge":"<43 base64url>","tokenTag":"<32 hex>","signature":"<86 base64url>"}
```

```http
HTTP/1.1 200 OK

{"state":"provisional"}
```

The new key replaces the old binding (or takes the unbound token); the previous holder gets `404
binding_unknown` on its next push. The binding passes the same quotas as a direct one and counts against
`newBindingsPerDay`; an opt-out pin of the token now names the proven key.
Refusals: `403 challenge_refused` for an unknown or expired challenge, a different key or token, a bad
signature, or an instance that is gone, suspended or revoked or a blocked pair; `429 binding_quota` when the
instance's binding quotas (see `POST /v1/bindings`) do not allow the new binding.

### DELETE /v1/bindings/self (app)

The direct opt-out. Deletes the binding without the instance, blocks the pair of token and instance for
365 days and pins the binding key to the token for 365 days (no other key binds the unbound token without
the challenge). Only the device lifts the block again: a later `POST /v1/bindings` through that instance
whose statement is signed by the same binding key, with a `seq` higher than that of the binding that left
and an `iat` after the opt-out and after the relay start (see `spec/protocol.md`, "Returning"). A block
restored from the registry export cannot be lifted.

Signed text: `hl-unbind-v1\n<host>\n<instance id>\n<hex token tag>\n<iat>`.

```http
DELETE /v1/bindings/self HTTP/1.1
Content-Type: application/json
HL-Nonce: q8Jr2mXc0Lw7Vd1sT5yNbA

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
HL-Nonce: q8Jr2mXc0Lw7Vd1sT5yNbA
HL-Token: <64 hex>
HL-Binding-Key: <43 base64url>
HL-Iat: 1795000000
HL-Signature: <86 base64url>
```

```json
{"kind":"device","instanceId":"6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c","state":"active","env":"production","boundDay":"2026-11-02","lastUsedWeekOf":"2026-11-16","consentVersion":"2026-11-21","consentDay":"2026-11-02","liveActivityConsentVersion":"2026-11-21","liveActivityConsentDay":"2026-11-21"}
```

`lastUsedWeekOf` is the Monday of the week of last use. `liveActivityConsentVersion` and
`liveActivityConsentDay` are present only while the Live Activity consent is given. Refusal:
`404 binding_unknown`.

### DELETE /v1/bindings/self/liveactivity (app)

The device withdraws its Live Activity consent directly, without its instance. The binding and its relay
consent stay; from then on start and update items for the token answer `403 liveactivity_consent_required`.
The body has the shape of the opt-out, with its own statement, so an opt-out signature is no withdrawal and
a withdrawal signature is no opt-out.

Signed text: `hl-la-withdraw-v1\n<host>\n<instance id>\n<hex token tag>\n<iat>`.

```http
DELETE /v1/bindings/self/liveactivity HTTP/1.1
Content-Type: application/json
HL-Nonce: q8Jr2mXc0Lw7Vd1sT5yNbA

{"token":"<64 hex>","bindingKey":"<43 base64url>",
 "statement":{"instanceId":"6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c","tokenTag":"<32 hex>","iat":1795000000},
 "signature":"<86 base64url>"}
```

```http
HTTP/1.1 204 No Content
```

Refusals: `404 binding_unknown` (no such binding, another instance, another key, or a bad signature),
`401 stale_timestamp`. A withdrawal without a stored consent also answers `204`.

The four app endpoints parse the request and check its signature first, for every request and before any
binding is looked up, so the response time does not reveal whether a binding exists. Only failed attempts are charged to one relay-wide bucket
(100, refilling 20 per second); once it is empty, further failures answer `429 global`, scope `global`. A
correctly signed call is never charged there; it is limited per device token instead (bucket of 10,
refilling 10 per hour, `429 device_quota`, scope `device`).

## Push

### POST /v1/push

Up to 50 items. The answer is `200` with one result per item, in request order, unless the whole batch is
refused (`503 maintenance`, `503 relay_misconfigured`, `503 apns_unavailable`, `413 too_many_items`,
`422 invalid_item` for an unparseable body). The relay waits at most 8 seconds for Apple; a result that
is there by then is reported as it is, items still open return `503 apns_unavailable` with a retry hint.

| Field | Rules |
|---|---|
| `ref` | `[A-Za-z0-9._:-]{1,40}`, unique in the batch; the idempotency key for the item's lifetime, at least 10 minutes |
| `token` | the bound device token (hex) |
| `env` | `production` or `sandbox`, equal to the binding's |
| `class` | `alert`, `silent` or `liveactivity` |
| `ttlSeconds` | positive; clamped to 6 h (alert), 1 h (silent), 4 h (liveactivity) |
| `envelope` | alert and silent: exactly 1,075 bytes (version `0x01`, suite `0x01`, class byte, 32-byte encapsulated key, 1,024-byte ciphertext, 16-byte tag); not allowed for liveactivity |
| `collapse` | 22 base64url characters; required for alert, optional for silent, not allowed for liveactivity |
| `activity` | liveactivity only: the event, the content state for start and update, the token and the statement the app signed |
| `activity.event` | `start`, `update` or `end`; `end` when absent |
| `activity.state` | required for `start` and `update`, not allowed for `end`; the closed content state below |
| `activity.token` | `start`: the app's push-to-start token; `update` and `end`: the activity's update token |

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
tag>\n<iat>`, signed by the binding key of the device's active binding; it may be up to 12 hours old. It
covers `update` and `end`.

#### Live Activity start and update

Both need the device's Live Activity consent (`POST /v1/bindings/liveactivity`), otherwise the item answers
`403 liveactivity_consent_required`. The content state travels in the clear to Apple, so it is a closed
template: exactly these six keys, all required, nothing else.

| Key | Values |
|---|---|
| `status` | `pending`, `due`, `overdue`, `snoozed`, `taken` or `skipped` |
| `countdownTarget` | `0`, or unix seconds from one day before to two days after the relay clock |
| `isOverdue`, `confirmed`, `pendingConfirm` | booleans |
| `timeFormatRaw` | `AUTO`, `H12` or `H24` |

A start goes to the app's push-to-start token and is signed as
`hl-la-start-v1\n<host>\n<instance id>\n<hex token tag>\n<hex push-to-start token tag>\n<iat>`; the
statement may be up to 30 days old (the app signs it again when the push-to-start token changes and at least
every 30 days). An update goes to the activity's update token under the activity statement above.

```http
POST /v1/push HTTP/1.1
Content-Type: application/json
HL-Instance: 6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c
HL-Timestamp: 1795000000
HL-Nonce: q8Jr2mXc0Lw7Vd1sT5yNbA
HL-Signature: <86 base64url>

{"items":[
 {"ref":"ls1","token":"<64 hex>","env":"production","class":"liveactivity","ttlSeconds":3600,
  "activity":{"event":"start","token":"<hex push-to-start token>","bindingKey":"<43 base64url>",
   "state":{"status":"due","countdownTarget":1795000600,"isOverdue":false,"confirmed":false,"pendingConfirm":false,"timeFormatRaw":"AUTO"},
   "statement":{"instanceId":"6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c","tokenTag":"<32 hex>","laTokenTag":"<32 hex>","iat":1794000000},
   "signature":"<86 base64url>"}},
 {"ref":"lu1","token":"<64 hex>","env":"production","class":"liveactivity","ttlSeconds":3600,
  "activity":{"event":"update","token":"<hex update token>","bindingKey":"<43 base64url>",
   "state":{"status":"taken","countdownTarget":0,"isOverdue":false,"confirmed":true,"pendingConfirm":false,"timeFormatRaw":"H24"},
   "statement":{"instanceId":"6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c","tokenTag":"<32 hex>","laTokenTag":"<32 hex>","iat":1794999000},
   "signature":"<86 base64url>"}}
]}
```

```json
{"results":[
 {"ref":"ls1","status":200,"result":"accepted"},
 {"ref":"lu1","status":429,"error":"device_quota","scope":"activity","retryAfter":1210}
],"notice":null,"relayTime":1795000000}
```

What Apple receives for the start (`<now>` is the relay clock):

```
{"aps":{"timestamp":<now>,"event":"start","content-state":{"status":"due","countdownTarget":1795000600,"confirmed":false,"pendingConfirm":false,"isOverdue":false,"timeFormatRaw":"AUTO"},"attributes-type":"HealthLogDoseAttributes","attributes":{"v":1},"alert":{"title":{"loc-key":"HL_LA_START_TITLE"},"body":{"loc-key":"HL_LA_START_BODY"}}}}
```

and for an update:

```
{"aps":{"timestamp":<now>,"event":"update","content-state":{"status":"taken","countdownTarget":0,"confirmed":true,"pendingConfirm":false,"isOverdue":false,"timeFormatRaw":"H24"}}}
```

The relay picks Apple's priority from the state, not from the instance: `apns-priority: 10` for the end and
for a start or update whose `status` is `due` or `overdue`, `5` for every other state. Priority 5 does not
count against the device's Live Activity budget at Apple, so routine changes cannot use up the budget a due
dose needs. The start above goes with 10, the update with 5.

Limits: 12 starts per device and day, 12 updates per activity and hour and 48 per day (`429 device_quota`
with scope `activity`), 12 ends per device and day. A key outside the template or a wrong type refuses the
whole request (`422 invalid_item`); a missing key, a value outside its set or a `countdownTarget` out of
bounds refuses the item (`422 invalid_item`).

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
| 200 | `soft_invalid` | Apple answered `BadDeviceToken` or `DeviceTokenNotForTopic` (in `reason`), or a `410` whose `timestamp` lies before the day the binding was made or renewed (`reason` `Unregistered`); the binding is marked and deleted on a second hit on another day |
| 200 | `activity_gone` | the Live Activity no longer exists |
| 403 | `activity_refused` | bad activity statement (or the wrong statement for the event, or too old), other binding key, or the binding is still provisional |
| 403 | `liveactivity_consent_required` | a start or update without the device's Live Activity consent |
| 404 | `binding_unknown` | the token is not bound to this instance |
| 410 | `unregistered` | Apple reports the token as gone, at or after the binding day or without a time; the binding was deleted |
| 422 | `invalid_item` | malformed item, duplicate `ref`, `env` differs from the binding, or a content state outside the template |
| 429 | `device_quota`, `instance_quota`, `instance_rate`, `binding_quota`, `global` | a limit, with `scope` and `retryAfter`. `device_quota` with scope `activity`: the update limit of one Live Activity. `binding_quota` with scope `device`: a soft-invalid binding on the day it failed (one probe push a day); with scope `instance`: a provisional binding that does not fit, or any non-active binding while the instance is over its invalid-token budget |
| 502 | `apns_rejected` | Apple refused the request (reason in `reason`); nothing was deleted |
| 503 | `apns_unavailable`, `relay_misconfigured`, `maintenance`, `queue_full` | transient; retry within the push's lifetime |

A repeated `ref` within the item's lifetime (`ttlSeconds` after clamping, at least 10 minutes) returns the
first definite result with `"duplicate":true` and is not sent again. Transient results are not kept, so a
retry really retries, and an item that Apple did not take for a reason of Apple's or the relay's is taken
off the limits it was counted against, so the retry is not refused by a budget the failure used up.

## Receipts

### POST /v1/receipts

Counts only: of the pushes the relay accepted more than six hours ago, how many a device confirmed through
the envelope receipt. Accepted once per instance per 45 minutes (report every 55 minutes); `confirmed`
must not exceed `accepted`, and `accepted` is at most 100,000. Only `standard` instances count, and each
reported `accepted` is capped at what the relay itself accepted for that instance in the last three days
(today and the two days before). The sums drive the display-only `delivery` field of `/healthz`.

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

Refusal: `429 instance_rate` when sent again within 45 minutes.

## Public pages

### GET /healthz

Signed; `200` when `status` is `ok`, otherwise `503`. No time stamps. `status` depends only on the relay's
own facts (`down` without a usable provider token or after Apple rejected a renewed one, `degraded` when the
store is not writable); `breaker` and `delivery` are display only. A nonce is optional here.

```json
{"status":"ok","db_writable":true,"apns_recent":true,"breaker":"closed","delivery":"ok"}
```

Field meanings: [operations.md](operations.md#health).

### GET /version

Signed.

```json
{"commit":"<git commit>","imageDigest":"sha256:<64 hex>","version":"v1.0.0"}
```

### GET /privacy, GET /terms, GET /.well-known/security.txt, GET /

Plain text (`text/plain; charset=utf-8`): the privacy notice, the terms, the RFC 9116 security contact
(`relay@healthlog.dev` and the repository's GitHub security advisories), and a short index with contact
addresses. Not signed. `/privacy`, `/terms` and `/` answer a browser, that is a request whose `Accept`
header prefers `text/html` over `text/plain`, with an HTML page rendered from the same text; everything
else, including `curl` and a HealthLog server, gets the plain text byte for byte, and both carry
`Vary: Accept`. `/privacy.txt` and `/terms.txt` always answer the plain text, for a reader in a browser who
wants it. Any other path, a known path with another method and any non-canonical path answer a
signed `404 not_found`.
