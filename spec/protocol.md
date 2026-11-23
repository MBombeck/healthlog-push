# Relay protocol, version 1

This document specifies the HTTP protocol of the HealthLog push relay: who talks to it, every endpoint, the
order of checks, the results, the limits and what the relay stores. The signed texts are in
`spec/statements.md`, the end-to-end envelope in `spec/envelope.md`, the machine-readable endpoint
description in `spec/relay-api.yaml`. Where this document and the Go code under `internal/` disagree, the
code is the reference and this document gets fixed.

Examples use the host `push.example.org`. The relay operated by the HealthLog project runs at
`push.healthlog.dev`.

## Actors

| Actor | Holds | Talks to the relay |
|---|---|---|
| **Instance**: one self-hosted HealthLog server | an Ed25519 instance key per relay host, an X25519 sender key per relay host | all `/v1` endpoints except the four app endpoints, every request signed |
| **App**: the HealthLog iOS app on one device | an Ed25519 binding key per installation and relay host, X25519 device keys | only `POST /v1/bindings/challenge`, `DELETE /v1/bindings/self`, `GET /v1/bindings/self`, `DELETE /v1/bindings/self/liveactivity`, each signed with the binding key |
| **Relay** | the relay identity key (Ed25519), the token MAC keys, read access to a short-lived APNs provider token | Apple Push Notification service |
| **Apple** (APNs) | | receives fixed-template pushes from the relay |
| **Operator** of the relay | a local operator interface on the relay host | not over HTTP |

What each party learns:

- The relay learns which instance sends how many pushes of which class to which device token, and when. It
  never learns the content: every alert and silent push carries a sealed envelope it cannot open, and the
  only visible text it can produce is a fixed localisation key.
- Apple learns the same metadata plus the opaque envelope.
- With the device's separate Live Activity consent, the relay and Apple also see the content state of Live
  Activity starts and updates in the clear: when a dose is due and its state, from a closed template without
  any free text (see "Live Activity consent").
- An instance learns nothing about devices bound to other instances. Every answer about a token that is not
  bound to the asking instance is the same `404 binding_unknown`.

## Transport

- HTTPS only, TLS 1.3 minimum. TLS 1.2 is offered solely to an ACME TLS-ALPN-01 validation handshake, that
  is a handshake whose only offered ALPN protocol is `acme-tls/1`; a handshake that offers `acme-tls/1`
  next to anything else gets the TLS 1.3 configuration.
- HTTP/1.1 and HTTP/2; at most 16 concurrent streams per HTTP/2 connection.
- Server timeouts: read header 5 s, read 10 s, write 15 s, idle 60 s. Request headers at most 8 KiB.
- At most 2000 concurrent connections in total, 8 per IPv4 address or IPv6 /64 and 64 per IPv6 /48. A
  HealthLog server needs one connection. Connections over a limit are closed at accept, without a response.
- Every response carries `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
  `Strict-Transport-Security: max-age=31536000` and `Content-Security-Policy: default-src 'none'`. The HTML
  pages (see Human pages) carry a policy that adds only their one inline style, allowed by its SHA-256
  hash, and no script.
- The relay sends no CORS headers.
- An unknown path, or a known path with another method, answers `404 not_found` (signed).
- Only canonical paths are routed. A path that `path.Clean` would change (for example `/v1//push` or
  `/v1/push/`) answers `404 not_found` (signed). The relay never answers with a redirect.
- Every `/v1` request (the path `/v1` itself and every path under `/v1/`) carries a valid `HL-Nonce` (see
  "Headers"); otherwise the relay answers `400 nonce_required` before anything else, before the path check.
  Only `GET /healthz` and `GET /version` may omit it.
- `POST` and `DELETE` requests declare their body length with `Content-Length` (`0` for no body; an HTTP/2
  request whose headers end the stream counts as `0`). A body of unknown length, for example chunked, is
  refused with `411 length_required`, a declared length above 128 KiB with `413 too_large`, both before a
  byte of the body is read. The declared length is reserved against a relay-wide budget of 32 MiB for request
  bodies in flight; when it would be exceeded the answer is `503 overloaded` with a retry of about 2 s.
- A response body is never longer than 65 536 bytes: a body that would be longer is replaced by `500
  internal`. Clients refuse a response body longer than 262 144 bytes without reading it further.
- Every JSON body is parsed strictly: an unknown field, trailing data after the value, a key that matches a
  field only when case is ignored (`Token` for `token`) and a key that appears twice in one object are all
  refused with `422 invalid_item`. A body therefore parses in exactly one way.

The client address is read only for the registration limiter and the connection limiter, in memory, and is
never stored or logged.

## Headers

| Header | Direction | Used on | Value |
|---|---|---|---|
| `HL-Instance` | request | instance endpoints | instance id, lowercase UUIDv4 |
| `HL-Timestamp` | request | instance endpoints | unix seconds, decimal |
| `HL-Nonce` | request | every `/v1` request, including registration and the app endpoints; optional only on `GET /healthz` and `GET /version` | 16 random bytes from a CSPRNG, unpadded base64url (22 characters), fresh for every request |
| `HL-Signature` | request | instance endpoints (`hl-relay-v1`), `GET /v1/bindings/self` (`hl-selfread-v1`) | Ed25519 signature, unpadded base64url |
| `HL-Client` | request | instance endpoints | `name/major.minor.patch`, for example `healthlog/1.49.0`; name `[a-z0-9-]{1,32}` |
| `HL-Token` | request | `GET /v1/bindings/self` | APNs device token, hex |
| `HL-Binding-Key` | request | `GET /v1/bindings/self` | Ed25519 binding public key, unpadded base64url |
| `HL-Iat` | request | `GET /v1/bindings/self` | unix seconds, decimal |
| `HL-Relay-Signature` | response | every JSON response and every `204` | `hl-relay-resp-v2` signature, unpadded base64url |
| `Retry-After` | response | request-level refusals with a retry hint | seconds, decimal; not signed, clients ignore it and use the body's `retryAfter` |

## Request signing

Instance endpoints: `POST /v1/instances/self/rotate`, `DELETE /v1/instances/self`, `POST /v1/bindings`,
`DELETE /v1/bindings`, `POST /v1/bindings/liveactivity`, `DELETE /v1/bindings/liveactivity`,
`POST /v1/push`, `POST /v1/receipts`, `GET /v1/status`.

Each request carries `HL-Instance`, `HL-Timestamp`, `HL-Nonce` and `HL-Signature`, the last being the
instance key's signature over the `hl-relay-v1` text (`spec/statements.md`). The nonce and the declared body
length are checked first for every `/v1` request (see "Transport"). Then the relay checks, in this order, and
stops at the first failure:

| # | Check | Refusal |
|---|---|---|
| 1 | `HL-Instance` is a UUIDv4 and names a known instance; nothing is read, hashed or verified before this | `401 unknown_instance` |
| 2 | `HL-Timestamp` parses, lies within 300 s of the relay clock and is not earlier than the start of the relay process | `401 stale_timestamp` with `relayTime` |
| 3 | the declared length is within the limit of the endpoint (128 KiB for `/v1/push`, 4 KiB otherwise), then the body is read | `413 too_large` |
| 4 | `HL-Nonce` and `HL-Signature` are well formed and the signature verifies | `401 bad_signature` |
| 5 | the instance is not revoked or suspended | `403 instance_revoked`, `403 instance_suspended` with `reason` |
| 6 | the instance is within its requests-per-minute limit (every request that reaches this step counts, whatever its later result) | `429 instance_rate`, scope `instance`, with `limits` |
| 7 | the nonce was not seen for this instance | `401 replayed` |
| 8 | the nonce store has room (2000 per instance, 200000 in total) | `503 overloaded`, retry about 5 s |
| 9 | when the relay has a minimum server version configured: `HL-Client` parses and its version is not lower | `426 min_server_version` |

The signature is always verified. Failed attempts are never a reason to refuse a request that verifies, so
knowing an instance id does not allow locking that instance out. The per-instance bad-signature bucket
(`badSignatureBurst`) only limits how often a failure is counted in the metric
`hlp_auth_failures_total{reason="bad_signature"}`.

A nonce is recorded at step 8 and kept for 600 s (twice the skew), so a request cannot be replayed while its
timestamp is valid. Because timestamps before the relay start are refused, a restart that empties the nonce
store does not reopen a replay window. An instance that receives `stale_timestamp` computes its offset from
`relayTime` and retries once with a corrected time and a fresh nonce.

After step 9 the relay records the week of contact for the instance (used for retention) and runs the
endpoint.

## Response signing

Every response the relay writes through its JSON reply path (every `/v1` response, `/healthz`, `/version`,
the router's `404`) carries `HL-Relay-Signature`: the relay identity key's signature over the
`hl-relay-resp-v2` text (`spec/statements.md`): host, request method, raw request path with query, the
request's `HL-Nonce`, the status code and the hex SHA-256 of the body. The nonce field is `-` only when the
request carried no valid nonce: `/healthz` and `/version` called without one, the `400 nonce_required`
refusal, and the router's `404` for an unknown path outside `/v1` (under `/v1` the nonce is checked first). The
pages `/`, `/privacy`, `/terms`, `/privacy.txt` and `/terms.txt` are not signed.

Instances and the app pin the relay identity public keys (`current` and `next`) at build time. They rebuild
the text from their own request and the received response and verify it. A response whose signature is
missing or does not verify against a pinned key, or that is bound to `-` although a nonce was sent, is a
transport error. It is never acted on as a refusal, a revocation, an upgrade demand, a deletion or a notice.
Clients take retry hints only from the signed body's `retryAfter`, capped at 86 400 seconds, never from the
`Retry-After` header, and refuse a response body longer than 262 144 bytes.

## Error envelope

Every refused request and every refused push item uses the same JSON shape. Only `error` is always present.

```json
{ "error": "instance_rate", "scope": "instance", "retryAfter": 41, "limits": { "...": 0 } }
```

| Field | Type | Present when |
|---|---|---|
| `error` | string | always: a fixed identifier from the tables below |
| `scope` | string | for rate and quota refusals: `device`, `activity` (the update limit of one Live Activity), `instance`, `tier` or `global` |
| `retryAfter` | integer, seconds | when the relay knows when a retry can succeed |
| `relayTime` | integer, unix seconds | on `stale_timestamp` |
| `reason` | string | on `instance_suspended` (closed set: `abuse`, `spam`, `invalid_tokens`, `harassment`, `legal`, `compromised`, `terms`, `operator_request`) and on `binding_conflict` (`challenge_sent`, `challenge_quota`, `challenge_unsent`) |
| `limits` | object | on `instance_rate` from the request-rate check and on `binding_quota`: the tier limits of the instance |

A JSON encoding failure on the relay, or a response body that would exceed 65 536 bytes, answers `500` with
`{"error":"internal"}`.

### Retry-After

`retryAfter` is the time until the limit that refused the request resets, spread by plus or minus 30 % so that
refused clients do not return in step: `max(1, floor(s * (0.7 + 0.6 * u)))`, with `s` the base duration in
seconds (at least 1) and `u` uniform in [0, 1). For a request-level refusal the same value is also sent as
the `Retry-After` header, for generic HTTP clients; that header is not signed, and HealthLog clients ignore
it. For a push item it is only in the item's `retryAfter`. A client waits at least the signed `retryAfter`,
capped at 86 400 seconds, before retrying anything within the named scope.

## Registration and rotation

### POST /v1/instances

Registers a new instance. Not signed with `hl-relay-v1`; the body carries a proof of possession.

```json
{ "publicKey": "<base64url 32>", "client": "healthlog/1.49.0", "time": 1795000000, "proof": "<base64url 64>", "invite": "<code>" }
```

- `publicKey`: the new Ed25519 instance public key. `proof`: its signature over `hl-register-v1`.
- `time`: unix seconds within 300 s of the relay clock.
- `client` (optional): the `HL-Client` format.
- `invite` (optional, at most 64 characters): a one-time code, required only while registration is in invite
  mode.
- Unknown fields, trailing data, case-folded or duplicate keys, or a malformed value make the body invalid.

Checks in order:

| # | Check | Result |
|---|---|---|
| 0 | valid `HL-Nonce`; `Content-Length` declared | `400 nonce_required`; `411 length_required` |
| 1 | body at most 4 KiB | `413 too_large` |
| 2 | body well formed | `422 invalid_item` |
| 3 | `time` within the skew | `401 stale_timestamp` with `relayTime` |
| 4 | `proof` verifies | `401 bad_signature` |
| 5 | the key is already registered: revoked | `403 instance_revoked` |
| | suspended | `403 instance_suspended` with `reason` |
| | otherwise | `200` with the existing `instanceId` (idempotent; this is also the recovery path after a lost relay database) |
| 6 | the store accepts writes | `503 storage_unavailable`, retry about 5 min |
| 7 | registration mode `closed` | `503 registration_paused`, retry about 1 h |
| | mode `invite` and no valid unused code | `403 invite_required` |
| 8 | registration limits (see "Limits") | `503 registration_paused`, retry about 1 h |
| 9 | created; in mode `invite` the code is spent now, so a registration refused at step 8 keeps it | `201` |

```json
{ "instanceId": "6f1c2a4e-1b9d-4c3e-8a7f-0d2b5e9c1a37", "tier": "probation", "limits": { "devices": 20, "...": 0 } }
```

A new instance starts in tier `probation`. While the operator has opened a recovery window (after the relay
lost its database and imported its registry export), the global registration caps are ten times higher
(never unlimited) and the per-address caps still apply. Only the instances that came back from the export
keep their tier: their keys are already known, so they get their old id back at step 5. Any other key
registers in `probation`, as outside the window. No host name, address or contact detail is part of a
registration.

### POST /v1/instances/self/rotate

Replaces the instance key. The request is authenticated with the old key (request signing above); the body
has the registration shape for the new key, with `proof` made by the new key.

| Check | Result |
|---|---|
| body malformed, `time` stale or `proof` invalid | `422 invalid_item` |
| the instance already rotated on this UTC day | `429 instance_rate`, scope `instance`, retry about 1 h |
| the new key is registered for any instance, this one included | `409 key_in_use` |
| store write failed | `503 storage_unavailable` |
| done | `200` with `instanceId`, `tier`, `limits` |

The old key stops working at once. `GET /v1/status` reports `keyRotatedDay` for 7 days after a rotation, so
an operator notices a rotation they did not make. An instance whose key was stolen and rotated by somebody
else recovers by registering a new instance; devices then bind to the new instance id with their binding
key, and the stolen instance cannot take them back.

### DELETE /v1/instances/self

Deletes the instance and all its bindings. The body must be empty (`Content-Length: 0`); any body is `422
invalid_item`. `204` on success, `503 storage_unavailable` when the store write fails. Afterwards the instance id is unknown (`401 unknown_instance`).

### Tiers

| Tier | Meaning |
|---|---|
| `probation` | every new instance; lower limits; a separate global pool |
| `standard` | after at least 7 days, at least one push accepted by Apple, and no anomaly |
| `suspended` | set by the operator with a reason; bindings stay; every signed request answers `403 instance_suspended` |
| `revoked` | set by the operator; bindings deleted; the record stays so the key cannot register again |

Promotion runs once a day. An instance is not promoted while it is flagged (it started a conflict challenge
or exceeded its invalid-token budget): the flag is stored in the instance record as a day (`flaggedDay`) and
blocks promotion on that day and the next, so neither the day change nor a restart drops it. Nor is it
promoted while the last 7 days (today and the six days before, the same window as the operator's suspects
list) show more than 20 rebinds, or more than 20 % invalid tokens over at least 10 sends. A `standard` instance whose device limit is the default 50
is raised to 80 after 30 quiet days with more than 80 % of the limit in use. The operator can set a device
limit from 1 to 150.

## Device binding

A device token is bound to exactly one instance at a time. The binding is keyed by a MAC of the token, holds
the hash of the device's binding key and is created only with a statement signed by that key.

### POST /v1/bindings

Instance-authenticated. The instance forwards what the app produced, unchanged, plus the consent record.

```json
{
  "token": "<hex>",
  "env": "production",
  "bindingKey": "<base64url 32>",
  "statement": { "instanceId": "6f1c2a4e-...", "tokenTag": "<hex 32>", "kind": "device", "seq": 7, "iat": 1795000000 },
  "signature": "<base64url 64>",
  "consent": { "textVersion": "2026-11-21", "day": "2026-11-21" }
}
```

| Field | Format |
|---|---|
| `token` | APNs device token, hex, 64 to 200 characters |
| `env` | `production` or `sandbox` |
| `bindingKey` | Ed25519 public key, base64url |
| `statement.instanceId` | must equal `HL-Instance` |
| `statement.tokenTag` | lowercase hex tag of `token` |
| `statement.kind` | `device` |
| `statement.seq` | integer, at least 0 |
| `statement.iat` | unix seconds within 300 s |
| `signature` | `hl-bind-v1` signature by `bindingKey` |
| `consent.textVersion` | `[A-Za-z0-9._-]{1,32}` |
| `consent.day` | `YYYY-MM-DD` |

Parsing (after request signing):

| Check | Result |
|---|---|
| malformed body, tag not matching the token, wrong `kind`, negative `seq` | `422 invalid_item` |
| `statement.instanceId` is not the requesting instance | `403 binding_refused` |
| `iat` stale | `401 stale_timestamp` with `relayTime` |
| signature does not verify | `403 binding_refused` |

Rules, in order:

| # | Situation | Result |
|---|---|---|
| 1 | `env` is not served by this relay (the hosted relay serves `production` only) | `422 env_unsupported` |
| 2 | the store does not accept writes | `503 storage_unavailable`, retry about 5 min |
| 3 | the pair (token, this instance) is blocked by a direct opt-out, and the statement is not the device's return (see "DELETE /v1/bindings/self") | `403 binding_refused` |
| 4 | the token is blocked by the operator and not currently bound to this instance | `403 binding_refused` |
| 5 | the token is unbound, its device opted out within the last 365 days (opt-out pin), and the binding key is not the pinned key (or the pin has no key, after a restore) | `409 binding_conflict`, see "Conflict" |
| 6 | same binding key as the stored binding, same instance, same `seq` | `200` with the stored state (idempotent repeat) |
| 7 | same binding key, `seq` not higher than the stored one | `403 binding_refused` |
| 8 | a different binding key than the stored binding, and either the request comes from another instance than the holder, or the binding's last accepted push (without one, its binding day) is less than 7 days ago | `409 binding_conflict`, see "Conflict" |
| 9 | the binding is new to this instance and a quota is exhausted (see below) | `429 binding_quota`, scope `instance`, with `limits` |
| 10 | stored | `201` when the token was not bound to this instance before, `200` when it was |

Response body on success: `{ "state": "provisional" }` (or the stored state on an idempotent repeat or a
re-bind by the same instance).

- **Trust on first use.** The first valid statement for a token creates the binding and fixes its binding
  key.
- **Moving to another instance** needs a statement by the same key with a higher `seq`. A former instance
  does not have the key; an old statement names the old instance and carries a lower `seq`.
- **Seven-day fallback.** A binding whose last accepted push (or, without one, whose binding day) is 7 or
  more days ago can be replaced by a statement with a different key directly, without a challenge, but only
  by the instance that holds the binding. This covers a restored device with a new key whose challenge push
  cannot arrive. Any other instance always needs the challenge, which only the device can answer, so a
  former instance that kept the token cannot take over a binding that went quiet.
- **Opt-out pin.** After a direct opt-out the token is unbound, but the hash of the binding key that opted
  out stays pinned to the token for 365 days. While the token is unbound, a binding with any other key, for
  example a key that a second instance made up, is a conflict that only the device can resolve.
- **Provisional.** A new binding is `provisional` until Apple accepts the first push to it, then `active`.
  Provisional bindings do not count against the device limit. A provisional binding without an accepted
  push for more than 2 days is removed.
- A re-bind by the instance that already holds the token keeps its state and its alert counter; a move to
  another instance starts `provisional` and counts as a rebind for that instance.

Binding quotas, checked only for a binding that is new to the instance:

| Condition | Retry |
|---|---|
| the instance exceeded its invalid-token budget in the last 24 h | until the block ends |
| (the same quotas apply when a conflict is resolved through `POST /v1/bindings/challenge`, and such a binding counts against `newBindingsPerDay`) | |
| new bindings today at the tier limit `newBindingsPerDay` | 1 day |
| provisional bindings at `provisional`, or active bindings at `devices` | 1 h |

### Conflict

A bind request with a valid statement but a different key than the live binding (rule 8), or than the opt-out
pin of an unbound token (rule 5), never takes the token on the spot. The relay sends a challenge to the
device token instead and answers `409`:

```json
{ "error": "binding_conflict", "reason": "challenge_sent" }
```

- The challenge is 32 random bytes, unpadded base64url. It is sent as a background push to the token in the
  request's environment, payload `{"aps":{"content-available":1},"c":"<challenge>"}`, priority 5, push type
  `background`, expiration 30 minutes.
- At most one challenge per token, instance and UTC day, and at most `challengesPerDay` (20) per instance
  per day. One instance therefore cannot use up the challenge of another, and an instance can wake a device
  at most once a day. Over either limit the answer is `409 binding_conflict` with `reason: challenge_quota`
  and no push is sent.
- When the challenge push cannot be queued, the token's and the instance's challenge counts are given back,
  the pending challenge is dropped, and the answer is `409 binding_conflict` with `reason: challenge_unsent`
  and `retryAfter` (about 1 minute).
- Starting a challenge flags the instance (`flaggedDay`; it is not promoted that day or the next).
- Pending challenges live in memory only, for 30 minutes.

### POST /v1/bindings/challenge

Sent by the app directly, not by the instance.

```json
{ "bindingKey": "<base64url 32>", "challenge": "<43 characters>", "tokenTag": "<hex 32>", "signature": "<base64url 64>" }
```

| Check | Result |
|---|---|
| body over 4 KiB | `413 too_large` (failed attempt) |
| malformed | `422 invalid_item` (failed attempt) |
| no pending challenge with this value, expired, other token tag, `bindingKey` not the key of the conflicting request, or `hl-challenge-v1` signature invalid | `403 challenge_refused` (failed attempt) |
| per-device limit for verified app calls | `429 device_quota`, scope `device` |
| the instance of the conflicting request is gone, suspended or revoked, or the pair is blocked | `403 challenge_refused` (the challenge is used up) |
| the binding quotas of that instance (see the binding quotas under `POST /v1/bindings`) | `429 binding_quota`, scope `instance` (the challenge is used up) |
| store write failed | `503 storage_unavailable` |
| done | `200 { "state": "provisional" }` |

On success the binding of the conflicting request (instance, new key, its `seq`, `env`, consent) replaces
the old binding, or takes the unbound token. It passes the same binding quotas as a direct binding and, when
it is new to that instance, counts against `newBindingsPerDay`. When the token has an opt-out pin, the pin
now names the key the device proved. The old holder gets `404 binding_unknown` on its next push to that
token.

### DELETE /v1/bindings

Instance-authenticated. Body `{ "token": "<hex>" }`. Removes the binding when the token is bound to the
requesting instance. Answers `204` in every case where the body is valid, bound or not, so it reveals
nothing; `422 invalid_item` for a malformed body, `503 storage_unavailable` when the delete fails.

### Live Activity consent

Live Activity start and update need a second, separate consent of the device, besides the relay consent of
the binding. ActivityKit cannot decrypt, so start and update carry their content state in the clear: with
this consent the relay and Apple see when a dose is due and its state (see "Live Activity content state").
Without it, the instance can only end an activity, as before. The consent is state of the binding: the text
version and the day are stored with it, `GET /v1/bindings/self` returns them, and they live and die with
the binding.

- The device signs it (`hl-la-consent-v1`, `spec/statements.md`); the instance passes it on unchanged with
  `POST /v1/bindings/liveactivity`.
- The instance drops it when the person switches it off in the app: `DELETE /v1/bindings/liveactivity`.
- The device withdraws it directly at the relay, without its instance: `DELETE /v1/bindings/self/liveactivity`
  (`hl-la-withdraw-v1`, see "Direct calls from the app").
- It belongs to the binding key that signed it. A rebind by the same key to the same instance keeps it; a
  binding with another key, a move to another instance, an opt-out and every deletion of the binding drop
  it.

### POST /v1/bindings/liveactivity

Instance-authenticated, body at most 4 KiB.

```json
{
  "token": "<hex>",
  "bindingKey": "<base64url 32>",
  "consent": { "textVersion": "2026-11-21", "day": "2026-11-21", "iat": 1795000000 },
  "signature": "<base64url 64>"
}
```

| Field | Format |
|---|---|
| `token` | APNs device token of the binding, hex, 64 to 200 characters |
| `bindingKey` | the binding key of the device, base64url |
| `consent.textVersion` | the version of the Live Activity consent text the person accepted, `[A-Za-z0-9._-]{1,32}` |
| `consent.day` | `YYYY-MM-DD`, the day of the consent |
| `consent.iat` | unix seconds within 300 s of the relay clock |
| `signature` | `hl-la-consent-v1` signature by `bindingKey` over host, the requesting instance, the token tag, `textVersion` and `iat` |

| Check | Result |
|---|---|
| malformed body, unknown field, bad format | `422 invalid_item` |
| `consent.iat` stale | `401 stale_timestamp` with `relayTime` |
| signature does not verify | `403 binding_refused` |
| the instance is gone | `401 unknown_instance` |
| no binding of the token held by the requesting instance, or another binding key | `404 binding_unknown` |
| store write failed | `503 storage_unavailable`, retry about 5 min |
| stored | `200 { "liveActivity": "granted" }` |

A repeated consent replaces the stored text version and day.

### DELETE /v1/bindings/liveactivity

Instance-authenticated. Body `{ "token": "<hex>" }`. Removes the Live Activity consent of the binding when
the token is bound to the requesting instance; the binding stays. Like `DELETE /v1/bindings` it answers
`204` in every case where the body is valid, bound or not, with or without a consent; `422 invalid_item`
for a malformed body, `503 storage_unavailable` when the write fails.

## Direct calls from the app

The app talks to the relay only on these four endpoints, without any account identifier or server
credential, each signed with its binding key and carrying `HL-Nonce`. It verifies every answer against the
pinned relay identity keys.

Each endpoint parses the request and then checks the signature first, outside the relay lock and for every
request, before it looks up any binding; so the response time does not reveal whether a binding exists (see
"Uniform answers"). A failed attempt (too large, malformed, stale, unknown
binding or bad signature) is charged to one relay-wide token bucket (capacity 100, refill 20 per second);
when it is empty, failed attempts are answered `429 global`, scope `global`, retry about 2 s, instead of
their own refusal. A request that verifies is never charged there, so junk traffic cannot block an opt-out,
a self-read, a withdrawal or a challenge answer. Verified calls are limited per device token: a bucket of 10, refilling 10
per hour, shared by the four endpoints; over it `429 device_quota`, scope `device`, with `retryAfter`.

### DELETE /v1/bindings/self

The direct opt-out. The device leaves an instance without the instance's cooperation.

```json
{ "token": "<hex>", "bindingKey": "<base64url 32>", "statement": { "instanceId": "...", "tokenTag": "<hex 32>", "iat": 1795000000 }, "signature": "<base64url 64>" }
```

| Check | Result |
|---|---|
| body over 4 KiB | `413 too_large` |
| malformed, tag not matching the token, instance id not a UUIDv4 | `422 invalid_item` |
| `iat` stale | `401 stale_timestamp` with `relayTime` |
| no binding for the token, bound to another instance, other key, or `hl-unbind-v1` signature invalid | `404 binding_unknown` |
| per-device limit for verified app calls | `429 device_quota`, scope `device` |
| store write failed | `503 storage_unavailable` |
| done | `204` |

On success the relay deletes the binding, drops pending challenges for the token, blocks the pair (token
MAC, instance id) for 365 days and pins the binding key to the token for 365 days:

- The pair block stores the day, the SHA-256 of the binding key that opted out and the `seq` of the binding
  it left, as JSON. No time of day is stored.
- The opt-out pin stores the day and the same key hash, keyed by the token alone. While the token is
  unbound, a binding by any instance with another key is `409 binding_conflict` with a challenge push (rule
  5); only the device can answer it. A binding with the pinned key itself (the device moving to another
  server) goes ahead as usual.
- The `iat` of the opt-out statement is kept in memory for 10 minutes only, never stored.

The instance that was left cannot bind the token again with anything it holds: a statement made before the
opt-out is older than the opt-out, and it cannot make a new one without the binding key. A second instance
it registers cannot bind it either: its own key is not the pinned one.

**Returning.** Only the device lifts the block. A `POST /v1/bindings` from that instance whose statement is
signed by the same binding key, with a `seq` higher than the stored one and an `iat` later than both the
opt-out statement (while that is still in memory) and the start of the relay process, removes the block and
is then handled as a new binding (rules 4 to 10, `provisional`, the binding quotas apply). A statement made
shortly before the opt-out is at most 300 s old when it is used, so 10 minutes in memory are enough, and
after a restart every statement must be newer than the start. Any other statement for the pair still gets
`403 binding_refused`. A block restored from the registry export carries no key and can be lifted by
nobody; after a restore a device returns to that instance only with a new token. A pin restored from the
export carries no key either, so after a restore every new binding of that token needs the challenge; a
resolved challenge updates the pin to the key the device proved.

The app signs such a statement only when the person turns the relay on again for that server. After a
direct opt-out it treats the relay as off for that account: a later `rebind_needed` or any other server
state never makes it sign a new binding statement on its own.

### GET /v1/bindings/self

The device reads everything the relay holds about its binding. Inputs travel in `HL-Token`,
`HL-Binding-Key`, `HL-Iat` and `HL-Signature` (`hl-selfread-v1`).

| Check | Result |
|---|---|
| malformed header | `422 invalid_item` |
| `HL-Iat` stale | `401 stale_timestamp` with `relayTime` |
| no binding, other key, or signature invalid | `404 binding_unknown` |
| per-device limit for verified app calls | `429 device_quota`, scope `device` |
| done | `200` |

```json
{
  "kind": "device",
  "instanceId": "6f1c2a4e-1b9d-4c3e-8a7f-0d2b5e9c1a37",
  "state": "active",
  "env": "production",
  "boundDay": "2026-11-21",
  "lastUsedWeekOf": "2026-11-16",
  "consentVersion": "2026-11-21",
  "consentDay": "2026-11-21",
  "liveActivityConsentVersion": "2026-11-21",
  "liveActivityConsentDay": "2026-11-21"
}
```

`lastUsedWeekOf` is the first day of the week of the last accepted push. Weeks are blocks of seven UTC days
starting on a Monday, so `lastUsedWeekOf` is always a Monday. `liveActivityConsentVersion` and
`liveActivityConsentDay` are the separate Live Activity consent; both are absent when it was not given or
was withdrawn.

### DELETE /v1/bindings/self/liveactivity

The device withdraws its Live Activity consent directly, without its instance. The body has the shape of
the opt-out; the statement is `hl-la-withdraw-v1`.

```json
{ "token": "<hex>", "bindingKey": "<base64url 32>", "statement": { "instanceId": "...", "tokenTag": "<hex 32>", "iat": 1795000000 }, "signature": "<base64url 64>" }
```

| Check | Result |
|---|---|
| body over 4 KiB | `413 too_large` |
| malformed, tag not matching the token, instance id not a UUIDv4 | `422 invalid_item` |
| `iat` stale | `401 stale_timestamp` with `relayTime` |
| no binding for the token, bound to another instance, other key, or `hl-la-withdraw-v1` signature invalid (an opt-out signature does not verify here) | `404 binding_unknown` |
| per-device limit for verified app calls | `429 device_quota`, scope `device` |
| store write failed | `503 storage_unavailable` |
| done | `204` |

On success the relay removes the Live Activity consent from the binding; the binding, its relay consent and
its state stay. A withdrawal without a stored consent also answers `204`. From then on start and update
items for the token are refused with `403 liveactivity_consent_required`; an `end` still goes through.

### Uniform answers

For a token that is not bound to the asking party the relay always answers the same way: `404
binding_unknown` for push items and the self endpoints, `204` for `DELETE /v1/bindings`. There is no
`binding_moved`, and no answer distinguishes "never bound", "bound elsewhere", "wrong key" and "bad
signature". `409 binding_conflict` is only ever sent to an instance that presented a valid device statement
for that very token.

The same holds for the work done. The app-direct endpoints verify the signature first, for every request,
before the binding is looked up, so each answer costs one Ed25519 verification whether or not a binding
exists; a party that knows a token and a former binding key cannot learn from the response time whether
the device is still bound with that key.

## Push

### POST /v1/push

Instance-authenticated. Body at most 128 KiB.

```json
{
  "items": [
    { "ref": "01JTESTVECT000000000000001", "token": "<hex>", "env": "production", "class": "alert",
      "ttlSeconds": 7200, "envelope": "<base64url, 1434 characters>", "collapse": "<22 characters>" },
    { "ref": "sync-2026-11-21T07", "token": "<hex>", "env": "production", "class": "silent",
      "ttlSeconds": 3600, "envelope": "<base64url, 1434 characters>" },
    { "ref": "end-cm_med_1-2026-11-21", "token": "<hex>", "env": "production", "class": "liveactivity",
      "ttlSeconds": 3600,
      "activity": { "token": "<hex>", "bindingKey": "<base64url 32>",
                    "statement": { "instanceId": "...", "tokenTag": "<hex 32>", "laTokenTag": "<hex 32>", "iat": 1795000000 },
                    "signature": "<base64url 64>" } },
    { "ref": "start-cm_med_1-2026-11-21", "token": "<hex>", "env": "production", "class": "liveactivity",
      "ttlSeconds": 3600,
      "activity": { "event": "start", "token": "<hex push-to-start token>", "bindingKey": "<base64url 32>",
                    "state": { "status": "due", "countdownTarget": 1795000600, "isOverdue": false,
                               "confirmed": false, "pendingConfirm": false, "timeFormatRaw": "AUTO" },
                    "statement": { "instanceId": "...", "tokenTag": "<hex 32>", "laTokenTag": "<hex 32>", "iat": 1794000000 },
                    "signature": "<base64url 64>" } },
    { "ref": "upd-cm_med_1-2026-11-21-1", "token": "<hex>", "env": "production", "class": "liveactivity",
      "ttlSeconds": 3600,
      "activity": { "event": "update", "token": "<hex update token>", "bindingKey": "<base64url 32>",
                    "state": { "status": "overdue", "countdownTarget": 1795000600, "isOverdue": true,
                               "confirmed": false, "pendingConfirm": false, "timeFormatRaw": "AUTO" },
                    "statement": { "instanceId": "...", "tokenTag": "<hex 32>", "laTokenTag": "<hex 32>", "iat": 1794999000 },
                    "signature": "<base64url 64>" } }
  ]
}
```

Request-level checks, after request signing:

| Check | Result |
|---|---|
| malformed body, unknown field anywhere, trailing data, empty `items` | `422 invalid_item` |
| more than 50 items | `413 too_many_items` |
| an operator pause for all classes covers the instance's tier | `503 maintenance` with `retryAfter` |
| the relay stopped sending (provider token rejected) or the circuit breaker is open | `503 relay_misconfigured` |
| Apple refused provider token updates in the last 20 minutes | `503 apns_unavailable` with `retryAfter` |

Otherwise the answer is `200` with one result per item, in item order:

```json
{ "results": [ { "ref": "01JTESTVECT000000000000001", "status": 200, "result": "accepted" } ], "notice": null, "relayTime": 1795000000 }
```

`notice` is the current operator notice or `null` (see "Status"); `relayTime` is the relay clock.

### Item validation

Each item is checked on its own; a bad item does not affect the others.

| Field | Rule |
|---|---|
| `ref` | `^[A-Za-z0-9._:-]{1,40}$`, unique within the batch; a repeated `ref` in the same batch is `422 invalid_item` |
| `token` | APNs device token, hex, 64 to 200 characters; must be bound to the requesting instance |
| `env` | `production` or `sandbox`; must equal the binding's environment |
| `class` | `alert`, `silent` or `liveactivity` |
| `ttlSeconds` | integer above 0; values above the class maximum (alert 21600, silent 3600, liveactivity 14400) are clamped |
| `envelope` | alert and silent: required, base64url of exactly 1075 bytes with a valid outer frame for the class (`spec/envelope.md`, "What the relay checks"); liveactivity: must be absent |
| `collapse` | alert: required, `^[A-Za-z0-9_-]{22}$`; silent: optional, same format; liveactivity: must be absent |
| `activity` | liveactivity: required; alert and silent: must be absent |
| `activity.event` | `start`, `update` or `end`; `end` when absent; any other value is refused |
| `activity.state` | `start` and `update`: required, the content state (below); `end`: must be absent (the end carries a fixed state) |
| `activity.token` | hex, 64 to 200 characters: for `start` the push-to-start token of the app, for `update` and `end` the update token of the activity |
| `activity.bindingKey` | the binding key of the device, base64url |
| `activity.statement.tokenTag` | tag of the item's `token` |
| `activity.statement.laTokenTag` | tag of `activity.token` |
| `activity.statement.instanceId` | a UUIDv4 |
| `activity.signature` | `start`: `hl-la-start-v1` signature; `update` and `end`: `hl-activity-v1` signature; checked against the binding (see "Limits and checks per item") |

A failure of any rule is `422 invalid_item`; a token that is not bound to the instance is `404
binding_unknown`.

#### Live Activity content state

The content state is the only Live Activity content the relay forwards. It is a closed template: exactly
these six keys, all required, with fixed types, closed enumerations and a bounded time, and no free text, in
particular no medication name.

| Key | Type and range |
|---|---|
| `status` | one of `pending`, `due`, `overdue`, `snoozed`, `taken`, `skipped` |
| `countdownTarget` | integer, unix seconds: `0` (no countdown) or from 86400 s (one day) before to 172800 s (two days) after the relay clock, bounds included |
| `isOverdue` | boolean |
| `confirmed` | boolean |
| `pendingConfirm` | boolean |
| `timeFormatRaw` | one of `AUTO`, `H12`, `H24` |

A key outside the template, a key that differs only in case, a repeated key or a value of the wrong type
makes the whole request invalid (`422 invalid_item` for the request, strict decoding). A missing or `null`
key, a value outside its enumeration and a `countdownTarget` outside its bounds refuse the item with `422
invalid_item` (step 5 below).

#### Statements per event

| `event` | `activity.token` | Statement | `iat` window |
|---|---|---|---|
| `start` | push-to-start token | `hl-la-start-v1` over the push-to-start token | at most 300 s ahead, at most 2592000 s (30 days) old |
| `update` | update token of the activity | `hl-activity-v1` over the update token | at most 300 s ahead, at most 43200 s (12 h) old |
| `end` | update token of the activity | `hl-activity-v1` over the update token | at most 300 s ahead, at most 43200 s (12 h) old |

An `hl-activity-v1` statement never starts an activity, and an `hl-la-start-v1` statement never updates or
ends one. The app signs the start statement again whenever its push-to-start token changes and at least
every 30 days; it signs the activity statement when the activity starts.

The collapse id is meant to differ per device: a HealthLog server derives it as the first 22 characters of
`base64url(HMAC-SHA256(collapse secret of the instance, token || key))`, so that the relay and Apple cannot
link the devices of one person through equal collapse ids.

### Limits and checks per item

After validation, idempotency and the binding lookup, each item passes these checks in order. A push is
counted against any limit only when every check passed.

| # | Check | Result |
|---|---|---|
| 1 | an operator pause covers the class and the instance's tier | `503 maintenance` with `retryAfter` |
| 2 | silent only: silent pushes are switched off relay-wide (Apple throttling, see "Failure handling") | `429 global`, scope `global` |
| 3 | Apple throttled this device for this class within the last hour | `429 device_quota`, scope `device` |
| 4 | liveactivity only: the binding is not provisional, `activity.bindingKey` is the binding's key, the statement of the event (see "Statements per event") verifies for the requesting instance and its `iat` is inside the window of the event | otherwise `403 activity_refused` |
| 4a | liveactivity `start` and `update` only: the binding holds the device's Live Activity consent | otherwise `403 liveactivity_consent_required` |
| 4b | liveactivity `start` and `update` only: the content state is inside the template at the relay clock | otherwise `422 invalid_item` |
| 5 | soft-invalid binding: it did not fail today (one probe push per day) | `429 binding_quota`, scope `device`, retry until the next UTC midnight |
| 6 | binding not `active` (provisional or soft-invalid): the instance is not blocked by its invalid-token budget | `429 binding_quota`, scope `instance`, retry until the block ends |
| 7 | provisional binding: active bindings below `devices` | `429 binding_quota`, scope `instance`, retry 1 h |
| 8 | instance pushes today below `pushesPerDay` | `429 instance_quota`, scope `instance` |
| 9 | instance pushes this minute below `pushesPerMinute` | `429 instance_rate`, scope `instance` |
| 10 | device pushes today below 300 (all classes) | `429 device_quota`, scope `device` |
| 11 | alert: device alerts today below 100; then a token in the device's alert bucket | `429 device_quota`, scope `device` |
| | silent: device silent pushes in the current UTC clock hour below 6 (only the instance's silent pushes count, not the relay's challenge push, and an item Apple did not take for a reason of its own or of the relay's is taken off again) | `429 device_quota`, scope `device` |
| | liveactivity `start`: device starts today below 12 | `429 device_quota`, scope `device` |
| | liveactivity `update`: updates of this activity (keyed by its update token) this hour below 12 and today below 48 | `429 device_quota`, scope `activity` |
| | liveactivity `end`: device `end` events today below 12 | `429 device_quota`, scope `device` |
| 12 | probation instance: the probation pool has room this minute | `429 global`, scope `tier` |
| | standard instance: the standard pool has room this minute for the class share | `429 global`, scope `global` |
| 13 | the send queue admits the item | `503 queue_full`, retry about 2 s; scope `instance` when the instance's own queue share is full |

An item that never reached the device for a reason of Apple's service or of the relay is taken off every
limit of this table it was counted against, so the instance's retry is counted afresh: an answer
`503 apns_unavailable`, a `503 relay_misconfigured` because Apple refused the relay's provider token, and a
drop after waiting too long in the queue. A limit whose window (minute, hour, day) has rolled over since the
item was counted is left alone. Apple throttling the device and Apple's answers about the token are not
refunded.

The item then waits for Apple. A batch waits at most 8 s in total. After that deadline, a result that is
already there is reported as it is; an item still without an answer is reported as `503 apns_unavailable`
with `retryAfter` about 30 s. Its send may still complete, and that result is then kept for replay.

## What the relay sends to Apple

Every push is one HTTP/2 `POST` to `https://api.push.apple.com/3/device/<hex token>` (sandbox:
`https://api.sandbox.push.apple.com`), using one shared client with at most four connections, a ping after
an hour without traffic, and one request in flight at a time until the first attempt ends, whatever its
outcome (a warm-up, so that the first connection is set up once). Each request to Apple
times out after 3 s and is never retried by the relay; the instance owns retries and deadlines.

Headers on every request:

| Header | Value |
|---|---|
| `authorization` | `bearer <provider token>` |
| `content-type` | `application/json` |
| `apns-expiration` | relay clock plus `ttlSeconds` after clamping, unix seconds |
| `apns-collapse-id` | the item's `collapse`, only when present |

No `apns-id` is sent. Per class:

| Class | `apns-push-type` | `apns-priority` | `apns-topic` | Device path token |
|---|---|---|---|---|
| `alert` | `alert` | `10` | `<topic>` | the item's `token` |
| `silent` | `background` | `5` | `<topic>` | the item's `token` |
| `liveactivity` | `liveactivity` | `10` for `end` and for a `start` or `update` whose `status` is `due` or `overdue`, otherwise `5` | `<topic>.push-type.liveactivity` | the item's `activity.token` |
| conflict challenge | `background` | `5` | `<topic>` | the token of the bind request |

`<topic>` is the app's bundle id, `dev.healthlog.app` for the HealthLog app.

iOS grants each device an hourly budget of priority 10 Live Activity pushes and may throttle beyond it;
priority 5 does not count against it (Apple, "Starting and updating Live Activities with ActivityKit push
notifications", "Determine the update frequency"). The relay therefore uses 10 only for what needs the
person's attention at once, decided from the template-checked state, never by the instance.

The payloads are templates in `internal/apns/apns.go` (alert, silent, challenge) and
`internal/apns/liveactivity.go` (Live Activity). An instance chooses the class, the envelope, the lifetime
and the collapse id, and for a Live Activity start or update a content state inside the closed template;
never any visible text, category, sound or other key.

Alert (`<envelope>` is the item's envelope, unpadded base64url):

```
{"aps":{"alert":{"loc-key":"HL_RELAY_ALERT"},"mutable-content":1,"sound":"default"},"e":"<envelope>"}
```

Silent:

```
{"aps":{"content-available":1},"e":"<envelope>"}
```

Conflict challenge (`<challenge>` generated by the relay, not content):

```
{"aps":{"content-available":1},"c":"<challenge>"}
```

Live Activity payloads, with `<now>` the relay clock in unix seconds. In `start` and `update`, the values
of `content-state` are those of the item's `activity.state` after the template check, written in this key
order; nothing else of the item reaches the payload.

`start` (to the push-to-start token; the attributes type and the attributes are fixed, so nothing about the
dose travels in them, and the alert is a fixed pair of localization keys):

```
{"aps":{"timestamp":<now>,"event":"start","content-state":{"status":"<status>","countdownTarget":<countdownTarget>,"confirmed":<confirmed>,"pendingConfirm":<pendingConfirm>,"isOverdue":<isOverdue>,"timeFormatRaw":"<timeFormatRaw>"},"attributes-type":"HealthLogDoseAttributes","attributes":{"v":1},"alert":{"title":{"loc-key":"HL_LA_START_TITLE"},"body":{"loc-key":"HL_LA_START_BODY"}}}}
```

`update` (to the activity's update token):

```
{"aps":{"timestamp":<now>,"event":"update","content-state":{"status":"<status>","countdownTarget":<countdownTarget>,"confirmed":<confirmed>,"pendingConfirm":<pendingConfirm>,"isOverdue":<isOverdue>,"timeFormatRaw":"<timeFormatRaw>"}}}
```

`end`, with `<now>` for both `timestamp` and `dismissal-date` and a constant content state:

```
{"aps":{"timestamp":<now>,"event":"end","content-state":{"status":"taken","countdownTarget":0,"confirmed":false,"pendingConfirm":false,"isOverdue":false,"timeFormatRaw":"AUTO"},"dismissal-date":<now>}}
```

The alert carries no `category`, `thread-id` or `interruption-level`. What the notification can do is set by
the notification service extension after it opened the envelope.

Without the Live Activity consent, a Live Activity token reaches the relay only together with the `end`
event, and the relay never learns when an activity starts. With it, the push-to-start token reaches the
relay with every start and the update token with every update, together with the content state in the
clear; Apple receives that state as well. The relay stores neither token nor any state: it keeps, in memory
only, the start count of the device and the update counts of each activity, keyed by an HMAC of its update
token, until the end of the UTC day.

## Results

### Per item

| `status` | `result` or `error` | Other fields | Meaning |
|---|---|---|---|
| 200 | `result: accepted` | | Apple accepted the push |
| 200 | `result: soft_invalid` | `reason` (`BadDeviceToken`, `DeviceTokenNotForTopic`, or `Unregistered` for a stale `410`) | Apple refused the token softly, or reported it gone before the binding was last made; the binding is marked, not deleted |
| 200 | `result: activity_gone` | | liveactivity: Apple reported the activity token as gone or invalid; nothing changes |
| 403 | `activity_refused` | | the activity statement or the binding does not allow the event: a provisional binding, another binding key, a statement that does not verify for the event, or an `iat` outside its window |
| 403 | `liveactivity_consent_required` | | a `start` or `update` for a binding without the device's Live Activity consent |
| 404 | `binding_unknown` | | the token is not bound to this instance |
| 410 | `unregistered` | | Apple reported the device token as unregistered; the binding is deleted |
| 422 | `invalid_item` | | the item failed validation, names another environment than its binding, or carries a content state outside the template |
| 429 | `device_quota` | `scope: device` or `activity`, `retryAfter` | `device`: a per-device limit or Apple's per-device throttling; `activity`: the update limit of one Live Activity |
| 429 | `binding_quota` | `scope: device` or `instance`, `retryAfter` | `device`: a soft-invalid binding on the day it failed; `instance`: a provisional binding that does not fit, or a non-active binding while the instance is over its invalid-token budget |
| 429 | `instance_quota` | `scope: instance`, `retryAfter` | the instance's daily push limit |
| 429 | `instance_rate` | `scope: instance`, `retryAfter` | the instance's per-minute push limit |
| 429 | `global` | `scope: global` or `tier`, `retryAfter` | a relay-wide pool, or silent pushes switched off |
| 502 | `apns_rejected` | `reason` | Apple refused the request for a reason that is a defect of the request or the relay; nothing is deleted |
| 503 | `apns_unavailable` | `retryAfter` | Apple did not answer, answered 5xx, or the provider token is unavailable or being refreshed |
| 503 | `relay_misconfigured` | | the breaker is not closed and a token failure was not applied, or the provider token was rejected |
| 503 | `maintenance` | `retryAfter` | an operator pause for this class |
| 503 | `queue_full` | `retryAfter`, `scope: instance` when the instance's share is full | the send queue refused or dropped the item |

Every result also carries the item's `ref` and `status`. A result replayed from the idempotency store
carries `duplicate: true`. `reason` values come from a closed set of Apple reasons; anything else is
reported as `other`.

### Per request

| Status | `error` | Endpoints | Other fields |
|---|---|---|---|
| 400 | `nonce_required` | every `/v1` endpoint | signed with nonce `-` |
| 401 | `unknown_instance` | instance endpoints | |
| 401 | `stale_timestamp` | instance endpoints, registration, `POST /v1/bindings`, `POST /v1/bindings/liveactivity`, `DELETE /v1/bindings/self`, `DELETE /v1/bindings/self/liveactivity`, `GET /v1/bindings/self` | `relayTime` |
| 401 | `bad_signature` | instance endpoints, registration | |
| 401 | `replayed` | instance endpoints | |
| 403 | `instance_revoked` | instance endpoints, registration | |
| 403 | `instance_suspended` | instance endpoints, registration | `reason` |
| 403 | `invite_required` | registration | |
| 403 | `binding_refused` | `POST /v1/bindings`, `POST /v1/bindings/liveactivity` | |
| 403 | `challenge_refused` | `POST /v1/bindings/challenge` | |
| 404 | `binding_unknown` | `POST /v1/bindings/liveactivity`, `DELETE /v1/bindings/self`, `DELETE /v1/bindings/self/liveactivity`, `GET /v1/bindings/self` | |
| 404 | `not_found` | any unknown route, a known path with another method, any non-canonical path | |
| 409 | `key_in_use` | rotation | |
| 409 | `binding_conflict` | `POST /v1/bindings` | `reason`: `challenge_sent`, `challenge_quota`, or `challenge_unsent` with `retryAfter` |
| 411 | `length_required` | every `POST` and `DELETE` | |
| 413 | `too_large` | every endpoint with a body | |
| 413 | `too_many_items` | `POST /v1/push` | |
| 422 | `invalid_item` | every endpoint with a body or inputs; `DELETE /v1/instances/self` with a non-empty body | |
| 422 | `env_unsupported` | `POST /v1/bindings` | |
| 426 | `min_server_version` | instance endpoints | |
| 429 | `instance_rate` | instance endpoints (request rate), rotation (once a day), receipts (once per 45 minutes) | `scope: instance`, `retryAfter`, `limits` on the request-rate refusal |
| 429 | `binding_quota` | `POST /v1/bindings`, `POST /v1/bindings/challenge` | `scope: instance`, `retryAfter`, `limits` |
| 429 | `device_quota` | app endpoints (verified calls per device token) | `scope: device`, `retryAfter` |
| 429 | `global` | app endpoints (failed attempts) | `scope: global`, `retryAfter` |
| 503 | `overloaded` | every `POST` and `DELETE` (body budget), instance endpoints (nonce store) | `retryAfter` |
| 503 | `storage_unavailable` | registration, rotation, deletion, binding endpoints | `retryAfter` on registration and `POST /v1/bindings` |
| 503 | `registration_paused` | registration | `retryAfter` |
| 503 | `maintenance` | `POST /v1/push` | `retryAfter` |
| 503 | `relay_misconfigured` | `POST /v1/push` | |
| 503 | `apns_unavailable` | `POST /v1/push` | `retryAfter` |
| 500 | `internal` | any (an encoding failure, or a body that would exceed 65 536 bytes) | |

Refusals without `retryAfter` (`relay_misconfigured`, `apns_rejected`, `storage_unavailable` on some
endpoints) carry no timing promise; a client applies its own backoff.

## Failure handling

How Apple's answer maps to the item result and what it changes. Only a definite `410 Unregistered` ever
deletes a binding outright.

Apple's `410` carries `timestamp`, the time in milliseconds at which APNs confirmed that the token was no
longer valid for the topic; a provider should stop sending to the token unless it was registered again after
that time. The relay keeps only the UTC day of a binding (made or renewed with a new `seq`), so it compares
loosely: the `410` is stale when the binding day begins more than 10 minutes after the timestamp. A binding
renewed on the same day as the invalidation cannot be told apart and is deleted; the device binds again
through its server. A missing timestamp, or one before 2015, counts as not stale.

| Apple answer | Item result | Effect at the relay | Kept for replay |
|---|---|---|---|
| `200` | `200 accepted` | binding becomes `active`, last success day and last-used week updated, the instance's first and last delivery day updated | yes |
| `410` | `410 unregistered` (liveactivity: `200 activity_gone`) | binding deleted; counts against the instance's invalid-token budget | yes |
| `410` with a `timestamp` before the binding day | `200 soft_invalid` with `reason` `Unregistered` | handled as a soft failure: the binding is marked, and a second such answer on a later day deletes it; counts against the invalid-token budget | yes |
| `400 BadDeviceToken`, `400 DeviceTokenNotForTopic` | `200 soft_invalid` with `reason` (liveactivity: `200 activity_gone`) | binding set to `soft_invalid`; a second such answer on a later day deletes it; counts against the invalid-token budget | yes |
| any of the three above while the breaker is open or half-open | `503 relay_misconfigured` | nothing is deleted or marked; the invalid-token budget is still charged unless the binding is established (has had an accepted push) | no |
| `429 TooManyRequests` | `429 device_quota`, scope `device`, retry about 1 h | this class is suspended for this device for 1 h | no |
| `403 ExpiredProviderToken` | `503 apns_unavailable`, retry about 30 s | a provider token refresh is requested | no |
| `403 InvalidProviderToken` | `503 relay_misconfigured` | the first rejection is recorded; it is forgotten once Apple accepts a push with a newer token. When the next renewed token is rejected as well, the relay stops sending to Apple until the operator resets it | no |
| `429 TooManyProviderTokenUpdates` | `503 apns_unavailable`, retry about 20 min | every push request is refused with `503 apns_unavailable` for 20 minutes | no |
| other `4xx` | `502 apns_rejected` with `reason` | nothing | yes |
| `5xx`, timeout, connection error | `503 apns_unavailable`, retry about 30 s | nothing | no |
| no provider token available | `503 apns_unavailable`, retry about 30 s | `/healthz` reports `down` | no |

**Invalid-token budget.** Each `Unregistered` or soft invalid answer for a device push counts against the
instance's `invalidTokensPerDay`. Over the budget, for 24 hours the instance gets no new bindings (also not
through a challenge answer) and every binding that is not `active` (provisional and soft-invalid) receives no
pushes (`429 binding_quota`, scope `instance`); it is also flagged (`flaggedDay`: not promoted that day or
the next).

**Soft-invalid bindings.** A binding marked `soft_invalid` receives no push on the UTC day it failed (`429
binding_quota`, scope `device`, retry until midnight UTC), so it gets at most one probe push per day. An
accepted probe makes it `active` again; a second soft failure on a later day deletes it.

**Apple throttling across the relay.** When more than 2 % of all sends in the last five minutes (at least 50
sends) end with `429 TooManyRequests`, silent pushes are switched off for every instance for 15 minutes
(`429 global`, scope `global`).

A relay or Apple outage never counts against a device: none of `apns_unavailable`, `relay_misconfigured`,
`maintenance`, `queue_full` or a quota refusal is a reason for an instance to drop a device.

## Circuit breaker

The breaker protects every binding from a relay-side misconfiguration (wrong key, wrong topic, bad deploy).
It counts only device sends (alert and silent; not Live Activity and not challenges) to **established**
bindings: bindings of the sending instance that have had at least one push accepted by Apple. A
misconfiguration hits exactly those; tokens an instance invented never reach that state and cannot move the
breaker.

| Parameter | Value |
|---|---|
| window | 5 minutes, in 10 slots of 30 s |
| opens when | at least 20 sends to established bindings in the window, more than 30 % of them end with `Unregistered`, `BadDeviceToken` or `DeviceTokenNotForTopic`, and those failures come from at least 3 different instances |
| cool-down | 10 minutes open, then half-open |
| half-open closes when | at least 20 sends to established bindings, at most 10 % token failures, at least one accepted push |
| half-open reopens when | at least 20 such sends, more than 30 % token failures, from at least 3 instances |

While **open**, every `POST /v1/push` is refused with `503 relay_misconfigured`. While **half-open**, traffic
flows, but a token failure changes no binding and is reported as `503 relay_misconfigured` for that item.
While the breaker is not closed, token failures of established bindings are not charged to the
invalid-token budget; failures of any other binding still are. The operator can open or close the breaker by
hand. `/healthz` shows the state for display; it does not change the health status.

## Provider token

The relay never holds the APNs signing key. A separate signer process, without network access, writes a
fresh provider token (ES256 JWT) to a file the relay reads. The relay:

- re-reads the file at most every 10 s,
- uses a token only while its `iat` is at most 55 minutes old,
- on `ExpiredProviderToken` asks for a refresh by touching a marker file; the signer honours that at most
  every 20 minutes (Apple's limit on token updates),
- never signs a provider token itself.

With no usable token every send ends in `apns_unavailable` and `/healthz` reports `down`.

## Idempotency

The idempotency key is `(instance id, ref)`. It does not include the token, the class or the envelope: a
retry must send the same item with the same `ref`.

- An item is registered under its key when it enters the send queue. Items refused before that (validation,
  binding, limits, queue) are not registered; a retry is evaluated afresh.
- A retry while the first send is still in flight waits for that send and returns its result.
- A retry after the first send finished returns the stored result with `duplicate: true` and sends nothing.
- Only definite answers are stored: `accepted`, `soft_invalid`, `activity_gone`, `unregistered` and
  `apns_rejected`. Transient results (`apns_unavailable`, `relay_misconfigured`, `device_quota` from Apple's
  throttling, `queue_full`) are forgotten, so a retry really retries.
- Entries live as long as the item's lifetime after clamping (`ttlSeconds`), at least 10 minutes: a retry
  after a lost response, late in the instance's backoff, gets the stored answer instead of a second copy at
  Apple. At most 200000 finished entries are kept; beyond that the oldest finished entries are dropped
  first.

## Queue

Sends go through an in-memory queue, never through disk.

| Parameter | Value |
|---|---|
| capacity | 4096 items |
| per instance | 256 items |
| workers | 256 |
| priority | alert and Live Activity before silent |
| fairness | round robin across instances within each priority |
| admission | an empty queue always admits; otherwise an item whose estimated wait exceeds 2 s is refused at once (`503 queue_full`) |
| drop | an item that waited longer than 2 s anyway is dropped at dequeue (`503 queue_full`) |

A panic in a send worker is not recovered: it ends the process, and the container is restarted (known
limitation; the restart rules under "After a restart" apply).

## Limits

All numbers are the defaults in `internal/relay/config.go` (`DefaultLimits`) and `internal/limits/limits.go`
(`DefaultRegistrationLimits`), which are the values of the hosted relay. Day windows are UTC days, hour and
minute windows are aligned to the clock; they are fixed windows, not sliding ones. Limits apply per instance
and per device, never per address, except for registration and connections.

### Per instance

The JSON names are those of the `limits` object in responses.

| Limit | JSON | `probation` | `standard` | Refusal |
|---|---|---|---|---|
| active bindings | `devices` | 20 | 50 (80 after 30 quiet days above 80 % use; up to 150 by the operator) | `429 binding_quota` |
| concurrent provisional bindings | `provisional` | 10 | 20 | `429 binding_quota` |
| new bindings per day | `newBindingsPerDay` | 20 | 100 | `429 binding_quota` |
| authenticated requests per minute | `requestsPerMinute` | 20 | 60 | `429 instance_rate` |
| pushes per day | `pushesPerDay` | 500 | 10000 | `429 instance_quota` |
| pushes per minute | `pushesPerMinute` | 30 | 120 | `429 instance_rate` |
| invalid tokens per day | `invalidTokensPerDay` | 20 | 100 | no new bindings for 24 h |
| conflict challenges per day | `challengesPerDay` | 20 | 20 | `409 binding_conflict`, `reason: challenge_quota` |
| failed signatures counted in metrics | `badSignatureBurst` | 30, refilled within one minute | 60, refilled within one minute | none; limits only how often a failure is counted, never refuses |

Also per instance: one key rotation per UTC day, one receipts report per 45 minutes.

### Per device

The same for every tier.

| Limit | Value | Refusal |
|---|---|---|
| pushes per day, all classes | 300 | `429 device_quota` |
| alerts | token bucket of 20, refilled at 6 per hour; at most 100 per day | `429 device_quota` |
| silent pushes per hour | 6 | `429 device_quota` |
| Live Activity `start` per day (only with the Live Activity consent) | 12 | `429 device_quota` |
| Live Activity `update` per activity (only with the Live Activity consent) | 12 per hour, 48 per day | `429 device_quota`, scope `activity` |
| Live Activity `end` per day | 12 | `429 device_quota` |
| soft-invalid binding | no push on the day it failed (one probe per day) | `429 binding_quota`, scope `device` |
| Apple `429 TooManyRequests` | the class is suspended for 1 h | `429 device_quota` |
| conflict challenges | 1 per token, instance and day | `409 binding_conflict`, `reason: challenge_quota` |
| verified app calls (opt-out, self-read, Live Activity withdrawal, challenge answer) | token bucket of 10, refilled at 10 per hour | `429 device_quota`, scope `device` |

### Global pools

| Pool | Size per minute | Refusal |
|---|---|---|
| global limit `G` | five times the highest minute of the last 7 days, at least 600, at most 6000 | |
| standard pool | `G` for alerts, 85 % of `G` for Live Activity, 70 % of `G` for silent, counted over all standard instances | `429 global`, scope `global` |
| probation pool | `G / 10`, at least 60, at most 600, counted over all probation instances | `429 global`, scope `tier` |

Under pressure silent pushes are shed first, then Live Activity, alerts last. Probation instances cannot
exhaust the standard pool, and reaching `standard` requires a push accepted by Apple.

### Registration

Counted in memory per source prefix (hashed with a salt that changes daily) and globally.

| Limit | Value |
|---|---|
| per IPv4 address or IPv6 /64 | 3 per day |
| per IPv6 /48 | 10 per day |
| global | 30 per hour, 200 per day |

Over a limit: `503 registration_paused`, existing instances notice nothing. During a recovery window the
global caps are ten times higher (300 per hour, 2000 per day) and not halved after a restart; the
per-address caps still apply.

### After a restart

Counts kept only in memory are lost on a restart. So that a restart does not hand out fresh quotas:

- until the next UTC midnight after the start, the global registration caps are halved (15 per hour, 100
  per day), and the per-device limits for Live Activity `start` events (6 per day) and Live Activity `end`
  events (6 per day) are halved;
- until the end of the UTC clock hour in which the relay started, the per-device limit for silent pushes is
  halved (3 per hour). Only that hour's count was lost; from the next hour on the count is complete and the
  limit is 6 again;
- the per-device alert count of the day is stored with the binding (flushed every minute) and survives;
- the per-instance daily push count is restored from the stored day counters;
- an instance flag is stored as a day and survives;
- timestamps from before the start are refused, which covers the emptied nonce store and the opt-out times
  that were kept in memory.

Known limitation: the other in-memory counters start from zero after a restart. These are, per instance, the
new bindings of the day (`newBindingsPerDay`), the challenges of the day (`challengesPerDay`) and the
24-hour block after an exceeded invalid-token budget, the per token, instance and day challenge record, and
the per-activity update counts of Live Activities, which are not halved.
The per-instance invalid-token count of the day is restored from the stored day counters, but a block that
was already running ends with the restart. Each restart therefore gives every instance these allowances
afresh for the rest of the day.

### Other bounds

| Bound | Value |
|---|---|
| `/v1/push` body | 128 KiB, declared in `Content-Length` |
| other bodies | 4 KiB |
| request bodies in flight, all connections | 32 MiB |
| HTTP/2 streams per connection | 16 |
| response body | at most 65 536 bytes; clients refuse more than 262 144 |
| items per push request | 50 |
| nonces | 2000 per instance, 200000 in total, each kept 600 s |
| idempotency entries | 200000, each kept for its item's lifetime, at least 10 minutes |
| batch wait for Apple | 8 s |
| request to Apple | 3 s |
| failed app endpoint attempts | token bucket of 100, refilled at 20 per second, shared by all callers |
| verified app endpoint calls | token bucket of 10 per device token, refilled at 10 per hour |

## Receipts

### POST /v1/receipts

Instance-authenticated. The instance reports how many of the pushes the relay accepted more than six hours
ago were confirmed by the device (the app acknowledges an opened envelope to its own server). Counts only,
no ids.

```json
{ "accepted": 120, "confirmed": 117 }
```

- `accepted` and `confirmed` are integers, `0 <= confirmed <= accepted <= 100000`; otherwise `422
  invalid_item`.
- At most one report per instance per 45 minutes; an earlier report is refused with `429 instance_rate`,
  scope `instance`, with `retryAfter` until the 45 minutes are over. Servers report every 55 minutes.
- `204` on success.
- Only reports of `standard` instances count; a report of any other tier is answered `204` and ignored.
- The reported `accepted` is capped at the number of pushes the relay itself accepted for that instance in
  the last three days (today and the two days before), and `confirmed` at the capped `accepted`.

The relay adds the counts into 24 hourly slots in memory, summed across all instances, and keeps nothing per
instance. From the last 24 hours it derives the delivery signal:

| `delivery` | Condition |
|---|---|
| `unknown` | fewer than 20 accepted pushes reported, or fewer than three reports |
| `degraded` | fewer than 80 % of them confirmed |
| `ok` | otherwise |

`delivery` is for display only. It never changes the `/healthz` status or its HTTP code.

## Status

### GET /v1/status

Instance-authenticated, empty body. `200`:

```json
{
  "state": "ok",
  "tier": "standard",
  "limits": { "devices": 50, "provisional": 20, "newBindingsPerDay": 100, "requestsPerMinute": 60,
              "pushesPerDay": 10000, "pushesPerMinute": 120, "invalidTokensPerDay": 100,
              "challengesPerDay": 20, "badSignatureBurst": 60 },
  "devices": { "active": 3, "provisional": 0, "limit": 50 },
  "notice": { "id": "planned_maintenance", "level": "planned", "until": 1795600000 },
  "keyRotatedDay": "2026-11-21",
  "relayTime": 1795000000,
  "registration": "open"
}
```

| Field | Meaning |
|---|---|
| `state` | `misconfigured` (provider token rejected), `maintenance` (a pause of all classes for all tiers), `degraded` (breaker open or half-open, or store not writable), `ok` |
| `tier` | the instance's tier |
| `limits` | the instance's tier limits, with its own device limit |
| `devices` | the instance's active and provisional bindings and its device limit; `active` includes `soft_invalid` bindings |
| `notice` | the current operator notice or `null` |
| `keyRotatedDay` | the day of the last key rotation, present for 7 days after it |
| `relayTime` | the relay clock, unix seconds |
| `registration` | registration mode: `open`, `invite` or `closed` |

### Notice

A notice is a fixed identifier with a level, never free text. The text for each identifier ships with the
HealthLog server, so the relay cannot put arbitrary words in front of an operator.

```json
{ "id": "relay_shutdown", "level": "action_required", "until": 1795600000 }
```

- `id`: `[a-z0-9_]{1,40}`.
- `level`: `info`, `planned` or `action_required`.
- `until` (optional): unix seconds after which the notice no longer appears.

The notice appears in every `POST /v1/push` response, in `GET /v1/status` and in the status file.

## Status file

The status file lets an instance learn the relay's state from somewhere other than the relay, for example
while the relay is unreachable or its breaker stays open. The operator produces it on the relay host and
publishes it at a location on another origin; the relay does not serve it.

```json
{
  "body": { "host": "push.example.org", "issued": 1795000000, "notice": null, "state": "ok" },
  "signature": "<base64url 64>"
}
```

- `body` members: `host` (the relay host), `issued` (unix seconds when the file was made), `notice` (as
  above, or `null`), `state` (as in `GET /v1/status`).
- `signature`: the relay identity key's signature over `hl-relay-status-v1`, the host and the SHA-256 of the
  exact bytes of `body` as they appear in the file.
- A reader verifies against the pinned relay identity keys, checks that `body.host` is the relay it uses,
  and ignores a file whose `issued` is older than it is willing to trust.

## Health

### GET /healthz

Public, unauthenticated, signed like every JSON response; `HL-Nonce` is optional (without it the signature
is bound to `-`). `200` when `status` is `ok`, `503` otherwise.

```json
{ "status": "ok", "db_writable": true, "apns_recent": true, "breaker": "closed", "delivery": "ok" }
```

| Field | Values |
|---|---|
| `status` | `down` (no usable provider token, or sending stopped after Apple rejected a renewed one), `degraded` (store not writable), `ok`. It depends only on these facts of the relay itself; the HTTP code, the container health check and the deploy gate follow it |
| `db_writable` | whether the store accepts writes |
| `apns_recent` | whether Apple accepted a push within the last 15 minutes |
| `breaker` | `closed`, `open` or `half_open`; display only |
| `delivery` | `ok`, `degraded` or `unknown` (see "Receipts"); display only |

Third parties can influence `breaker` and `delivery` (instances send the traffic and report the receipts),
so neither may turn the status.

The body carries no time stamp.

### GET /version

`200 { "version": "...", "commit": "...", "imageDigest": "..." }`: the build version, the source commit and
the container image digest the operator configured. Signed; `HL-Nonce` is optional.

### Human pages

`GET /` (index), `GET /privacy` (privacy notice) and `GET /terms` (terms of use) return
`text/plain; charset=utf-8`, unsigned: the text compiled into the binary, byte for byte. A client whose
`Accept` header names `text/html` or `application/xhtml+xml` with a quality above zero and above the
quality it gives `text/plain` gets an HTML page rendered from the same text instead
(`text/html; charset=utf-8`). A wildcard such as `*/*`, no `Accept` header, or equal preference keeps the
plain text. Both answers carry `Vary: Accept`. The HTML page loads nothing: its policy is
`default-src 'none'; style-src 'sha256-...'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
with the hash of its one inline style, and it carries `X-Frame-Options: DENY` and
`Referrer-Policy: no-referrer`. `GET /privacy.txt` and `GET /terms.txt` always return the plain text.
`GET /.well-known/security.txt` (RFC 9116: contact `relay@healthlog.dev` and the repository's GitHub
security advisories, with an `Expires` date) returns `text/plain; charset=utf-8`, unsigned.

## State

The relay keeps one database file. It stores only what this section lists. Times are stored as day numbers
(days since the Unix epoch, UTC) or week numbers (day number plus 3, divided by 7, so that a week runs Monday to Sunday), never as a time of day. There is
no field for a raw device token, an address, or a push class per instance.

| Record | Key | Fields |
|---|---|---|
| instance | instance id | Ed25519 public key, tier, reason of a suspension or revocation (closed set) and its day, creation day, last contact week, device limit, first delivery day, last rotation day, quiet-since day, last delivery day, flagged day |
| instance key index | hex public key | instance id |
| binding | HMAC-SHA256 of the raw token under the token MAC key | instance id, SHA-256 of the binding key, `seq`, environment, state (`provisional`, `active`, `soft_invalid`), binding day, last-used week, last success day, soft-invalid day, consent text version, consent day, alerts today and their day, Live Activity consent text version and day (empty without that consent) |
| blocked pair (`blocked_pairs`) | SHA-256("hl-blocked-pair\n" ‖ token MAC ‖ "\n" ‖ instance id) | JSON: day of the opt-out, SHA-256 of the binding key that opted out, the `seq` of the binding it left |
| blocked token (`blocked_tokens`) | SHA-256("hl-blocked-token\n" ‖ token MAC) | day of the block |
| opt-out pin (`optout_pins`) | SHA-256("hl-optout-pin\n" ‖ token MAC) | JSON: day of the opt-out, SHA-256 of the binding key that opted out (none after a restore) |
| instance day counters | day and instance id | pushes accepted, invalid tokens, rebinds; no class |
| global day counters | day, class or category, result | count, without any instance |
| operator control | fixed | pauses, registration mode, notice, recovery window, invite codes (as hashes) |

Only in memory: nonces, idempotency entries, per-device counters (except the alert count), pending
challenges, the per token, instance and day challenge record, the per-instance counts of new bindings and
challenges of the day and the 24-hour invalid-budget block, the per-activity Live Activity update counts
(keyed by an HMAC of the update token, cleared at the end of the UTC day), the `iat` of an opt-out (10 minutes),
registration counters (keyed by salted prefix hashes), receipts, Apple throttling counts, and the delivery
traces: Apple's `apns-unique-id` of a push, which Apple sends only in the development environment, with the
item result, keyed by instance id and `ref`, for 72 hours and at most 50,000 entries, so that the operator
can look up one lost push in Apple's delivery log. Traces are never stored, exported, logged or counted, and
go with the instance.

Suspension and revocation live in the instance record (tier, reason, reason day); there is no separate
list. A revocation writes the record and deletes the bindings in one transaction. A suspension of a revoked
instance is refused, so a revocation cannot be undone by suspending and unsuspending.

Reads of the pair blocks, the token blocks and the opt-out pins fail closed: a read error counts as blocked
or pinned.

**Token MAC keys.** The relay holds a current and optionally a previous MAC key. A binding found only under
the previous key is moved to the current key on first use, so a MAC key rotation needs no downtime. A
binding whose MAC matches no configured key can no longer be found and does not count against any limit.

**Store failures.** When a write fails the store is treated as read-only: the push path keeps working from
memory, new bindings and registrations are refused with `503 storage_unavailable`, and `/healthz` reports
`db_writable: false` and `status: degraded`. Changed bindings, changed instance records and the counters are
written once a minute in a single write transaction; the daily retention deletes stale bindings in one
transaction as well. A metrics scrape writes nothing: usage counts not yet flushed are added from memory. A consistency check runs at start and daily. Only
proven damage at start (a failed consistency check, a bbolt error for an invalid file, a version or checksum
mismatch, a mapping error, or a truncated file) moves the file aside, as
`relay.db.damaged-YYYYMMDDTHHMMSSZ` with a numeric suffix if that name exists, so no earlier copy is ever
overwritten. Any other error opening the store (a held lock, wrong permissions, a full disk) stops the relay
with an error and leaves the file in place. After moving a damaged file aside (or when it starts with an
empty data directory), the relay starts empty, imports the instances (suspended and revoked ones keep their
tier, reason and reason day) and all blocks and pins from its daily registry export and opens a recovery
window of 14 days.

### Registry export

The relay writes `registry.json` once a day (format `healthlog-push-registry-v2`):

| Field | Content |
|---|---|
| `format` | `healthlog-push-registry-v2` |
| `host` | the relay's public host name |
| `day` | `YYYY-MM-DD` of the export |
| `instances` | `{id, publicKey, tier, reason, createdDay, deviceLimit, firstDeliveryDay, reasonDay}` per instance; suspended and revoked ones only while their reason day is at most 365 days old |
| `blockedPairs` | `{pair, reason: "device_opt_out", expiresDay}` per device opt-out |
| `blockedTokens` | `{pair, reason: "operator_block", expiresDay}` per operator token block |
| `optOutPins` | `{pair, reason: "device_opt_out_pin", expiresDay}` per opt-out pin |
| `signature` | the relay identity key's Ed25519 signature over `hl-relay-export-v1` (`spec/statements.md`) |

`pair` is the hex keyed hash of the stored record above. Entries past their expiry are neither exported nor
imported. The binding key hash and `seq` of an opt-out and the key of a pin are not exported, so a restored
opt-out cannot be lifted by the device's return statement and a restored pin sends every new binding of the
token through the challenge. Bindings are not exported, and with them no Live Activity consent; devices bind again through the normal
binding path and give that consent again.

The signature covers the export marshaled as JSON without its `signature` field. An unsigned export is never
written. On import (at start with an empty data directory or after a damaged store was moved aside, and
through the operator's `recovery --from`) the relay checks the signature against its own identity key and
the `host` against its configured name, and every instance must be inside the closed sets the relay writes:
a lowercase UUIDv4 id, a 32-byte key, a tier of `probation`, `standard`, `suspended` or `revoked`, a reason
from the closed list (or none) and a device limit from 1 to 150. Every block and pin entry must carry a
32-byte hex hash, its own reason code and a valid expiry day; expired entries are dropped as on export. Any
failure makes the whole import fail; at start the relay then does not start. Instances whose id or key
already exists are skipped.

## Retention

| What | Removed after |
|---|---|
| binding without an accepted push | 13 weeks (about 90 days) after its last-used week |
| provisional binding | more than 2 days after its binding day without an accepted push |
| instance without authenticated contact | 13 weeks after its last contact week, with its bindings |
| instance that never had an accepted push | once it is more than 30 days old and its last contact week lies before the week of the day 30 days back, with its bindings; an instance that keeps checking in (status, registration, pushes) is kept |
| Live Activity consent | with its binding; earlier when the instance drops it, the device withdraws it, or the binding changes key or instance |
| blocked pairs, blocked tokens, opt-out pins | 365 days |
| suspended and revoked instance records | 365 days after the reason day, with their bindings |
| instance day counters | 7 days |
| global day counters | 400 days |
| pending challenges | 30 minutes |
| nonces | 600 s |
| idempotency entries | the item's lifetime after clamping, at least 10 minutes |

Suspended and revoked instances are not removed by the idle rules. Retention runs once a day.

## Usage aggregates

For the operator the relay computes usage from the global day counters and the in-memory state. It contains
counts only: no instance id and no value of a single instance.

| Field | Meaning |
|---|---|
| `granularity` | `day` |
| `activeInstances` | instances in `probation` or `standard` |
| `instancesPushedLast7Days`, `instancesPushedLast30Days` | instances with an accepted push in that window |
| `activeBindings` | bindings in `active` or `soft_invalid` |
| `registrationsPerWeek`, `optOutsPerWeek` | `{ "weekOf": "YYYY-MM-DD", "n": 0 }` per completed week |
| `pushesPerDay` | per completed day: `total`, `byClass`, `accepted`, `softFailed` (soft invalid and activity gone), `unregistered` |

Days are completed days only (yesterday back), so no partial day of a small population is ever shown. With
fewer than 20 active instances, the summary log line is written hourly instead of every minute, so the
traffic of a single instance cannot be read off the log. The metrics are counts without any instance or
device. Only HTTP responses by status class, requests to Apple without a split by kind, Apple's refusals by
reason, the delivery latency and the gauges of the relay's own health are current at every scrape. Every
other metric (every split by push class or kind, the key slot, the silent budget refusals, the instances per
tier, the bindings per state and the usage figures) is served from a copy taken every five minutes, with a
tier of fewer than three instances counted under `other`. Registrations, key rotations, instance
deletions and resolved conflict challenges have no log line of their own; they are counted in the `events`
map of the summary line. Metrics are served on the loopback interface only.

## Operator controls

The operator acts through a local interface on the relay host, never over the public HTTP port. What the
controls do is visible in the protocol:

| Control | Effect |
|---|---|
| suspend, unsuspend | tier `suspended` with a reason (`403 instance_suspended`), back to `probation`; a revoked instance cannot be suspended |
| revoke | tier `revoked`, bindings deleted in the same transaction (`403 instance_revoked`) |
| block token | the token can no longer be bound by any instance except its current holder (`403 binding_refused`) |
| device limit | an instance's active device limit, 1 to 150 |
| pause | a class (`all`, `alert`, `silent`, `liveactivity`) for a tier (`all`, `probation`) for up to 7 days (`503 maintenance`) |
| registration | mode `open`, `invite` (one-time codes valid for 7 days) or `closed` |
| notice | set or clear the notice |
| recovery | open a recovery window, optionally importing a registry export (verified as above) |
| breaker | open or close the breaker, or clear the stop after a rejected provider token |
| status file | produce a signed status file |
| delivery | show the delivery trace (`apns-unique-id` and result) of one instance id and `ref` from the last 72 hours |
| suspects | list instances with invalid tokens, rebinds or challenges in the last 7 days, worst first, with their counts; instance ids appear only here and in `instance`, on the operator interface |

Pauses and notices expire on their own when given a duration.
