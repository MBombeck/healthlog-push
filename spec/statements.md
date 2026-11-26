# Signed statements, version 1

Every signature in the relay protocol is an Ed25519 signature over a short text statement. This document
lists each statement exactly as `internal/wire/wire.go` builds it, who signs it, who verifies it, and which
entry of `spec/vectors/v1.json` covers it.

## Common rules

- **Signature scheme.** Ed25519 as in RFC 8032 (pure Ed25519: no prehash, no context string), over the UTF-8
  bytes of the statement text. Every statement is plain ASCII.
- **Layout.** The fields are joined with a single line feed (`0x0A`). There is no line feed before the first
  field and none after the last one. No field may contain a line feed; every field format below excludes it.
- **Domain prefix.** The first field names the statement and its version (`hl-...-v1`). A signature for one
  statement type never verifies as another.
- **Host.** `host` is the public host name of the relay as configured on the relay (`HLP_PUBLIC_HOST`),
  lowercase, without scheme, port or trailing dot, for example `push.healthlog.dev` or `push.example.org`.
  The relay uses its configured name, never the `Host` header of the request. A statement for one relay
  never verifies at another.
- **Keys and signatures on the wire.** Ed25519 public keys (32 bytes) and signatures (64 bytes) travel as
  unpadded base64url (alphabet `A-Z a-z 0-9 - _`, no `=`). A value that is padded, uses `+` or `/`, contains
  whitespace or decodes to the wrong length is refused as malformed.
- **Inside the text** binary values are lowercase hex, never base64url, with one exception: the request
  nonce and the challenge appear exactly as they travel (base64url), because they are opaque strings.
- **Numbers** are decimal ASCII without sign, without leading zeros and without a fraction: unix seconds for
  times, the HTTP status code, the binding sequence number. In JSON bodies the same values are JSON integers;
  in headers (`HL-Timestamp`, `HL-Iat`) they are at most 11 digits.
- **Body hash.** `hex(SHA-256(body))` is the lowercase hex SHA-256 of the exact body bytes as sent or
  received, before any parsing. An empty body hashes to
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- **Token tag.** `tokenTag = SHA-256("hl-push-token" || token)[0..16]` over the raw token bytes, written as
  32 lowercase hex characters (see `spec/envelope.md`, "AAD"). A token itself travels as hex (upper- or
  lowercase, 64 to 512 characters); the tag is computed from the decoded bytes.
- **Clock skew.** Where a statement carries a time, the relay accepts it when it differs from the relay clock
  by at most 300 seconds in either direction. A time outside that window is refused as `stale_timestamp`
  together with the relay time, before the signature is checked.

| Encoding | Used for |
|---|---|
| lowercase hex | instance public key in `hl-register-v1`, token tags, body hashes |
| base64url, unpadded, as sent | request nonce, conflict challenge |
| decimal unix seconds | `t`, `iat` |
| decimal integer | status code, `seq` |
| literal | statement prefix, `kind` (`device`), method, path, `-` for a missing nonce |

## hl-register-v1

Proof of possession of a new instance key, at registration and at key rotation.

```
hl-register-v1
<host>
<hex(publicKey)>
<time>
```

| Field | Value |
|---|---|
| `hex(publicKey)` | the new Ed25519 instance public key, 64 lowercase hex characters |
| `time` | the `time` field of the request body, unix seconds, within 300 s of the relay clock |

- **Signs:** the new instance key (at rotation the new key, not the old one; the rotation request itself is
  additionally signed with the old key through `hl-relay-v1`).
- **Verifies:** the relay, on `POST /v1/instances` and `POST /v1/instances/self/rotate`. The body carries the
  key as base64url in `publicKey` and the signature in `proof`.
- **Vectors:** `register`, `rotateNewKeyProof`.

## hl-relay-v1

Signature of the instance over every authenticated request.

```
hl-relay-v1
<host>
<instanceId>
<METHOD>
<pathAndQuery>
<timestamp>
<nonce>
<hex(SHA-256(body))>
```

| Field | Value |
|---|---|
| `instanceId` | the `HL-Instance` header: lowercase UUIDv4 issued by the relay |
| `METHOD` | the HTTP method as sent, uppercase (`GET`, `POST`, `DELETE`) |
| `pathAndQuery` | the request target exactly as sent: path, and `?` plus query when there is one, without scheme and host, without normalisation (for HTTP/2 the `:path` pseudo-header) |
| `timestamp` | the `HL-Timestamp` header, unix seconds |
| `nonce` | the `HL-Nonce` header as sent: 16 random bytes, unpadded base64url (22 characters) |
| body hash | over the raw request body; empty for `GET` and for an empty `DELETE` |

- **Signs:** the instance key registered for `instanceId`. The signature travels in `HL-Signature`.
- **Verifies:** the relay, for every endpoint listed as instance-authenticated in `spec/protocol.md`.
- The timestamp must be within 300 s of the relay clock and not earlier than the start of the relay process.
  Each nonce is accepted once per instance within the window.
- **Vectors:** `request` (POST with body `{"items":[]}`), `requestWithQuery` (GET with a query and an empty
  body). Negative: `requestQueryAdded`, `requestOtherMethod`.

## hl-relay-resp-v2

Signature of the relay over every response it produces through its JSON reply path. Version 2 replaces
version 1 before any release: it binds method and path, and the nonce is mandatory on every `/v1` request.

```
hl-relay-resp-v2
<host>
<method>
<path-with-query>
<nonce>
<status>
<hex(SHA-256(body))>
```

| Field | Value |
|---|---|
| `host` | the relay's configured public host name, for example `push.healthlog.dev` (never taken from the request) |
| `method` | the request method exactly as sent, upper case (`GET`, `POST`, `DELETE`) |
| `path-with-query` | the raw request target exactly as sent on the wire, path plus `?query` if present, not decoded or normalised (for HTTP/2 the `:path` pseudo-header) |
| `nonce` | the request's `HL-Nonce` header: 16 random bytes, unpadded base64url, exactly 22 characters. The single character `-` appears only where no valid nonce exists (see below) |
| `status` | the HTTP status code of the response, decimal, no leading zeros |
| body hash | lowercase hex SHA-256 over the exact response body bytes; for an empty body (every `204`) the hash of the empty string, `e3b0c442...b855` |

Fields are joined with a single line feed (0x0A), no trailing line feed, UTF-8. The signature is Ed25519 by
the relay identity key over these bytes, sent as unpadded base64url in the response header
`HL-Relay-Signature`.

Client rules (HealthLog server and app, both MUST):

1. Send a fresh `HL-Nonce` (16 bytes from a CSPRNG) on every `/v1` request, including registration and the
   app's direct calls. The relay answers a `/v1` request without a valid nonce with `400 nonce_required`.
2. Rebuild the text from the request it sent (own method, own raw path with query, own nonce) and the
   response it received (status, raw body bytes), and verify against each pinned relay identity key
   (`current`, then `next`).
3. Treat as a transport error, never as an answer: a missing or invalid signature, and any response bound to
   `-`. A transport error is never read as a refusal, a revocation, `410`, `426` or a notice.
4. Take retry hints only from the signed body (`retryAfter`, seconds), never from the unsigned `Retry-After`
   header, and cap them at 86 400 seconds.
5. Refuse a response body longer than 262 144 bytes without reading it further (the relay never sends more
   than 65 536).

`-` is used only for `GET /healthz` and `GET /version` when the caller sends no nonce (monitors that do not
verify), and for the `400 nonce_required` refusal itself.

- **Signs:** the relay identity key. **Verifies:** the HealthLog server for its requests and the app for its
  direct calls, against the pinned relay identity keys.
- A response replayed onto another request (other nonce, method or path), a changed status or a changed body
  fails.
- The pages `/`, `/privacy`, `/terms`, `/privacy.txt`, `/terms.txt` and `/.well-known/security.txt` are not
  signed, in either form.
- **Vectors:** `response` (`POST /v1/push`, status 200, body `{"items":[]}`), `responseAppEndpoint`
  (`DELETE /v1/bindings/self`, status 204, empty body), `responseWithoutNonce` (`GET /healthz`, status 200).
  Negative: `responseOtherNonce`, `responseOtherStatus`, `responseOtherMethod`, `responseOtherPath`,
  `responseAppReplayedOntoOtherRequest`.

## hl-relay-status-v1

Signature of the relay over the out-of-band status file.

```
hl-relay-status-v1
<host>
<hex(SHA-256(body))>
```

- **Signs:** the relay identity key.
- **Verifies:** the HealthLog server, against the pinned relay identity keys, when it fetches the status file
  from a location other than the relay (see `spec/protocol.md`, "Status file").
- `body` is the exact byte string of the `body` member of the status file, not a re-serialisation of it.
- **Vector:** `statusFile` (body `{"notice":null}`).

## hl-relay-export-v1

Signature of the relay over its daily registry export (`spec/protocol.md`, "Registry export").

```
hl-relay-export-v1
<host>
<hex(SHA-256(export))>
```

| Field | Value |
|---|---|
| `host` | the relay's configured public host name; must equal the export's `host` field |
| export hash | lowercase hex SHA-256 over the export marshaled as JSON without its `signature` field (Go `encoding/json` of the export object with `signature` empty and therefore omitted) |

- **Signs:** the relay identity key, when it writes `registry.json`. An unsigned export is never written. The
  signature travels as unpadded base64url in the export's `signature` field.
- **Verifies:** the relay itself, on import (start with an empty data directory or after a damaged store was
  moved aside, and the operator's `recovery --from`), against its own identity public key and configured
  host. A missing or invalid signature, or another host, makes the whole import fail.
- **Vector:** `registryExport` (body `{"format":"healthlog-push-registry-v2"}`).

## hl-bind-v1

The device statement that binds an APNs device token to one instance.

```
hl-bind-v1
<host>
<instanceId>
<hex(tokenTag)>
<kind>
<seq>
<iat>
```

| Field | Value |
|---|---|
| `instanceId` | the instance the device binds to; must equal the `HL-Instance` of the request that carries the statement |
| `tokenTag` | tag of the APNs device token in the same request |
| `kind` | the literal `device` |
| `seq` | a non-negative counter per binding key, increased for every new statement |
| `iat` | unix seconds, within 300 s of the relay clock |

- **Signs:** the device binding key (Ed25519, one per app installation and relay host, never leaves the
  device).
- **Verifies:** the relay, on `POST /v1/bindings`. The HealthLog server forwards the statement unchanged and
  may verify it before forwarding.
- A statement for another instance cannot be reused: the instance id is signed (negative vector
  `bindOtherInstance`). An older statement cannot be replayed after a move: its `seq` is lower
  (`bindLowerSeq`).
- **Vector:** `bind`. Negative: `bindOtherInstance`, `bindLowerSeq`, `bindOtherHost`.

## hl-unbind-v1

The direct opt-out: the device leaves an instance without the instance's cooperation.

```
hl-unbind-v1
<host>
<instanceId>
<hex(tokenTag)>
<iat>
```

- **Signs:** the device binding key.
- **Verifies:** the relay, on `DELETE /v1/bindings/self`, sent by the app itself. The key must be the one
  stored for the binding of that token and instance.
- `iat` within 300 s of the relay clock.
- The relay keeps this `iat` in memory for 10 minutes, never in the store. Only an `hl-bind-v1` statement by
  the same key with a higher `seq` and an `iat` later than the opt-out (while it is in memory) and than the
  start of the relay process returns the device to that instance (`spec/protocol.md`, "Returning").
- **Vector:** `unbind`. Negative: `unbindOtherInstance`.

## hl-challenge-v1

The answer to a binding conflict challenge.

```
hl-challenge-v1
<host>
<challenge>
<hex(tokenTag)>
```

| Field | Value |
|---|---|
| `challenge` | the value of `c` in the challenge push, as received: 32 random bytes in unpadded base64url (43 characters) |
| `tokenTag` | tag of the device token the challenge push was sent to |

- **Signs:** the binding key that the conflicting bind request presented (the new key).
- **Verifies:** the relay, on `POST /v1/bindings/challenge`, sent by the app itself.
- There is no time field. A challenge is valid for 30 minutes after it was issued and can be answered once.
- **Vector:** `challenge`.

## hl-activity-v1

The Live Activity statement over an activity's update token, made by the device when the activity starts.
The relay checks it on every `update` and `end` push of that activity.

```
hl-activity-v1
<host>
<instanceId>
<hex(tokenTag)>
<hex(laTokenTag)>
<iat>
```

| Field | Value |
|---|---|
| `tokenTag` | tag of the APNs device token of the binding (the item's `token`) |
| `laTokenTag` | tag of the Live Activity push token (the item's `activity.token`) |
| `iat` | unix seconds, the start of the activity |

- **Signs:** the device binding key.
- **Verifies:** the relay, on a `liveactivity` item of `POST /v1/push`, against the binding key of the active
  binding of the same token and the requesting instance. The HealthLog server stores the statement and passes
  it on unchanged.
- The window differs from the other statements: `iat` may be at most 300 s in the future and at most
  43200 s (12 h: the activity lifetime of 8 h plus the class deadline of 4 h) in the past.
- **Vector:** `activity`. Negative: `activityTokenSwapped`.

## hl-la-start-v1

The push-to-start statement: the device allows its instance to start Live Activities through the relay with
this push-to-start token.

```
hl-la-start-v1
<host>
<instanceId>
<hex(tokenTag)>
<hex(startTokenTag)>
<iat>
```

| Field | Value |
|---|---|
| `tokenTag` | tag of the APNs device token of the binding (the item's `token`) |
| `startTokenTag` | tag of the push-to-start token (the item's `activity.token`) |
| `iat` | unix seconds when the device signed; the app signs again whenever the push-to-start token changes and at least every 30 days |

- **Signs:** the device binding key. **Verifies:** the relay, on a `liveactivity` item with `event: "start"`,
  against the binding key of the active binding of the same token and the requesting instance.
- Window: at most 300 s in the future and at most 2592000 s (30 days) in the past.
- An `hl-activity-v1` statement never starts an activity, and this statement never updates or ends one.
- **Vector:** `laStart`. Negative: `laStartAsActivity`.

## hl-la-consent-v1

The device's consent to Live Activity start and update over the relay. It is separate from the relay
consent: start and update carry the content state in the clear, so with this consent the relay and Apple see
when a dose is due.

```
hl-la-consent-v1
<host>
<instanceId>
<hex(tokenTag)>
<textVersion>
<iat>
```

| Field | Value |
|---|---|
| `tokenTag` | tag of the APNs device token of the binding |
| `textVersion` | the version of the consent text the person accepted, `[A-Za-z0-9._-]{1,32}`, for example `2026-11-21` |
| `iat` | unix seconds; within 300 s of the relay clock when presented |

- **Signs:** the device binding key. **Verifies:** the relay, on `POST /v1/bindings/liveactivity`, against
  the binding key of the binding of that token held by the requesting instance. The HealthLog server passes
  it on unchanged. The relay stores the text version and the day with the binding.
- The consent belongs to the binding key: it survives a rebind by the same key to the same instance and is
  dropped when the binding changes key or instance.
- **Vector:** `laConsent`. Negative: `laConsentOtherVersion`.

## hl-la-withdraw-v1

The device withdraws its Live Activity consent directly at the relay, without its instance.

```
hl-la-withdraw-v1
<host>
<instanceId>
<hex(tokenTag)>
<iat>
```

- **Signs:** the device binding key. **Verifies:** the relay, on `DELETE /v1/bindings/self/liveactivity`
  (body shaped like the opt-out: `token`, `bindingKey`, `statement {instanceId, tokenTag, iat}`,
  `signature`). `iat` within 300 s. The binding stays; only the Live Activity consent is removed.
- **Vector:** `laWithdraw`. Negative: `laWithdrawAsUnbind` (an opt-out statement is not a withdrawal and the
  other way round).

## hl-selfread-v1

The device reads what the relay holds about its binding.

```
hl-selfread-v1
<host>
<hex(tokenTag)>
<iat>
```

- **Signs:** the device binding key.
- **Verifies:** the relay, on `GET /v1/bindings/self`. The values travel in headers: `HL-Token` (the device
  token in hex), `HL-Binding-Key`, `HL-Iat` and `HL-Signature`.
- The statement names no instance; the binding of a token is unique at the relay.
- `iat` within 300 s of the relay clock.
- **Vector:** `selfRead`.

## Summary

| Statement | Signed by | Verified by | Time check | Vectors |
|---|---|---|---|---|
| `hl-register-v1` | new instance key | relay | `time` within 300 s | `register`, `rotateNewKeyProof` |
| `hl-relay-v1` | instance key | relay | `HL-Timestamp` within 300 s, not before relay start | `request`, `requestWithQuery` |
| `hl-relay-resp-v2` | relay identity key | server, app | none (method, path and nonce bind) | `response`, `responseAppEndpoint`, `responseWithoutNonce` |
| `hl-relay-export-v1` | relay identity key | relay (on import) | none (`day` in the export) | `registryExport` |
| `hl-relay-status-v1` | relay identity key | server | none (`issued` in the body) | `statusFile` |
| `hl-bind-v1` | binding key | relay | `iat` within 300 s | `bind` |
| `hl-unbind-v1` | binding key | relay | `iat` within 300 s | `unbind` |
| `hl-challenge-v1` | binding key | relay | challenge age at most 30 min | `challenge` |
| `hl-activity-v1` | binding key | relay | `iat` at most 300 s ahead, at most 12 h old | `activity` |
| `hl-la-start-v1` | binding key | relay | `iat` at most 300 s ahead, at most 30 days old | `laStart` |
| `hl-la-consent-v1` | binding key | relay | `iat` within 300 s | `laConsent` |
| `hl-la-withdraw-v1` | binding key | relay | `iat` within 300 s | `laWithdraw` |
| `hl-selfread-v1` | binding key | relay | `iat` within 300 s | `selfRead` |

Each vector carries the public key (`publicKey`), the exact text (`text`), the signature (`signature`) and,
for statements that hash a body, the body (`body`). The keys derive from the synthetic seeds in `keys`
(`instanceSeed`, `instanceRotatedSeed`, `bindingSeed`, `relaySeed`). Ed25519 signatures are deterministic,
so an implementation that builds the same text with the same seed must produce the same signature byte for
byte. Every entry of `negativeStatements` is a mutated text that must not verify under the public key and
signature of the statement named in `of`.
