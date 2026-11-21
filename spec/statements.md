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
  lowercase, 64 to 200 characters); the tag is computed from the decoded bytes.
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

## hl-relay-resp-v1

Signature of the relay over every response it produces through its JSON reply path.

```
hl-relay-resp-v1
<host>
<nonce>
<status>
<hex(SHA-256(body))>
```

| Field | Value |
|---|---|
| `nonce` | the `HL-Nonce` header of the request when it is well formed (22 characters of base64url decoding to 16 bytes), otherwise the single character `-` |
| `status` | the HTTP status code of the response, decimal |
| body hash | over the response body bytes; empty for `204` |

- **Signs:** the relay identity key. The signature travels in the response header `HL-Relay-Signature`.
- **Verifies:** the HealthLog server for its requests, and the app for its direct calls, against the relay
  identity keys they have pinned (`current` and `next`). A missing or invalid signature is a transport error:
  the response is treated as if it never arrived, and in particular never as a refusal, a revocation, an
  upgrade demand or a notice.
- The nonce binds the response to the request. A response replayed onto another request, a changed status or
  a changed body fails. Requests that carry no nonce (registration, and app calls that send none) get `-`;
  the app may send its own `HL-Nonce` on a direct call to bind the answer, the relay neither checks nor
  records it there.
- The plain-text pages `/`, `/privacy` and `/terms` are not signed.
- **Vectors:** `response` (status 200, body `{"items":[]}`), `responseWithoutNonce` (status 404, body
  `{"error":"not_found"}`). Negative: `responseOtherNonce`, `responseOtherStatus`.

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

The Live Activity statement, made by the device when an activity starts, sent to the relay only with the
`end` push.

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
| `hl-relay-resp-v1` | relay identity key | server, app | none (nonce binds) | `response`, `responseWithoutNonce` |
| `hl-relay-status-v1` | relay identity key | server | none (`issued` in the body) | `statusFile` |
| `hl-bind-v1` | binding key | relay | `iat` within 300 s | `bind` |
| `hl-unbind-v1` | binding key | relay | `iat` within 300 s | `unbind` |
| `hl-challenge-v1` | binding key | relay | challenge age at most 30 min | `challenge` |
| `hl-activity-v1` | binding key | relay | `iat` at most 300 s ahead, at most 12 h old | `activity` |
| `hl-selfread-v1` | binding key | relay | `iat` within 300 s | `selfRead` |

Each vector carries the public key (`publicKey`), the exact text (`text`), the signature (`signature`) and,
for statements that hash a body, the body (`body`). The keys derive from the synthetic seeds in `keys`
(`instanceSeed`, `instanceRotatedSeed`, `bindingSeed`, `relaySeed`). Ed25519 signatures are deterministic,
so an implementation that builds the same text with the same seed must produce the same signature byte for
byte. Every entry of `negativeStatements` is a mutated text that must not verify under the public key and
signature of the statement named in `of`.
