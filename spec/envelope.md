# Push envelope, version 1

The envelope carries everything a HealthLog server wants a device to see. The server seals it for one
device, the relay forwards it to Apple unchanged inside a fixed payload template, and the device opens it.
The relay never holds a key that opens an envelope and never looks inside one.

The reference implementation is `spec/tools/envelope.mjs`. The test vectors in `spec/vectors/v1.json` are
normative: an implementation that disagrees with a vector is wrong, not the vector.

## Algorithm

HPKE as specified in RFC 9180, in `mode_auth` (mode byte `0x02`), with the suite

| Component | RFC 9180 identifier | Name |
|---|---|---|
| KEM | `0x0020` | DHKEM(X25519, HKDF-SHA256) |
| KDF | `0x0001` | HKDF-SHA256 |
| AEAD | `0x0003` | ChaCha20-Poly1305 |

- One message per encapsulation: the AEAD nonce is the HPKE `base_nonce` at sequence number 0. No envelope
  ever uses a second sequence number.
- `info` is the ASCII string `HealthLog push envelope v1` (26 bytes).
- `psk` and `psk_id` are empty (auth mode, no pre-shared key).
- The recipient key pair (`skR`, `pkR`) is the device key: X25519, raw 32 bytes.
- The sender key pair (`skS`, `pkS`) is the sender key of one HealthLog server for one relay host: X25519,
  raw 32 bytes. The device trusts only the sender keys it has pinned for that account.

Auth mode is used because in base mode anybody who knows a device public key can build an envelope that the
device opens. In auth mode only the holder of a pinned sender key can. A leaked sender key allows forging
envelopes for the devices that pin it; it does not decrypt past envelopes, because the shared secret also
needs `dh(skE, pkR)`.

### Ephemeral key

The ephemeral key `skE` is generated fresh, from a cryptographically secure source, inside every seal
operation. A production sealer:

- never accepts an ephemeral key from its caller,
- never caches or reuses an ephemeral key,
- on a retry sends the already sealed envelope again instead of sealing again.

Reusing `skE` for the same recipient reuses the AEAD key and nonce. With ChaCha20-Poly1305 that reveals the
XOR of two plaintexts and allows forgeries. The only function that takes an injected ephemeral key is
`sealWithInjectedEphemeralForVectors` in `spec/tools/envelope.mjs`, which exists to make the test vectors
deterministic. Implementations keep the equivalent, if they have one, in test code only and guard that by a
test.

## Format

The envelope is binary. On the wire (inside the relay API and inside the Apple payload) it is encoded as
unpadded base64url.

| Offset | Length | Field | Value |
|---|---|---|---|
| 0 | 1 | version | `0x01` |
| 1 | 1 | suite | `0x01`: HPKE `mode_auth`, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 |
| 2 | 1 | class | `0x01` alert, `0x02` silent, `0x03` live activity |
| 3 | 32 | `enc` | the encapsulated ephemeral public key |
| 35 | B + 16 | ciphertext | AEAD output over the padded plaintext of B bytes, followed by the 16-byte tag |

The header (bytes 0 to 2) carries no key identifier of any kind. For a given class it is the same for every
device of every server, so it cannot be used to group devices. A device with at most two recipient keys and
at most two pinned sender keys tries every pair, at most four derivations.

### Fixed sizes

The plaintext is padded to a fixed bucket per class, so the envelope length depends on the class only.

| Class | Class byte | Bucket B | Envelope length | base64url characters |
|---|---|---|---|---|
| `alert` | `0x01` | 1024 | 1075 | 1434 |
| `silent` | `0x02` | 1024 | 1075 | 1434 |
| `liveactivity` | `0x03` | 512 | 563 | 751 |

Envelope length is `3 + 32 + B + 16`.

The class byte `0x03` is reserved for sealed Live Activity content. Protocol version 1 sends Live Activity
`end` events from a fixed template without an envelope (see `spec/protocol.md`, "What the relay sends to
Apple"), so a v1 relay never forwards a `0x03` envelope.

### AAD

```
aad = header[0..3] || tokenTag
tokenTag = SHA-256("hl-push-token" || apnsToken)[0..16]
```

`apnsToken` is the raw APNs device token (the bytes, not the hex string). `"hl-push-token"` is the 13 ASCII
bytes without a terminator. The AAD is 19 bytes. It binds the version, the suite, the class and the device
token; the KEM context binds `pkR` and `pkS`. A silent envelope relabelled as alert fails on the alert path
with `authFailure` (vector `classByteTamperedOnMatchingPath`).

Vector: `aad.alert` in `spec/vectors/v1.json`, for the synthetic token of `keys.apnsToken`.

### Padded plaintext

```
padded = uint16_be(len) || json || zero bytes up to B
```

- `json` is the UTF-8 encoding of one JSON object (the plaintext schema below), `len` its length in bytes.
- `len` is at least 1 and at most `B - 2`.
- Every byte after `json` is `0x00`.

A sealer whose JSON does not fit shortens visible text at character boundaries, measured after JSON encoding,
until it fits. The bucket never changes. The vector `exactBucketMultibyteEnd` fills an alert bucket exactly
(1022 bytes of JSON) and ends on a two-byte UTF-8 character.

## Plaintext schema

```json
{
  "v": 1,
  "t": "MEDICATION_INTAKE_RECORDED",
  "id": "01JTESTVECT000000000000001",
  "iat": 1795000000,
  "exp": 1795007200,
  "d": { },
  "n": { "title": "...", "body": "...", "subtitle": "..." },
  "ui": { "category": "...", "thread": "...", "level": "passive", "sound": "default", "badge": 3 }
}
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `v` | integer | yes | schema version, exactly `1` |
| `t` | string | yes | message type; an unknown type is shown as a neutral placeholder |
| `id` | string | yes | ULID, 26 characters of Crockford base32 (`^[0-9A-HJKMNP-TV-Z]{26}$`); the replay key |
| `iat` | integer | yes | issue time, unix seconds |
| `exp` | integer | yes | expiry, unix seconds; `exp > iat` and `exp - iat` at most the class maximum |
| `d` | object | no | data for the app |
| `n` | object | no | visible text: `title`, `body`, `subtitle` |
| `ui` | object | no | presentation set by the notification service extension: `category` (a logical name), `thread`, `level` (`passive`, `active`, `time-sensitive`), `sound`, `badge` |

There is no URL or deep-link field. Deep-link targets are derived by the app from `t` and the identifiers in
`d`. A receiver checks `ui.sound` and `ui.category` against fixed lists, bounds `badge` (0 to 999) and the
length of every string, and accepts `level: time-sensitive` only for the types allowed to use it.

Class maxima for `exp - iat` (the same values bound `ttlSeconds` at the relay):

| Class | Maximum lifetime |
|---|---|
| `alert` | 21600 s (6 h) |
| `silent` | 3600 s (1 h) |
| `liveactivity` | 14400 s (4 h) |

## Opening

The receiver knows the class from the path the push arrived on (alert through the notification service
extension, silent through background delivery). It opens in this order. Each step has its own error code,
and the first failing step decides the code.

| Step | Check | Error code |
|---|---|---|
| 1 | length at least `3 + 32 + 16 + 2` (53 bytes) | `malformed` |
| 2 | version byte `0x01` and suite byte `0x01` | `unsupportedVersion` |
| 3 | class byte equals the class of the arrival path | `classMismatch` |
| 4 | length equals the envelope length of that class | `malformed` |
| 5 | for every pair of own recipient key and pinned sender key: auth decapsulation, key schedule, AEAD open with the AAD above; any failure of a pair, including a derivation failure for a low-order `enc`, only fails that pair | `authFailure` when no pair opens |
| 6 | length prefix not zero and `len + 2` within the bucket; all padding bytes zero; strict UTF-8 (no replacement); valid JSON; schema: `v == 1`, `t` a string, `id` a ULID, `iat` and `exp` integers | `malformed` |
| 7 | `exp > iat` and `exp - iat` within the class maximum | `lifetimeTooLong` |
| 8 | `iat <= now + 300` | `notYetValid` |
| 9 | `now <= exp + 300` | `expired` |
| 10 | replay store (below) | `replayed`, `replayStoreFull` |

"Unknown sender", "unknown recipient key" and "wrong device token" all end in `authFailure`; the receiver
does not learn which one it was, and does not try to.

On any failure the receiver shows a neutral placeholder (alert path) or does nothing (silent path) and has
no side effect. A silent push that fails to open does not start a sync, because it did not come from the
device's own server.

Vectors: every entry of `envelopes` in `spec/vectors/v1.json` names the expected code in `expect` (`ok` or
one of the codes above). The replay codes are state, not vector, cases.

## Replay store

- The receiver records every opened `id` together with its `exp`.
- An `id` stays recorded until `exp + 300` seconds have passed; only then may it be pruned.
- An `id` already recorded is refused with `replayed`.
- The capacity is at least 512 entries, which is above the relay's per-device daily quota of 300 pushes, so
  a valid `id` is never evicted while its envelope could still be opened. A full store refuses with
  `replayStoreFull` instead of evicting.
- If the store is full or cannot be read, the receiver behaves as on any other failure: placeholder, no side
  effect.
- The store is shared between every process that opens envelopes (app and extension); reads and writes are
  atomic under a file lock.

Because `exp` is inside the sealed plaintext, neither the relay nor anybody on the path can hold an
envelope back and deliver it later than the server intended.

## Keys

| Key | Type | Held by | Encoding on the wire |
|---|---|---|---|
| device key (recipient) | X25519 | device, in a keychain group reachable only by the app and its notification extension | raw 32 bytes, base64url |
| sender key | X25519 | HealthLog server, encrypted at rest; one per relay host | raw 32 bytes, base64url |

The key id `SHA-256("hl-push-key" || pkR)[0..8]` exists for APIs and display only and never appears in an
envelope. Vector: `keys.recipientKeyIdApiOnly`.

### Low-order key rejection

A recipient public key is refused before it is ever used for sealing when it is not 32 bytes or when an
X25519 derivation against it yields the all-zero shared secret. This covers the known low-order points of
Curve25519, listed in `lowOrderPoints` of `spec/vectors/v1.json`:

```
0000000000000000000000000000000000000000000000000000000000000000
0100000000000000000000000000000000000000000000000000000000000000
e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800
5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157
ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
```

A server rejects such a key at device registration (status 422), and the reference sealer refuses it with
`invalidRecipientKey`. On the receiving side a low-order `enc` makes the derivation fail for every pair and
ends in `authFailure` (vectors `lowOrderEncZero` and `lowOrderEncPoint`).

### Rotation

- **Device key:** a new pair at every sign-in, every 30 days and at reinstallation. The previous pair stays
  usable for opening for 7 days, so the receiver holds at most two recipient keys. Signing out deletes every
  pair of that account together with its pinned sender keys. Vector: `previousRecipientKey`.
- **Sender key:** rotated yearly and on demand. The previous key stays pinned as `previous` for 30 days, so
  the receiver trusts at most two sender keys. An emergency rotation drops the previous key at once.
  Vector: `previousSender`.
- Rotation never changes the envelope format; the header carries no key id, so nothing in the envelope
  reveals which key was used.

## What the relay checks

The relay checks the outer frame only, against the class the push item claims:

1. the `envelope` field decodes as unpadded base64url to exactly the envelope length of the class,
2. byte 0 is `0x01`, byte 1 is `0x01`,
3. byte 2 is the class byte of the item's `class`.

Anything else, including authentication, padding and the plaintext, is opaque to the relay. An envelope
that fails step 5 or later on the device passes the relay. The verdict the relay must reach for each
envelope vector is recorded in its `relay` field (`accept` or `reject`); `internal/wire/vectors_test.go`
checks the Go implementation against it.

The relay forwards the bytes unchanged. It never re-encodes, truncates or pads an envelope.
