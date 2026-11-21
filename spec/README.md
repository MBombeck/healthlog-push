# HealthLog push relay specification

This directory is the contract between the three independent implementations of the HealthLog push path:
the relay in this repository, the HealthLog server that seals envelopes and calls the relay, and the iOS app
that opens envelopes and talks to the relay directly for its own binding. Any of them can be replaced by
another implementation that follows these documents and passes the vectors.

## Contents

| Path | What it is |
|---|---|
| `protocol.md` | the HTTP protocol: actors, endpoints, check order, results, limits, state and retention |
| `statements.md` | every signed text, byte for byte, with its signer, verifier and vector |
| `envelope.md` | the end-to-end envelope: HPKE suite, binary layout, AAD, padding, plaintext schema, open order, replay store |
| `relay-api.yaml` | OpenAPI 3.1 description of every public endpoint, its headers and its JSON schemas |
| `vectors/v1.json` | test vectors for the envelope and the statements; normative |
| `tools/envelope.mjs` | reference seal and open on `node:crypto` only |
| `tools/gen-vectors.mjs` | generator of `vectors/v1.json` from the reference |
| `tools/check-vectors.mjs` | independent check of `vectors/v1.json` against the reference |
| `tools/reference/hpke-proof.mjs` | the design proof the reference functions come from, including RFC 9180 checks |
| `LICENSE` | CC0 1.0 Universal |

The test vectors are normative. When a document and a vector disagree, the vector wins and the document is
corrected.

## Versioning

There are three independent version markers. None of them changes silently.

- **Specification tag.** The state of this directory that the first interoperable releases build against is
  tagged `spec-v1`. Implementations pin the SHA-256 of `vectors/v1.json` from that tag. A file published
  under a `spec-vN` tag is never edited in place; a change to the wire format, to a signed text or to a
  cryptographic step produces a new vector file (`vectors/v2.json`) and a new tag.
- **Envelope version byte** (byte 0 of every envelope, currently `0x01`). It names the envelope layout:
  header, AAD construction, padding and plaintext framing. A receiver refuses an unknown version with
  `unsupportedVersion`.
- **Envelope suite byte** (byte 1, currently `0x01`: HPKE `mode_auth` with DHKEM(X25519, HKDF-SHA256),
  HKDF-SHA256 and ChaCha20-Poly1305). A new cipher suite gets a new suite byte under the same layout; a
  receiver refuses an unknown suite with `unsupportedVersion`. Devices report the suites they support when
  they register with their server, so a server never seals with a suite a device cannot open.

Signed texts carry their own version in the prefix (`hl-relay-v1`, `hl-bind-v1`, ...). A changed text gets a
new prefix, so an old signature can never be read under new rules.

## License

Everything under `spec/`, the test vectors and the tools included, is dedicated to the public domain under
CC0 1.0 Universal (`spec/LICENSE`, SPDX identifier `CC0-1.0`). Anybody may copy the vectors into their own
test suite, under any license, without attribution. The rest of the repository is licensed separately (see
the `LICENSE` file at the repository root).

All key material in the vectors is synthetic (repeated bytes). It is published on purpose and must never be
used outside tests.

## Checking the vectors

The checker needs Node.js 22 or later and nothing else (no packages, no network):

```sh
node spec/tools/check-vectors.mjs
```

It checks that `vectors/v1.json` is exactly what the generator produces (no hand edits), runs the reference
proof in `tools/reference/hpke-proof.mjs` (including the RFC 9180 test vectors A.2.1 and A.2.3) and compares
its alert envelope with the `alert` vector, opens every envelope vector with the reference implementation
and compares the outcome with `expect`, recomputes every token tag, verifies every statement signature and
makes sure every negative statement fails. It prints a summary line on success, and every failed check plus a non-zero exit code otherwise. CI
runs it on every change.

To regenerate the vectors after an intentional, versioned change:

```sh
node spec/tools/gen-vectors.mjs           # prints the JSON
node spec/tools/gen-vectors.mjs --write   # writes spec/vectors/v1.json and prints its SHA-256
```

The generator re-opens every vector it writes and stops when an outcome differs from what it recorded.

## How the Go tests use the vectors

`internal/wire/vectors_test.go` reads the same `spec/vectors/v1.json` (relative to the repository root), so
the relay and the reference cannot drift apart:

- `TestVectorsTokenTags` recomputes every token tag with the Go `TokenTag`.
- `TestVectorsEnvelopeFrame` runs the relay's outer frame check (`CheckEnvelopeFrame`) on every envelope
  vector for the class in `expectedClass` and compares the verdict with the vector's `relay` field
  (`accept` or `reject`). Envelopes that fail only inside (for example `authFailure`) must be accepted by
  the relay, which never opens them. It also compares the class lengths with `constants.envelopeLength`.
- `TestVectorsStatements` builds every statement with the Go text builders in `internal/wire/wire.go` from
  the vector inputs, requires the text to be byte-identical to the vector, verifies the signature, signs
  again with the seed from `keys` and requires the same signature, and checks that every negative statement
  fails.

Run them with `go test ./internal/wire/`.
