# Assurance case

Why the maintainer believes that healthlog-push meets its security requirements. This page does not add
new claims. It collects the argument in one place and points to the evidence: the threat model, the
security invariants with their tests, and the build and release pipeline. Where a claim cannot be made, the
page says so.

## 1. The claim

A self-hosted HealthLog server can send push notifications through the relay, and:

1. the relay and its operator cannot read a notification;
2. a server can push only to devices that agreed to it, and a device can leave without anybody's help;
3. requests and answers cannot be forged or replayed;
4. the relay stores and reveals no more than the published lists say;
5. one server cannot take the service away from the others;
6. what users run is what this repository built.

These are the security requirements. They are written for users in the
[README](../README.md) and in [privacy.md](privacy.md), and for reviewers as numbered invariants in
[security-invariants.md](security-invariants.md).

## 2. Threat model

[threat-model.md](threat-model.md) names the assets (notification content, the APNs key, the provider token,
the relay identity key, the token MAC key, device tokens, bindings, metadata, availability), the actors
(instance operator, device, relay operator, network attacker, mass registrant, intruder, Apple), and for
each actor what it can and cannot do. Its section "Known limitations" lists every accepted risk.

## 3. Trust boundaries

| Boundary | What crosses it | What is checked at the boundary |
|---|---|---|
| Internet to relay (TLS 1.3 on port 443) | signed requests from servers, signed calls from the app, public pages | Headers before the body, body size budgets, strict JSON with unknown and duplicate keys refused, Ed25519 signature over host, method, path, time, nonce and body hash, single-use nonce, closed sets for every field (invariants A1 to A5, F1; every parser lives in `internal/wire` and is fuzzed, I2) |
| Server to device, through the relay | the sealed envelope | The relay checks only the outer frame and forwards it unchanged; it links no code that could open it (C1, C3) |
| Relay to Apple (HTTP/2, TLS with certificate verification) | fixed payload templates and the envelope | Payloads are built from constants in one package; a server chooses only class, envelope, lifetime and collapse id (C2) |
| Signer to relay (shared tmpfs) | a provider token valid for at most one hour; an empty marker file the other way | The signer has no network and parses nothing from the relay; the relay never holds the APNs key (D8, [threat-model.md](threat-model.md#compromise-of-the-relay-process)) |
| Relay to disk (store and export) | HMACs of tokens, public keys, day and week numbers | Closed set of buckets, retention applied, export signed and refused when edited, read only from the export directory (P3, P4) |
| Host to relay (admin socket) | operator commands | The socket trusts the host. Anyone who can run a command in the container is an operator. This is stated as a limitation, not countered. |
| Repository to user (release) | image, binaries, SBOM, provenance | Keyless signatures bound to the release workflow at the tag, verification commands in [release-verification.md](release-verification.md) |

## 4. Secure design principles

The principles are those of Saltzer and Schroeder. For each one: what the design does, and where it is held.

- **Economy of mechanism.** One binary, two processes, two direct dependencies, the standard library for
  HTTP, TLS and signatures ([dependencies.md](dependencies.md)). All mutable state sits behind one lock. A
  test keeps files under 350 lines and functions under 60 (I4).
- **Fail-safe defaults.** A new relay accepts registrations by invitation only. A missing, broken or old
  provider token stops sending (D8). An export that does not verify stops the start instead of importing
  part of it (P4). A body whose length is not declared is refused before it is read (F1).
- **Complete mediation.** Every `/v1` request is authenticated by its signature and its nonce, and
  non-canonical paths get a signed 404 instead of a redirect (A1 to A3). A handler that released the lock
  checks that its instance still exists before it writes (D7).
- **Open design.** The protocol, the envelope format and the test vectors are public and dedicated to the
  public domain ([spec/](../spec/README.md)). Security does not depend on anything being secret except the
  keys.
- **Separation of privilege.** The APNs key lives in a process without network; the process with network
  never sees it. The build job cannot sign a provenance that verifies, and the job that writes the SBOM
  cannot sign ([release-verification.md](release-verification.md#how-the-pipeline-is-protected)). Taking a
  binding over needs both the server and the device (B1, B2).
- **Least privilege.** Both containers run as unprivileged users with a read-only root filesystem, all
  capabilities dropped, a seccomp filter and an AppArmor profile each ([hardening.md](hardening.md)). Every
  workflow starts without token permissions and each job is granted what it needs.
- **Least common mechanism.** Limits are kept per server, per device and per address, so one party cannot
  spend another's budget (F2 to F4). Failed app calls share one bucket, and a correctly signed opt-out is
  never charged to it (F2).
- **Psychological acceptability.** A person agrees in the app before any key is created, and can leave from
  the app without asking the server operator (B4, B7).

## 5. Common implementation weaknesses

| Weakness | Why it does not apply, or how it is countered |
|---|---|
| Memory safety (buffer overflow, use after free) | Go, built with `CGO_ENABLED=0`; the relay code does not import `unsafe`. Tests run with the race detector. |
| Injection (SQL, command, template) | No SQL, no shell, no template engine. The store is a key-value file; payloads to Apple are constants plus an opaque envelope (C2). |
| Path traversal | The only path a caller can influence is the export file, opened through `os.Root` inside the export directory (P4). Found by CodeQL and fixed in 1.0.2. |
| Improper input validation | Strict JSON, closed sets, exact lengths; every parser of network input has a fuzz target that runs in CI from a committed corpus (I2). |
| Broken authentication, replay | Signatures over the full request, single-use nonces, a 300 second window, proof of possession for registration and rotation (A1 to A5). |
| Information exposure | No access log; one logger with a closed set of keys; tests fail when an address, a token or an instance id reaches logs, metrics, stats or the export (P1). Answers about tokens bound elsewhere are the same as for unknown tokens, also in the work done (B3). |
| Weak or home-made cryptography | Ed25519, ECDSA P-256, HMAC-SHA-256 and TLS from the Go standard library. The relay implements no cipher and links no envelope cryptography (C1). TLS 1.3 only for clients. |
| Hard-coded or leaked credentials | Keys are files outside the image and the repository ([key-ceremony.md](key-ceremony.md)). The repository has no stored secrets; GitHub secret scanning and push protection are on. |
| Resource exhaustion | Header, body and connection limits, per-address registration limits, a fair queue with admission control (F1 to F4). |
| Vulnerable or malicious dependencies | Two direct modules, each justified in writing; `go mod verify`, `govulncheck` and Dependabot; base images and actions pinned by digest or commit ([dependencies.md](dependencies.md)). |
| Tampered build or release | Signed image and checksums, SBOM and provenance attestations, protected release tags, a reproducible binary build checked in the release rehearsal ([release-verification.md](release-verification.md)). |
| Server-side request forgery | The relay opens connections only to Apple and to the certificate authority. No caller can name a host. |

## 6. Evidence that the argument stays true

- Every invariant names the tests that fail when it breaks, and `TestInvariantsNameRealTests` fails when a
  named test no longer exists.
- Structural tests fail when the code links envelope cryptography, builds a payload outside the one package
  allowed to, logs through a second logger, or registers a metric that the published table does not list.
- CI runs build, vet, tests with the race detector, golangci-lint (including gosec), govulncheck, every fuzz
  target, the spec vectors and CodeQL on every pull request, and all of them are required for a merge. The
  test job also measures statement coverage and fails below 80 %.

## 7. What is not claimed

- Metadata is visible to the relay and to Apple. Time patterns can reveal behaviour.
- Whoever holds the APNs key can put a plaintext alert on a device whose token they have seen.
- Nobody can prove which code runs on a host they do not control.
- The host of the hosted relay is one machine, run by one person.
- No second person has reviewed the code or the changes to it, and no independent security review has
  taken place. Every check named on this page is automated or done by the maintainer.

The full list is in [threat-model.md](threat-model.md#known-limitations).
