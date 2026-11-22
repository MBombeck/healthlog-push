# healthlog-push

[![CI](https://github.com/MBombeck/healthlog-push/actions/workflows/ci.yml/badge.svg)](https://github.com/MBombeck/healthlog-push/actions/workflows/ci.yml)
[![CodeQL](https://github.com/MBombeck/healthlog-push/actions/workflows/codeql.yml/badge.svg)](https://github.com/MBombeck/healthlog-push/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/MBombeck/healthlog-push/badge)](https://scorecard.dev/viewer/?uri=github.com/MBombeck/healthlog-push)
[![Go Report Card](https://goreportcard.com/badge/github.com/MBombeck/healthlog-push)](https://goreportcard.com/report/github.com/MBombeck/healthlog-push)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The push relay of the HealthLog project. Self-hosted HealthLog servers use it to send notifications to the
HealthLog iOS app from the App Store. The relay holds the Apple Push Notification service (APNs) key for the
app, so a self-hoster does not need an Apple developer account. Notification content is end-to-end
encrypted on the HealthLog server for each device; the relay forwards an opaque envelope and cannot open it.

The hosted relay runs at `https://push.healthlog.dev`. It is meant for households: one person or a family
running their own HealthLog server. It is not a medical service. Local reminders on the device stay the
authoritative reminder path; the relay only adds convenience.

One Go binary, two processes: `relay` serves the API and talks to Apple, `signer` holds the APNs key without
any network access and hands the relay a short-lived provider token through a shared tmpfs.

## What the relay sees and what it never sees

The relay forwards sealed envelopes it cannot open and keeps only the metadata needed to address devices and
enforce limits, never medication names, doses, readings, notes, account data or any plaintext; the full list,
with every retention period, is the privacy notice in [docs/privacy.md](docs/privacy.md), the single source
(also served at `/privacy`). The relay only carries what a registered server sends to its own bound
devices. The operator never sends anything through it: no announcements, no update notices, no messages of
any kind.

## Architecture

```mermaid
flowchart LR
  subgraph home["Self-hosted HealthLog server"]
    I["instance: encrypts one envelope per device, signs every request"]
  end
  subgraph host["Relay host"]
    R["relay: public TLS 1.3 on 443 (redirected to 8443), bbolt store"]
    S["signer: no network, holds the APNs .p8 key"]
    S -- "provider JWT via tmpfs" --> R
    R -- "empty refresh marker via tmpfs" --> S
  end
  D["iPhone: HealthLog app and notification service extension"]
  A["Apple Push Notification service"]
  D -- "device key, binding statement, consent" --> I
  I -- "register, bind, push, receipts (signed)" --> R
  R -- "signed responses" --> I
  R -- "HTTP/2, fixed payload templates" --> A
  A --> D
  D -- "direct: opt-out, self-read, Live Activity withdrawal, challenge answer" --> R
```

- Every request from an instance is signed with its Ed25519 key; every `/v1` response is signed with the
  relay identity key, which instances and the app pin. The response signature covers method, path, the
  request's mandatory nonce, status and body, so an answer cannot be replayed onto another request.
- A device binding needs a statement signed by a key that only the app holds. A server that merely knows a
  device token cannot bind it.
- The app can leave an instance directly (`DELETE /v1/bindings/self`) without the instance's cooperation.
  The pair is then blocked for 12 months; only the same device can lift the block, with a newly signed
  binding statement. The binding key is pinned to the token for the same time, so another instance, even
  one the same operator registers with a made-up key, cannot bind the token without a challenge that only
  the device can answer.
- The relay builds every APNs payload from constants. An instance chooses the class, the opaque envelope,
  the lifetime and a collapse id, never visible text, a category or `userInfo` keys.

## Threat model in short

The relay cannot read content. It does see metadata, and time patterns can reveal health behaviour (for
example when a dose was recorded on another device). Whoever holds the APNs key (the operator, or someone who
compromises the signer or the host) can put a plaintext alert with arbitrary text on a device whose token
they have seen. They cannot read any data, and the HealthLog app is built to take no action on a
notification it could not decrypt and verify. A compromised relay process can forge relay responses; of the
APNs credentials it only ever holds a provider token valid for at most one hour. DNS or TLS takeover turns into an outage rather than a
takeover, because responses are signed. Nobody can prove which code runs on a server they do not control.
The full analysis, including the known limitations, is in [docs/threat-model.md](docs/threat-model.md). How
the host of the hosted relay is hardened is in [docs/hardening.md](docs/hardening.md).

## Self-hosting quick guide

A self-hosted relay only works with an app you build yourself under your own Apple developer account. It
cannot serve the App Store app. Read [docs/self-hosting.md](docs/self-hosting.md) first; this is the short
version. Host provisioning with Ansible is described in [deploy/ansible/README.md](deploy/ansible/README.md).

1. Pick a released image by digest and verify it (see [Verifying releases](#verifying-releases)):

   ```sh
   IMAGE=ghcr.io/mbombeck/healthlog-push@sha256:<digest>
   ```

2. Generate the keys:

   ```sh
   docker run --rm "$IMAGE" keygen relay-id      # JSON: relay_id_key (secret) and publicKey (pin this)
   docker run --rm "$IMAGE" keygen token-mac     # base64url, 32 bytes
   docker run --rm "$IMAGE" keygen acme-account  # PEM, EC P-256
   ```

   Keep all three in your secret store. The file `relay_id_key` holds only the value of the
   `relay_id_key` field, not the whole JSON line.

3. Lay out the secrets and state directories:

   ```
   /srv/healthlog-push/secrets/relay/relay_id_key            owner 65532, mode 0400
   /srv/healthlog-push/secrets/relay/token_mac_key           owner 65532, mode 0400
   /srv/healthlog-push/secrets/relay/token_mac_key_previous  optional, only during a rotation
   /srv/healthlog-push/secrets/relay/acme_account_key        owner 65532, mode 0400
   /srv/healthlog-push/secrets/signer/apns.p8                owner 65533, mode 0400
   /srv/healthlog-push/data                                  65532:65530, 0700 (database, admin socket)
   /srv/healthlog-push/export                                65532:65530, 0750 (daily registry.json)
   /srv/healthlog-push/acme                                  65532:65530, 0700 (certificate cache)
   ```

4. Copy `deploy/compose/compose.yaml` and `deploy/compose/.env.example` (as `.env`) to
   `/srv/healthlog-push/compose/`, fill in `HLP_IMAGE`, `HLP_IMAGE_DIGEST`, `HLP_PUBLIC_HOST`,
   `HLP_APNS_TOPIC`, `HLP_APNS_KEY_ID` and `HLP_APNS_TEAM_ID`, then:

   ```sh
   cd /srv/healthlog-push/compose && docker compose up -d
   docker compose exec relay /healthlog-push healthcheck && echo healthy
   ```

5. The relay listens on 8443 with host networking and no capabilities. Redirect 443 to it, for IPv4 and
   IPv6, and accept 8443 only for redirected connections:

   ```
   table inet hlp {
     chain prerouting { type nat hook prerouting priority dstnat; policy accept;
       tcp dport 443 redirect to :8443 }
     chain input { type filter hook input priority filter; policy drop;
       iif "lo" accept
       ct state established,related accept
       tcp dport 8443 ct status dnat accept
       # plus ICMP, ICMPv6 and your management access
     }
   }
   ```

   The certificate comes from Let's Encrypt over TLS-ALPN-01 on port 443 once DNS points at the host.
   The complete rule set is `deploy/ansible/roles/firewall/templates/nftables.conf.j2`.

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
budget do not; see the known limitations in [docs/threat-model.md](docs/threat-model.md#known-limitations).

## Verifying releases

Releases are built by `.github/workflows/release.yml` from a `vX.Y.Z` tag. The image is signed keyless
with cosign, carries an SPDX SBOM attestation and SLSA provenance, all in the Sigstore bundle format that
cosign 3 reads without extra flags. Verify before you run it (v1.0.0 differs, see
[docs/release-verification.md](docs/release-verification.md#v100)):

```sh
IMAGE=ghcr.io/mbombeck/healthlog-push@sha256:<digest>
TAG=vX.Y.Z

cosign verify "$IMAGE" \
  --certificate-identity "https://github.com/MBombeck/healthlog-push/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

cosign verify-attestation "$IMAGE" --type slsaprovenance1 \
  --certificate-identity "https://github.com/MBombeck/healthlog-push/.github/workflows/provenance.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository MBombeck/healthlog-push > /dev/null

cosign verify-attestation "$IMAGE" --type spdxjson \
  --certificate-identity "https://github.com/MBombeck/healthlog-push/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com > /dev/null
```

The GitHub release also carries static Linux binaries for amd64 and arm64 with a signed checksum file:

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/MBombeck/healthlog-push/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing
```

The hosted relay reports its version, commit and image digest at `https://push.healthlog.dev/version`.
That answer comes from the server being checked, so it is a statement, not proof.

[docs/release-verification.md](docs/release-verification.md) walks through checking a release end to end.
The pipeline can be rehearsed locally, with a throwaway registry and key, with `scripts/release-dry-run.sh`.

### Hosted relay identity keys

The public identity keys of the hosted relay `push.healthlog.dev`, `current` and `next`, were published with
the first release (v1.0.0): in its release notes and as `keys/push.healthlog.dev.json` in the tagged tree, in the
form `{"host": "push.healthlog.dev", "current": "<base64url 32>", "next": "<base64url 32>"}` (unpadded
base64url Ed25519 public keys); v1.0.2 added `"emergency"` beside them. Clients pin them at build time. The HealthLog server ships them as its hosted
relay pins, the iOS app as its `HLPushRelayKeys` build setting. Neither fetches them from the relay at
run time, because an answer from the relay cannot vouch for the key that signs it. A new `next` key is
published in the release notes of the release that ships it, before the relay switches to it (see
[docs/operations.md](docs/operations.md), "Relay identity key", and [docs/key-ceremony.md](docs/key-ceremony.md)
for how the keys are made and kept).

| Key | Ed25519 public key (base64url) |
|---|---|
| `current` | `IU8JGZzcE-O4gp4q2BL2o6YYNJeHyDg8MNmAGL5_Ypo` |
| `next` | `kPhnCqIwrF_cyQIFTAgCHrWnPavdWkcwMB35oi_wCH0` |
| `emergency` | `dcrihMfqGY7srT95DZrVP7sKA-IS3oJPPhOVbbqTvBU` |

`emergency` is a third key, generated and kept offline, apart from `current` and `next`, and never deployed
to the relay host. It is pinned like the others and is used only if both `current` and `next` are lost
([docs/key-ceremony.md](docs/key-ceremony.md#lost-current-and-next)).

The same values are in [`keys/push.healthlog.dev.json`](keys/push.healthlog.dev.json). Key rotations are
announced in [docs/transparency.md](docs/transparency.md) at least 7 days before the relay signs with the
new key.

## Project layout

```
cmd/healthlog-push/    entry point: relay, signer, admin, keygen, healthcheck, version
internal/relay/        HTTP API, bindings, push path, limits, breaker, maintenance, admin socket
internal/wire/         every parser and every signed text of the protocol (fuzzed)
internal/apns/         APNs client and the fixed payload templates
internal/signer/       the network-less signer that writes provider JWTs
internal/store/        bbolt persistence, retention, registry export
internal/limits/       token buckets, windows, registration and connection limiters
internal/queue/        fair, bounded in-memory send queue
internal/logx/         the only logger: JSON lines with a closed set of keys
internal/metrics/      coarse Prometheus counters without instance labels
internal/notice/       the texts served at /privacy, /terms, /.well-known/security.txt and /
internal/admin/        operator command line over the admin socket
spec/                  protocol specification, test vectors and their tools
deploy/compose/        compose file for relay and signer
deploy/ansible/        host provisioning and verified deployment
docs/                  operations, privacy, terms, threat model, self-hosting, API, dependencies, migration
structure_test.go      structural rules about the code base itself
```

## Development

You need the Go version named in `go.mod` and Node 22 for the vector check.

```sh
go build ./...
go vet ./...
go test -race ./...
golangci-lint run                                        # v2, config in .golangci.yml
go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...
node spec/tools/check-vectors.mjs
scripts/check-text.sh
docker build -t healthlog-push:dev .
```

Fuzz targets run for 20 seconds each in CI; see [CONTRIBUTING.md](CONTRIBUTING.md) for running one
locally. Dependencies and the policy for adding one: [docs/dependencies.md](docs/dependencies.md).

## Documentation

- [docs/operations.md](docs/operations.md): deploy, rollback, admin commands, key rotation, alerts, runbooks
- [docs/self-hosting.md](docs/self-hosting.md): running your own relay for your own app build
- [docs/api.md](docs/api.md): API reference with examples; the contract is `spec/protocol.md` and `spec/relay-api.yaml`
- [docs/threat-model.md](docs/threat-model.md): assets, actors, limitations
- [SECURITY-INVARIANTS.md](SECURITY-INVARIANTS.md): every security invariant and the tests that fail when it breaks
- [docs/key-ceremony.md](docs/key-ceremony.md): how the relay identity, MAC and APNs keys are made, kept and rotated
- [docs/transparency.md](docs/transparency.md): authority requests (none so far), how they are handled, and the feed of deprecations and key rotations
- [docs/release-verification.md](docs/release-verification.md): verifying a release and rehearsing one locally
- [docs/hardening.md](docs/hardening.md): how the hosted relay's host is hardened
- [docs/privacy.md](docs/privacy.md) and [docs/terms.md](docs/terms.md): the texts of the hosted relay
- [docs/migration.md](docs/migration.md): moving the relay to a new host
- [docs/dependencies.md](docs/dependencies.md): every module and why it is there

Security reports: [SECURITY.md](SECURITY.md). Contact: relay@healthlog.dev (operation),
abuse@healthlog.dev (abuse, suspension appeals), privacy@healthlog.dev (data protection).

## License

The code is licensed under the [Apache License 2.0](LICENSE). Everything under `spec/`, the specification,
the test vectors in `spec/vectors/` and their tools, is dedicated to the public domain under CC0 1.0
([spec/LICENSE](spec/LICENSE)), so that other implementations can copy it without conditions. The HealthLog server
and apps are separate projects under their own licenses.
