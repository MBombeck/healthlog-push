# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-21

First release.

### Added

- One binary with the subcommands `relay`, `signer`, `admin`, `keygen`, `healthcheck` and `version`.
- Relay API: instance registration with proof of possession, key rotation and deletion
  (`/v1/instances`), device bindings with a device-signed statement (`/v1/bindings`), conflict resolution
  by a challenge push (`/v1/bindings/challenge`), the direct opt-out and self-read for the app
  (`/v1/bindings/self`), batched pushes of up to 50 items (`/v1/push`), envelope receipt counts
  (`/v1/receipts`) and the instance status (`/v1/status`).
- Ed25519 request signatures with a 300-second window, nonce replay protection and refusal of time stamps
  from before the relay started; every `/v1` response, `/healthz` and `/version` signed with the relay
  identity key (`hl-relay-resp-v2`) and bound to the request method, path and nonce.
- Fixed APNs payload templates for alert, silent and Live Activity end; envelopes are checked for version,
  suite, class and exact length and never opened.
- Signer process without network access that holds the APNs key and writes an ES256 provider token to a
  shared tmpfs every 30 minutes, or on request at most every 20 minutes.
- Per-instance, per-device, per-tier and relay-wide limits, registration limits by IPv4 address and IPv6
  /64 and /48 (salted daily, in memory), a connection limiter, a fair in-memory send queue with admission
  control and idempotency by `(instance, ref)` for 10 minutes.
- Token-failure circuit breaker: when more than 30 % of at least 20 sends to established bindings in five
  minutes fail with a token error, from at least three instances, no binding is deleted or marked until
  Apple accepts again.
- Only `Unregistered` from Apple deletes a binding; `BadDeviceToken` and `DeviceTokenNotForTopic` mark it
  soft-invalid and delete it on a second hit on another day.
- Handling of Apple's provider token errors and throttling: refresh on an expired token, a 20-minute pause
  on too many token updates, a full stop on a rejected renewed token, per-device back-off on
  `TooManyRequests`, and a relay-wide 15-minute silent pause when Apple throttles more than 2 % of sends.
- bbolt storage with day and week granularity only, token MACs instead of tokens, retention and pruning,
  a consistency check at start and daily, a daily registry export of instances and the denylist, automatic
  recovery from a damaged or missing database with a 14-day recovery window, and MAC key rotation with a
  previous key.
- Probation tier with automatic promotion after seven days, a delivered push and no anomaly; automatic
  device limit raise for quiet, well-used standard instances.
- Operator commands over a unix socket: `stats`, `instance`, `pause`, `resume`, `registration`, `invite`,
  `notice`, `suspend`, `unsuspend`, `revoke`, `block-token`, `unblock-token`, `limits`, `recovery`,
  `export`, `breaker`, `status-file` and `suspects`.
- Usage statistics as counts only (completed days and weeks) in `admin stats` and as `hlp_usage_*` metrics.
- `/healthz` with `status`, `db_writable`, `apns_recent`, `breaker` and `delivery`, the last derived from the
  receipt counts instances report. `status` depends only on the relay's own facts.
- JSON logging with a closed set of keys and no instance ids, tokens or addresses; HTTP server error lines
  counted and discarded. Metrics without instance labels on `127.0.0.1:9464`, refreshed hourly while fewer
  than 20 instances are active.
- TLS 1.3 with certificates from Let's Encrypt over TLS-ALPN-01, or certificate files.
- Privacy notice and terms served at `/privacy` and `/terms`.
- Compose file with two hardened containers and an Ansible deployment that verifies the cosign signature and
  SLSA provenance before starting a digest-pinned image, gates on health and rolls back.
- Release workflow with multi-arch images, keyless signatures, SBOM attestation, SLSA provenance and signed
  checksums for static binaries.
- Protocol specification and test vectors under `spec/`, fuzz targets for every parser, structural tests
  for logging, address handling, cryptography imports, payload templates and deletion paths.

### Security

- Response signatures (`hl-relay-resp-v2`) cover host, method, raw path with query, nonce, status and body
  hash. `HL-Nonce` is mandatory on every `/v1` request, registration and the app's direct calls included;
  without it the relay answers `400 nonce_required`. Clients take retry hints only from the signed body,
  capped at one day, and refuse response bodies over 256 KiB; the relay never sends more than 64 KiB.
- Instance requests are checked for a known instance and a valid time stamp from the headers before the
  body is read. The signature is always verified; the per-instance budget for failed signatures only limits
  how often failures are counted, so forged requests can no longer lock an instance out.
- `POST` and `DELETE` must declare `Content-Length` (`411 length_required`); bodies above 128 KiB are
  refused before reading, bodies in flight are capped at 32 MiB in total (`503 overloaded`), HTTP/2
  connections allow 16 concurrent streams, and the relay container runs with `GOMEMLIMIT=220MiB`.
- The app endpoints verify first and charge only failed attempts to the global bucket; verified calls are
  limited per device token (10, refilling 10 per hour, `429 device_quota`). Junk traffic can no longer block
  a device's opt-out.
- The breaker counts only sends to bindings that have had an accepted push and opens only with failures from
  at least three instances. A soft-invalid binding gets one probe push per day. Over its invalid-token budget
  an instance gets no pushes to provisional or soft-invalid bindings for 24 hours.
- Receipts count only for `standard` instances, at most once per 45 minutes each, with `accepted` capped at
  what the relay accepted for that instance in the last three days.
- TLS 1.2 is offered only to a handshake whose only ALPN protocol is `acme-tls/1`.
- During a recovery window the global registration caps are ten times higher instead of lifted; per-address
  caps still apply.
- The challenge answer checks that the instance is still active and applies its binding quotas.
- Release workflow: no QEMU step, BuildKit pinned by digest, no `# syntax` line in the Dockerfile, the SBOM
  generated in a job without `id-token` and attested in a separate job, and the tag must point to a commit
  on `main`.
- Ansible: a secrets fingerprint (`HLP_SECRETS_REV`) in `.env` and the compose environment recreates the
  containers whenever a secret changed, also after an earlier failed run; the cloud metadata endpoint is
  reachable only for uid 0; the SSH restart handler no longer ignores failures; the shared tmpfs volumes are
  mounted `noexec`, `nosuid`, `nodev`.

### Changed

- `/healthz` `status`, its HTTP code, the container health check and the deploy gate depend only on the
  relay's own facts (provider token, writable store); `breaker` and `delivery` are display only.
- The database is moved aside only on proven damage, as `relay.db.damaged-YYYYMMDDTHHMMSSZ`, never over an
  earlier copy; any other error opening it stops the relay.
- The minute flush writes all changed bindings, changed instance records and the counters in one write
  transaction.
- Registrations, key rotations, instance deletions and resolved challenges no longer get a log line of their
  own; they are counted in the `events` map of the periodic `relay.summary` line.
- New admin command `suspects`: instances with invalid tokens, rebinds or challenges in the last seven days,
  worst first.
- An invite code is spent only when the registration passes every limit. A challenge push that cannot be
  queued gives the quota back and answers `409 binding_conflict` with reason `challenge_unsent`.
- The documented week start is Monday, matching the code.
- CI runs yamllint, a playbook syntax check and ansible-lint on the deploy code; `.gitleaks.toml` allowlists
  the synthetic key material in `spec/vectors` and `spec/tools`.

[1.0.0]: https://github.com/MBombeck/healthlog-push/releases/tag/v1.0.0
