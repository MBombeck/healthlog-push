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
  identity key and bound to the request nonce.
- Fixed APNs payload templates for alert, silent and Live Activity end; envelopes are checked for version,
  suite, class and exact length and never opened.
- Signer process without network access that holds the APNs key and writes an ES256 provider token to a
  shared tmpfs every 30 minutes, or on request at most every 20 minutes.
- Per-instance, per-device, per-tier and relay-wide limits, registration limits by IPv4 address and IPv6
  /64 and /48 (salted daily, in memory), a connection limiter, a fair in-memory send queue with admission
  control and idempotency by `(instance, ref)` for 10 minutes.
- Token-failure circuit breaker: when more than 30 % of at least 20 device sends in five minutes fail with a
  token error, no binding is deleted or marked until Apple accepts again.
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
  `export`, `breaker` and `status-file`.
- Usage statistics as counts only (completed days and weeks) in `admin stats` and as `hlp_usage_*` metrics.
- `/healthz` with `status`, `db_writable`, `apns_recent`, `breaker` and `delivery`, the last derived from the
  receipt counts instances report.
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

[1.0.0]: https://github.com/MBombeck/healthlog-push/releases/tag/v1.0.0
