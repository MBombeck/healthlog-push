# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The GitHub release carries SLSA v1.0 provenance for the Linux binaries and `SHA256SUMS`,
  `healthlog-push_vX.Y.Z.intoto.jsonl`, signed by the SLSA generic generator (v2.1.0). It checks with
  `slsa-verifier verify-artifact`. The image signature, its SBOM and its provenance, and what the deployment
  role verifies, do not change.

## [1.0.2] - 2026-11-22

### Security

- `admin recovery --from` read the export from any path the relay process could open; through the admin
  socket that is root on the host anyway, but the reader now accepts only a file inside the export directory
  (`HLP_EXPORT_DIR`), as a relative name or an absolute path under it, through `os.Root`, so `..` and
  symbolic links cannot leave it. Code scanning alert `go/path-injection` is closed by this change, not
  suppressed. The import at start reads `registry.json` from the same directory as before.

### Changed

- Live Activity pushes go to Apple with `apns-priority: 10` only for the end and for a start or update whose
  `status` is `due` or `overdue`; every other state (`pending`, `snoozed`, `taken`, `skipped`) goes with 5.
  iOS grants each device an hourly budget of priority 10 Live Activity pushes and may throttle beyond it,
  and priority 5 does not count against it, so routine changes no longer use up the budget a due dose
  needs. The relay decides from the checked content state; nothing in the API changes.
- A `410` from Apple whose `timestamp` lies before the UTC day the binding was made or renewed (with 10
  minutes of tolerance) no longer deletes the binding. Apple confirmed the old registration gone, and the
  device has registered the token again since. The item answers `200 soft_invalid` with `reason`
  `Unregistered`, the binding is marked, and the same answer on a later day deletes it. A `410` without a
  timestamp, or one at or after the binding day, deletes as before.

### Added

- Delivery traces: for a push to a development build, Apple returns `apns-unique-id`. The relay keeps it
  with the item result in memory for 72 hours (at most 50,000 traces, keyed by instance id and `ref`), and
  `admin delivery <instance-id> <ref>` shows it, so one lost push can be looked up in Apple's delivery log.
  Traces are never stored, exported, logged or counted; production pushes have none. The retention is in
  `docs/privacy.md` (now version 1.1; the consent text version stays `2026-11-21`) and
  `docs/operations.md`.
- A third identity key for the hosted relay, `emergency` (`dcrihMfqGY7srT95DZrVP7sKA-IS3oJPPhOVbbqTvBU`), in `keys/push.healthlog.dev.json` and the
  README. It is kept offline, apart from `current` and `next`, never deployed, and promoted only if both are
  lost; `docs/key-ceremony.md` has the procedure. The relay keeps signing with `current`.
- `docs/transparency.md`: authority requests (none so far), how a request is handled, and a dated feed of
  deprecations and key rotations. Identity key rotations are announced there at least 7 days ahead. Linked
  from the README, the privacy notice and the threat model.
- Tests for the provider token path (`FileTokens`), which had none, for the Live Activity priorities, the
  410 timestamp and the delivery traces.

### Documentation

- The threat model states as an accepted limit that the silent intake sync goes out at once after a dose
  is recorded, so Apple and the relay can see that time: preventing a double dose is chosen over hiding it.
- The privacy notice (1.1), the terms (1.1, terms version unchanged) and the README state the operator's
  commitment: the relay only carries what a registered server sends to its own bound devices, and the
  operator never sends anything through it.
- The README lists the hosted identity keys once; the second, stale table is gone.
- The README no longer repeats what the relay sees; it points to `docs/privacy.md`, the single source.

The test vectors (`spec/vectors/v1.json`) are unchanged.

## [1.0.1] - 2026-11-21

### Security

- A new store no longer starts with open registration. Until the first `admin registration` command, a fresh
  relay accepted registrations from anyone for as long as it took the operator to close it. The relay now
  takes its mode from `HLP_REGISTRATION_MODE` (`invite` when unset, also `closed` or `open`), stores it and
  only then accepts requests. A mode stored with `admin registration` wins over the variable, so a restart
  never reopens what an operator closed. A value other than `open`, `invite` or `closed` stops the relay at
  start.
- AppArmor profiles for both containers in `deploy/apparmor/`: the relay reads only its own secrets, writes only
  `/data`, `/acme`, `/export` and the refresh marker and has no capability; the signer has no network and
  writes only the provider token. They are opt-in through `HLP_APPARMOR_RELAY` and `HLP_APPARMOR_SIGNER`
  (Docker's `docker-default` otherwise); the Ansible role takes `healthlog_push_apparmor_relay` and
  `healthlog_push_apparmor_signer`, installs the profiles of the release with
  `healthlog_push_apparmor_install`, refuses a profile the kernel has not loaded in enforce mode, and checks
  after the start that each container runs under its profile.

### Changed

- The SLSA provenance is now SLSA v1 (`slsaprovenance1`), signed by the reusable workflow
  `.github/workflows/provenance.yml` with GitHub's `attest-build-provenance` and stored as a Sigstore bundle
  next to the signature and the SBOM. cosign 3 verifies all three without format flags. The provenance of
  v1.0.0 came from the SLSA generator in the older `.att` format, which cosign 3 finds only with
  `--new-bundle-format=false`; [docs/release-verification.md](docs/release-verification.md) has the commands for both.
- The Ansible role verifies the provenance with the new identity and type and pins cosign v3.1.4 with the
  SHA-256 of the amd64 and arm64 binaries in its defaults. Releases before v1.0.1 do not pass the new
  provenance step; deploy them with the role of their own tag.
- `HLP_REGISTRATION_MODE` is passed by the compose file (default `invite`) and rendered by the role from
  `healthlog_push_registration_mode`.

### Updating

- A store on which no mode was ever set (the relay answered `open` without having stored it) now starts in
  `invite`. To keep accepting registrations from anyone, run `admin registration open` once.

## [1.0.0] - 2026-11-21

First release.

### Added

- One binary with the subcommands `relay`, `signer`, `admin`, `keygen`, `healthcheck` and `version`.
- Relay API: instance registration with proof of possession, key rotation and deletion
  (`/v1/instances`), device bindings with a device-signed statement (`/v1/bindings`), conflict resolution
  by a challenge push (`/v1/bindings/challenge`), the direct opt-out and self-read for the app
  (`/v1/bindings/self`), the Live Activity consent (`/v1/bindings/liveactivity`) and its direct withdrawal
  (`/v1/bindings/self/liveactivity`), batched pushes of up to 50 items (`/v1/push`), envelope receipt counts
  (`/v1/receipts`) and the instance status (`/v1/status`).
- Ed25519 request signatures with a 300-second window, nonce replay protection and refusal of time stamps
  from before the relay started; every `/v1` response, `/healthz` and `/version` signed with the relay
  identity key (`hl-relay-resp-v2`) and bound to the request method, path and nonce.
- Fixed APNs payload templates for alert, silent and Live Activity start, update and end; envelopes are checked for version,
  suite, class and exact length and never opened. Envelopes exist for alert and silent only; the Live
  Activity class byte `0x03` is reserved and the vectors carry no envelope of that class.
- Direct opt-out with a device-only return: the pair stays blocked against the instance, and only a later
  bind statement by the same binding key with a higher `seq`, signed after the opt-out and after the relay
  start, lifts the block. The binding key that opted out is pinned to the token for 365 days (bucket
  `optout_pins`): while the token is unbound, a binding with any other key, also by a newly registered
  instance, is `409 binding_conflict` with a challenge push that only the device can answer.
- Live Activity start and update over the relay (`activity.event` `start`, `update` or `end`, `end` when
  absent), only with the device's second, separate Live Activity consent: signed by the binding key
  (`hl-la-consent-v1`), passed on by the instance with `POST /v1/bindings/liveactivity`, dropped by it with
  `DELETE /v1/bindings/liveactivity`, withdrawn by the device directly with
  `DELETE /v1/bindings/self/liveactivity` (`hl-la-withdraw-v1`). The consent version and day are stored with
  the binding, returned by the self-read (`liveActivityConsentVersion`, `liveActivityConsentDay`) and kept on
  a rebind by the same key to the same instance. Without it a start or update answers
  `403 liveactivity_consent_required`.
- A closed content state for start and update, forwarded in the clear: `status` (`pending`, `due`,
  `overdue`, `snoozed`, `taken`, `skipped`), `countdownTarget` (`0` or one day back to two days ahead of the
  relay clock), `isOverdue`, `confirmed`, `pendingConfirm` and `timeFormatRaw` (`AUTO`, `H12`, `H24`), all
  required and nothing else; a start names the fixed attributes type `HealthLogDoseAttributes` with
  `{"v":1}` and a fixed localized alert. A start is signed over the push-to-start token (`hl-la-start-v1`, at
  most 30 days old); an update or end over the update token (`hl-activity-v1`, at most 12 hours old).
- Live Activity limits: 12 starts per device and day, 12 updates per activity and hour and 48 per day
  (`429 device_quota`, scope `activity`), 12 ends per device and day. Metrics
  `hlp_bindings_total{result="liveactivity_consent"}` and `{result="liveactivity_consent_withdrawn"}`.
- Fixed shapes, with vectors, for the `DATA_CHANGED`, `HEALTHKIT_CATCH_UP` and `SECURITY_ALERT` plaintexts
  (`spec/envelope.md`, "Types with a fixed shape").
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
  a consistency check at start and daily, a daily registry export (`healthlog-push-registry-v2`: instances
  with tier and reason, opt-out blocks, opt-out pins and token blocks) signed with the relay identity key
  (`hl-relay-export-v1`), automatic recovery from a damaged or missing database with a 14-day recovery
  window, and MAC key rotation with a previous key.
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
- Privacy notice and terms served at `/privacy` and `/terms`, and `/.well-known/security.txt` (RFC 9116).
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
  caps still apply. Only instances from the export keep their tier; any other key registers in probation.
- The challenge answer checks that the instance is still active and applies its binding quotas; a binding
  made through a challenge counts against `newBindingsPerDay`. Challenges are limited to one per token,
  instance and day, so one instance cannot use up the challenge of another.
- The seven-day direct replacement of a silent binding with a new key is allowed only to the instance that
  holds the binding; every other instance needs the challenge.
- The registry export is signed and checked on import: signature, host, and every instance inside the
  closed sets (UUIDv4 id, 32-byte key, known tier and reason, device limit 1 to 150). Anything else fails the
  whole import, and the relay does not start. An unsigned export is never written.
- Suspension and revocation live in the instance record (tier, reason, reason day) and expire after 365 days;
  there is no separate denylist. A revoked instance cannot be suspended, and a revocation is one
  transaction.
- The stored opt-out block holds the day, the key hash and `seq` only, as JSON; the opt-out time is kept in
  memory for 10 minutes and never stored. Reads of blocks and pins fail closed.
- Non-canonical request paths get a signed `404 not_found` instead of a redirect, and `/v1` itself needs a
  nonce.
- The app endpoints check the signature first for every request, so the response time does not reveal
  whether a binding exists.
- Strict JSON also refuses keys that match a field only when case is ignored, and duplicate keys.
- Connections are limited to 2,000 in total, 8 per IPv4 address or IPv6 /64 and 64 per IPv6 /48.
- `DELETE /v1/instances/self` refuses a non-empty body with `422 invalid_item`. No response body exceeds
  65,536 bytes.
- A rotation that races a deletion can no longer bring a deleted instance back.
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
- CI runs yamllint, a playbook syntax check and ansible-lint on the deploy code, with the linters installed
  hash-pinned from `.github/deploy-lint-requirements.txt`; `.gitleaks.toml` allowlists the synthetic key
  material in `spec/vectors` and `spec/tools`. The fuzz corpus is committed.
- The send queue always admits when it is empty, and the APNs warm-up ends after the first attempt whatever
  its outcome, so the push path recovers after an Apple outage.
- A provider-token rejection is forgotten once a newer token is accepted; only a rejection of the next
  renewed token stops the relay.
- An instance flag (challenge started, invalid-token budget exceeded) is stored as a day and blocks promotion
  on that day and the next, also across a restart. The suspicious-instance window is seven days, as in
  `suspects`.
- Daily retention deletes stale bindings in one transaction, and a metrics scrape writes nothing.
- After the batch deadline a result that is already there is reported as it is.
- Configuration: Apple's endpoints are constants (no `HLP_APNS_URL` or `HLP_APNS_SANDBOX_URL`);
  `HLP_APNS_TOPIC` is required; `HLP_PUBLIC_HOST` must be a lower-case DNS name without port and
  `HLP_APNS_ENVIRONMENT` only `production` or `sandbox`, both checked at start; the compose file passes
  `HLP_MIN_CLIENT_VERSION`; the admin socket default follows `HLP_DATA_DIR` for server and client; a failing
  listener makes the process exit with an error.

[1.0.2]: https://github.com/MBombeck/healthlog-push/releases/tag/v1.0.2
[1.0.1]: https://github.com/MBombeck/healthlog-push/releases/tag/v1.0.1
[1.0.0]: https://github.com/MBombeck/healthlog-push/releases/tag/v1.0.0
