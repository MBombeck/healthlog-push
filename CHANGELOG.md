# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.11] - 2026-11-26

v1.0.10 was never published; its fix is part of this release.

### Fixed

- Device and activity tokens of up to 512 hex characters are accepted. The cap was 200, and an iPhone
  that hands out a 256 character push-to-start token had its Live Activity start refused. Apple documents
  no fixed token length; the limit stays even-length hex with a lower bound of 64 characters.

### Changed

- The wallet process signs: the HealthLog brand images (asset set v2) are pinned in
  `internal/wallet/pinned.go` and `spec/wallet-manifest-v1.json`. Until now the pin set was empty and the
  wallet process refused to start.
- The Ansible role can switch Wallet on: `healthlog_push_wallet_enabled` with the Pass Type ID, the team id
  and the pass key and certificate as PEM writes `secrets/wallet`, sets the compose profile and
  `HLP_WALLET_DIR`, loads the `healthlog-push-wallet` AppArmor profile and waits for the wallet socket to
  answer. Off by default; turning it off removes the container and the secrets.

## [1.0.9] - 2026-11-25

### Added

- Blind signing of Apple Wallet passes for registered HealthLog servers (`spec/wallet.md`), off until a
  Pass Type ID certificate is configured. `POST /v1/wallet/apple/sign` takes only `manifest.json`, the
  list of file hashes, checks it against a closed file set with the HealthLog brand images pinned by hash,
  and answers a detached CMS SignedData; `POST /v1/wallet/apple/notify` sends pass update pushes. `GET
  /v1/status` carries a `wallet` block. Limits per server, relay-wide and per pass push token; a ledger of
  manifest hash, server and day for 400 days, readable only with `admin wallet lookup`; `admin wallet
  block` and `unblock`; metrics `hlp_wallet_requests_total` and `hlp_wallet_cert_days_left`.
- A third process, `healthlog-push wallet`: holds the pass key, has no network, checks the manifest and the
  pins again itself, signs, and reaches Apple only through a byte tunnel of the relay that dials
  `api.push.apple.com:443` and nothing else, with TLS from the wallet process to Apple. Compose service
  `wallet` behind the profile `wallet`, AppArmor profile `healthlog-push-wallet`, health check
  `healthcheck --wallet`, `keygen wallet-csr`. Apple's WWDR G4 intermediate is embedded and pinned by
  SHA-256; no new module.
- Test vectors `spec/vectors/wallet-v1.json` (manifest answers and byte-identical signatures from keys
  derived from public seeds) with a reference implementation on `node:crypto`, checked in CI against Go and
  `openssl smime -verify`. Privacy notice 1.4 describes what Wallet signing sees and keeps.

- `deploy/compose/compose.journald.yaml` and the role variable `healthlog_push_log_driver` (`json-file` or
  `journald`, default `json-file`): the containers can log to the host's systemd journal instead of Docker's
  json-file driver. The override replaces the whole logging block, because the journald driver refuses the
  json-file size options; the role names it through `COMPOSE_FILE` in `.env`. `docs/self-hosting.md` has a
  section "Logs".

### Changed

- A Live Activity start carries the item's `ref` as the start id: the attributes are
  `{"v":1,"s":"<ref>"}` instead of `{"v":1}`. HealthLog chooses the ref as a random id per start, and the
  app reads it back to tell which start an activity belongs to, so more than one dose can run as a Live
  Activity on a device. The relay copies a value it already validates (1 to 40 characters of
  `A-Z a-z 0-9 . _ : -`, written only when it is 1 to 64 printable ASCII characters) and reads nothing into
  it; no wire field is added. App builds that decode only `v` ignore `s`. `spec/protocol.md`, `docs/api.md`,
  the threat model, invariant B8 and privacy notice 1.4 say so.
- Every counter and label value the alert table of `docs/operations.md` watches exists from the first
  scrape at zero: `hlp_connections_rejected_total`, `hlp_auth_failures_total`,
  `hlp_invalid_budget_exceeded_total`, `hlp_body_budget_refused_total`, `hlp_queue_dropped_total`,
  `hlp_silent_paused_total`, `hlp_challenges_total`, `hlp_requests_total` by status class,
  `hlp_registrations_total`, `hlp_bindings_total`, `hlp_http_errors_total` and the watched results of
  `hlp_push_total`. Until now they appeared only with their first event, which `increase()` cannot see, so an
  alert missed exactly the first flood or the first dropped job. A test fails when a row of the table names a
  series a fresh relay does not have.
- The twelve log lines that call for action (`export.failed`, `relay.watchdog`, `relay.listener_failed`,
  `relay.wallet_tunnel_failed`, `store.damaged_moved_aside`, `store.write_failed`, `store.check_failed`,
  `signer.write_failed`, `apns.provider_token_rejected`, `breaker.opened`, `apns.throttled`,
  `wallet.unreachable`) carry `"level":"alert"` and go to standard error; every other line stays on standard
  output without a level. A pipeline can alert on that key, and the journald driver gives these lines the
  priority `err`. A test fails when the code writes an alert the table of `docs/operations.md` does not list,
  or when the table names a log line the code does not write.
- The relay keeps an idle client connection for 120 seconds instead of 60, so a HealthLog server that keeps
  its own connection for a little less can reuse it between pushes. `spec/protocol.md` says so, and a test
  holds the two together.
- Privacy notice 1.4 says that the hosted relay keeps its log lines in the host's journal for at most 14
  days and in the operator's monitoring for 30 days.
- Every response carries `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`, not only the HTML
  notices. A JSON reply has nothing to frame or to refer from; the headers state that for scanners and
  for any client that renders a reply.
- Privacy notice 1.4 also describes the public day totals at `/stats`, which the hosted relay serves
  since v1.0.8. `docs/transparency.md` and `docs/api.md` said it did not serve them yet; the feed has a
  correction and the missing entries for v1.0.5 to v1.0.8.
- A test fails while a release in this changelog has no entry in the feed of `docs/transparency.md`, or
  while an entry does not say whether the release rotates a key and whether it deprecates anything. The
  feed states a minimum notice of 30 days for a deprecation.
- `docs/hardening.md` explains why SSL Labs grades the relay A and not A+ (TLS 1.3 only), and
  `docs/key-ceremony.md` says that the yearly drill has not been rehearsed yet and when it is planned.

## [1.0.8] - 2026-11-24

### Fixed

- The release job that compares the image with the release binaries pulled the image index once per
  platform; the second pull fails with `cannot overwrite digest`, so the v1.0.7 run stopped before the
  GitHub release. `scripts/compare-image-binaries.sh` now resolves each platform manifest from the index and
  pulls it by its own digest; the release workflow runs it. Both v1.0.7 image binaries match the release
  binaries of that run.
- Grype scanned only the runner's platform of the multi-platform image, in the release workflow and in the
  weekly scan of the latest release. Both now scan linux/amd64 and linux/arm64.
- v1.0.7 was never deployed: its release run was incomplete (signed image, but no GitHub release and no
  signed `SHA256SUMS`). Its tag stays as it is; 1.0.8 is the release of the same changes.

## [1.0.7] - 2026-11-24

### Added

- `docs/verify.md` and `scripts/verify-release.sh`: one command checks a release from public sources. It
  reads `/version`, verifies the signed `SHA256SUMS`, rebuilds both binaries from the tag, verifies the
  image signature and provenance, and compares the binary inside each platform image with the release.
- `/version` also reports `binarySha256`, the SHA-256 of the running executable that the relay hashes at
  start, `platform` and `goVersion`, so the answer can be matched to a line of the release's `SHA256SUMS`.
  No field describes the host, the configuration or anyone using the relay.
- Metric `hlp_apns_connections_total{connection="new"|"reused"}`: every request to Apple, by whether it
  opened a new connection or reused one. The share of `reused` shows whether slow deliveries come from new
  connections to Apple. `docs/transparency.md` lists it and has a short table of queries for the figures
  that matter.
- `GET /stats`, public day aggregates (items to Apple, delivered, failed, token gone and throttled
  shares, latency percentiles, uptime) over the last 7 and 30 completed days. Off unless
  `HLP_PUBLIC_STATS=true`. No figure is shown while fewer than three servers are registered, and no window
  unless three or more had a push accepted on a completed day in it; no instance, tier, count or time of
  day appears, and the answer is cached for 15 minutes. `docs/api.md` has the rules. The Ansible role sets it from
  `healthlog_push_public_stats` (default `false`).
- The README is shorter and says what matters first: a diagram of the path of a push (light and dark
  variants in `docs/images/`), what the relay can and cannot see, how the relay is restricted to the
  HealthLog app, the measured figures on speed with their sources, the one-command verification, and how
  to use the hosted relay or run your own.
- Benchmarks of the push path (envelope frame check, batch parse and validation, request signature,
  binding statement, queue, the send to Apple, and a whole push through the handler) and a load test in
  the test binary (`-tags load`), with the method and the figures of a run in `docs/performance.md`. CI
  runs both as a smoke test.

### Fixed

- The binary in the image was not the release binary of the same tag (for v1.0.6, linux/amd64:
  `83830217...` in the image, `3b32835f...` in the release), because the release job built in a checkout
  and Go stamped VCS details into it, while the Docker build had no `.git`. Both now run one recipe,
  `scripts/build.sh` (Go release from `go.mod`, `-trimpath`, `-buildvcs=false`, version and commit from
  `-ldflags` only), so `SHA256SUMS` describes what runs. A CI job builds every change both ways and fails
  on any difference, and the release workflow compares the pushed image with the release binaries before
  it creates the GitHub release.
- A hung relay stayed hung: Docker does not restart a container that is only unhealthy. A watchdog now
  exits the relay (log `relay.watchdog`, status 2) when the core lock cannot be taken for 60 seconds or
  the maintenance loop has not finished a pass for 3 minutes, and the signer exits after six failed token
  writes in a row instead of logging `signer.write_failed` forever. The restart policy brings either back.
- A connection to Apple that went silent (TCP up, HTTP/2 not answering) was found only by the next push,
  which then failed with `apns_unavailable` after 3 seconds. The client now sends an HTTP/2 PING after two
  minutes without traffic instead of an hour and closes a connection whose PING is not answered within
  15 seconds, so the next push opens a fresh one. `spec/protocol.md` says so.
- `docs/hardening.md` said container images are scanned for known vulnerabilities, but no workflow did.
  Grype now scans the image on every pull request and push to `main`, the pushed image by digest before a
  GitHub release is created, and the latest release weekly; a HIGH or CRITICAL finding with a fix fails
  the run. govulncheck also runs weekly, so a fix in the Go standard library is noticed without a commit.
  All actions stay pinned by commit.

### Security

- `golang.org/x/net` v0.63.0 (from v0.62.0). The relay uses it only for `idna` in autocert; govulncheck
  reported nothing reachable before or after.

## [1.0.6] - 2026-11-23

### Fixed

- After a restart the per-device silent limit was halved to 3 per hour until the next UTC midnight, so a
  device's fourth silent push in an hour was refused with `429 device_quota` hours after a deploy, although
  Apple had not throttled anything. The limit is a fixed UTC clock-hour window, and only the window in which
  the relay started lost counts; the halving now ends with that hour, and the device gets 6 per hour again
  from the next one. The halved Live Activity start and end limits, which are counted per day, still last
  until midnight. `spec/protocol.md` ("After a restart", push rule 11) and the threat model say so.
- Tests now hold that every request to Apple, on every send path and whatever Apple answers, counts in
  exactly one kind of `hlp_apns_sends_total`, so the kinds add up to `hlp_apns_requests_total`; that the
  silent budget counts only the instance's silent pushes (not alerts, Live Activity pushes, the challenge
  push, a replayed ref or a refunded send); and that a provisional binding, also one bound again after an
  opt-out, gets silent pushes within the device budget, which leaving and binding again neither resets nor
  lowers. The split by kind is served from the copy taken every five minutes while the total is live, so
  between two copies the kinds can trail the total; a test shows they agree again at the next copy.

## [1.0.5] - 2026-11-23

### Changed

- `/privacy`, `/terms` and `/` answer a browser with a readable HTML page: a short header, the text, and a
  footer with the relay version, a link to the plain text and the source repository; light and dark follow
  the system setting. Every other client, `curl` and HealthLog servers included, gets the plain text byte
  for byte as before. The choice follows the `Accept` header: only a client that prefers `text/html` over
  `text/plain` gets HTML, and both answers carry `Vary: Accept`. `/privacy.txt` and `/terms.txt` always
  answer the plain text.
- The HTML is rendered from the same embedded text when the relay starts, by a small renderer in
  `internal/notice` for the markdown the notices use. It escapes every character, links only https and
  mailto targets, and refuses anything outside that subset, so a new construct in a notice fails the tests
  rather than rendering as something the text does not say. No dependency is added.
- The HTML pages run no script and load nothing. Their Content-Security-Policy is `default-src 'none'` plus
  their one inline style, allowed by its SHA-256 hash, with `base-uri`, `form-action` and `frame-ancestors`
  set to `'none'`; they also carry `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`. HSTS,
  `nosniff` and `no-store` stay as on every other response.

## [1.0.4] - 2026-11-22

### Added

- The GitHub release carries an SPDX SBOM for each Linux binary,
  `healthlog-push_vX.Y.Z_linux_<arch>.spdx.json`. syft reads it from the finished binary, so it lists the
  modules and the Go version that were compiled in. The SBOMs are listed in `SHA256SUMS` and covered by its
  signature and by the binary provenance. A job without signing rights builds the binaries and the SBOMs.
- Dependabot also watches the hash-pinned linters for the deploy code.
- `GOVERNANCE.md`, `MAINTAINERS.md`, `docs/roadmap.md`, `docs/continuity.md` and `docs/assurance-case.md`: how
  decisions are made, who has access to what, the direction, what is in place if the maintainer is gone,
  and the argument for why the design meets its security requirements.
- CI measures statement coverage across all packages and fails below 80 %.

### Changed

- The README is cut to what a first reader needs. The limits and the identity keys of the hosted relay are
  now in `docs/hosted-relay.md`, the privacy properties in full and the code layout in
  `docs/architecture.md`.
- `SECURITY-INVARIANTS.md` moved to `docs/security-invariants.md`, next to the threat model it belongs to.
- golangci-lint runs in a workflow of its own, `lint.yml`, so the README badge shows its state on `main`.
- The `emergency` identity key is described as it is held: separately from the relay host and from the
  operational keys, and never deployed to the relay. Earlier texts said "kept offline", which was not
  accurate; the changelog entry for 1.0.2 and the transparency feed are corrected, and the feed notes the
  correction.
- `docs/continuity.md` states only what is in place: a continuity arrangement with a designated trusted contact,
  a successor for the maintainer's GitHub account, and a yearly review.
- Release tags are signed from the next release on (`git tag -s`). Tags up to v1.0.3 are unsigned
  lightweight tags.
- Contributions need a `Signed-off-by` line on every commit (Developer Certificate of Origin 1.1); the check
  `DCO sign-off` enforces it on pull requests. Until now no sign-off was required.
- `SECURITY.md` states the support policy, how fixed vulnerabilities are published and credited, the
  thresholds for findings from automated analysis, and how secrets are handled. `CONTRIBUTING.md` gains the
  coding style, the test policy and the review rule.
- Seven metrics are current at every scrape: HTTP responses by status class (`hlp_requests_total`), requests
  to Apple without a split by kind (`hlp_apns_requests_total`, new), Apple's refusals by reason, the delivery
  latency, and the breaker, provider-token and store gauges. Until now the whole `/metrics` output was a
  snapshot refreshed once an hour while fewer than 20 instances were active, which hid a failed or slow
  delivery for up to an hour. Every other metric, every split by push class or kind, the key slot, the silent
  budget refusals by type, the queue and the figures about who is registered among them, is served from a copy
  taken every five minutes, at every number of instances. A metric added later is held unless the code
  declares it live. `hlp_instances` counts a tier with fewer than three instances under `tier="other"`, so
  that no value names the tier of a single instance; `admin stats` keeps the exact sums. With very few active
  instances the live counts still reflect their traffic in aggregate, without its kind, and with a single one
  they are that instance's: the privacy notice (now version 1.3; the consent text version stays
  `2026-11-21`), the threat model, the specification and invariant P2 say so. The summary log line keeps its
  hourly period below 20 active instances.
- `docs/transparency.md` states for every metric how current it is (`live` or `every 5 min`), and a test
  fails when the table and the code disagree. A second test fails when the live set changes without the test
  changing with it.
- An instance that never had an accepted push is removed only once it has also been out of contact for
  more than 30 days, counted in whole weeks. Until now it was removed two days after registration whatever it
  did, with every binding, so a server still waiting for its first device lost its registration and, in
  invite mode, could not register again without a new invite. Status calls, a registration with its key and
  pushes count as contact. The privacy notice (section 5), the threat model and the specification say so.
- An idempotency entry lives as long as its item's lifetime after clamping, at least 10 minutes. It lived 10
  minutes, while an instance can retry an alert for up to six hours: a retry after a lost response, late in
  the backoff, put a second copy at Apple. Now it gets the stored answer.
- `spec/envelope.md` lists the six `DATA_CHANGED` domains and the six `securityKind` values a HealthLog
  server sends, and describes discreet mode as a property of a single alert, used for cycle reminders only.
  `spec/relay-api.yaml` no longer declares `BindResponse.challenge` and `StatusResponse.reason`, which the
  relay never sends.
- `hlp_apns_misconfigured` exists from the start and reads 0 on a healthy relay. It used to appear only once
  Apple had rejected the provider token, so a rule on it looked at no data until the incident it is for.
- `hlp_delivery_latency_seconds` has nine buckets (0.05, 0.1, 0.15, 0.25, 0.5, 1, 2.5, 5 and 10 s) instead
  of six from 0.1 s to 5 s. Apple usually answers in 100 to 250 ms, which all fell into one bucket; and with
  5 s as the last bound a 95th percentile above five seconds read as exactly five. Dashboards and rules that
  name the old bounds need the three new ones.

### Fixed

- `hlp_push_total` counts the two item refusals that happen before an item is queued: `binding_unknown` (no
  binding of the instance for that token) and `invalid_item` for an item addressed to the other APNs
  environment. Both were answered correctly but left no trace in the metrics.
- An item Apple did not take for a reason of Apple's service or of the relay (`apns_unavailable`,
  `relay_misconfigured` after a refused provider token, or a drop after waiting too long in the queue) is taken
  off every limit it was counted against, as long as the window that counted it is still the current one.
  Until now every retry during an outage at Apple used up the device's silent budget (six an hour, three
  after a restart) and the instance's quotas, and the first push after the outage could be refused.

## [1.0.3] - 2026-11-22

### Added

- The GitHub release carries SLSA v1.0 provenance for the Linux binaries and `SHA256SUMS`,
  `healthlog-push_vX.Y.Z.intoto.jsonl`, signed by the SLSA generic generator (v2.1.0). It checks with
  `slsa-verifier verify-artifact`. The image signature, its SBOM and its provenance, and what the deployment
  role verifies, do not change.
- Two gauges on the local metrics listener: `hlp_instances{tier}` (probation, standard, suspended, revoked)
  and `hlp_bindings{state}` (provisional, active, soft_invalid), the same sums as the `instances` and
  `bindings` blocks of `admin stats`. Every label of the closed sets is present on every scrape, zero
  included, and the values pass through the same coarse snapshot as the other metrics. An operator can now
  chart registrations and binding states without polling the admin socket.
- Operational counters about the relay's own work, every label from a closed set fixed in the code:
  `hlp_apns_sends_total{kind}` (alert, silent_sync, silent_wake for the relay's challenge push, la_start,
  la_update, la_end), `hlp_delivery_latency_seconds` (a histogram without labels from acceptance to Apple's
  answer, six buckets from 0.1 s to 5 s), `hlp_apns_rejections_total{reason}` (Apple's reason codes, anything
  unknown as `other`), `hlp_liveactivity_priority_total{priority}`, `hlp_push_retries_total{answer}`,
  `hlp_queue_depth`, `hlp_silent_budget_refused_total{kind}` (sync, wake),
  `hlp_deliveries_by_key_slot_total{slot}` (current, next, emergency, unpinned),
  `hlp_registrations_rejected_total{reason}` (no_invite, bad_signature, rate_limited) and
  `hlp_rate_limited_total{surface}`. Nothing describes an instance beyond the existing counts, and the values
  pass through the same coarse snapshot.
- `docs/transparency.md` lists every metric the relay exposes, with its labels and the reason it exists, and
  states how long the hosted relay's monitoring keeps them. A test fails when the code registers a metric the
  table does not list, and another when a series carries a label or a value outside the fixed allowlist.

### Changed

- The privacy notice (now version 1.2; the consent text version stays `2026-11-21`) states that Hetzner
  Online GmbH hosts the relay as a processor under a data processing agreement (Art. 28 GDPR), concluded on
  2026-11-22. Until now it said only that such an agreement was available.
- The README is reorganised around what the relay is, how the privacy works, what the operator can see,
  the hosted relay, self-hosting, verifying a release and security. The limits, the identity keys and the
  verification commands are unchanged.
- `docs/release-verification.md` describes how the build pipeline is protected as it is: every action pinned
  to a commit, with the SLSA generator as the one tag-pinned exception and the reason for it, the tag
  ruleset, and why GitHub's immutable releases stay off. `SECURITY.md` gains the same in short and a section
  on verifying a release.
- Only the first job of the release workflow names the `release` environment, which accepts only `v*`
  tags; every other job depends on that job. The environment has no required reviewer.
- The hardening statement, the key ceremony and the Ansible examples no longer name the server model, the
  exact reboot time, an example host name or the layout of the secret store.
- golangci-lint also runs `contextcheck` and `unparam`. The admin socket listener and the shutdown derive
  their contexts from the process context; queued sends keep their own context on purpose, because they
  outlive the request that queued them.

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
  README. It is held separately from the relay host and from `current` and `next`, never deployed, and
  promoted only if both are lost; `docs/key-ceremony.md` has the procedure. The relay keeps signing with `current`.
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

[1.0.11]: https://github.com/MBombeck/healthlog-push/releases/tag/v1.0.11
[1.0.9]: https://github.com/MBombeck/healthlog-push/releases/tag/v1.0.9
[1.0.8]: https://github.com/MBombeck/healthlog-push/releases/tag/v1.0.8
[1.0.7]: https://github.com/MBombeck/healthlog-push/releases/tag/v1.0.7
[1.0.6]: https://github.com/MBombeck/healthlog-push/releases/tag/v1.0.6
[1.0.5]: https://github.com/MBombeck/healthlog-push/releases/tag/v1.0.5
[1.0.4]: https://github.com/MBombeck/healthlog-push/releases/tag/v1.0.4
[1.0.3]: https://github.com/MBombeck/healthlog-push/releases/tag/v1.0.3
[1.0.2]: https://github.com/MBombeck/healthlog-push/releases/tag/v1.0.2
[1.0.1]: https://github.com/MBombeck/healthlog-push/releases/tag/v1.0.1
[1.0.0]: https://github.com/MBombeck/healthlog-push/releases/tag/v1.0.0
