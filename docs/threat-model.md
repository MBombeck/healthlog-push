# Threat model

This document describes what the relay protects, against whom, what it cannot protect, and which tests hold
the properties in place. It describes the code in this repository. Rules that the HealthLog app and server
must follow are named where the relay depends on them; they are enforced in those projects, not here.

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Notification content | encrypted envelope, in transit only | health data; the relay must never be able to read it |
| APNs signing key (`.p8`) | file readable only by the signer container, which has no network | whoever holds it can send pushes to any token of the app |
| Provider token (JWT) | tmpfs shared by signer and relay | lets the relay talk to Apple; valid for at most one hour |
| Relay identity key (Ed25519) | relay secrets directory, relay process memory | signs every response; instances and the app pin its public key |
| Token MAC key | relay secrets directory, relay process memory | turns device tokens into the stored HMAC |
| Device tokens | memory during a request; at rest only as HMAC | needed to address a device through APNs |
| Bindings and instance registry | bbolt file in `/data`, daily export in `/export` | who may push to which token |
| Metadata | memory, day counters, logs, metrics | time patterns can reveal health behaviour |
| ACME account key and TLS key | relay secrets directory, `/acme` | the certificate for the public name |
| Availability | one host | notifications for every App Store user with a self-hosted server |

## Actors

- **Instance operator.** Runs a HealthLog server, registers it, binds devices of its users and pushes to
  them. Usually benign; can be hostile towards one of its own users (for example a former partner).
- **Device.** The HealthLog app. Holds the binding key and the device encryption key. Talks to the relay
  directly only to opt out, to read its own binding and to answer a conflict challenge.
- **Relay operator.** Holds the APNs key, the identity key and the admin socket.
- **Network attacker.** Can observe or redirect traffic, including through DNS or a mis-issued certificate.
- **Mass registrant.** Registers many instances or binds made-up tokens to exhaust limits or Apple's
  goodwill.
- **Intruder.** Compromises the relay process, the signer, or root on the host.
- **Apple.** Delivers every push and can link a token to an Apple account.

## What the relay sees, and what Apple sees

The relay sees the instance id and key, the instance's IP address (memory only), device tokens during a
request, the class, lifetime, fixed size and time of every push, a hash of the binding key, the consent text
version and day, and the device's IP address on the direct app calls. It never sees plaintext, user names,
host names of instances or the device encryption key. The full list with retention is in
[privacy.md](privacy.md).

Apple sees the device token, the time, the push type (`alert`, `background`, `liveactivity`), the priority,
the topic and the payload size, and can link the token to an Apple account. The payload is a fixed
template plus an opaque envelope (`internal/apns/apns.go`).

Metadata is the residual risk. The class and the timing of pushes can reveal behaviour: a Live Activity end
says "a dose was recorded elsewhere, now". The relay keeps times only as day or week numbers in its store,
keeps no class per instance at rest, writes logs and metrics without instance ids, and coarsens the summary
log line and the metrics to hourly while fewer than 20 instances are active. Registrations, key rotations,
instance deletions and resolved conflict challenges get no log line of their own; they are counted in the
`events` map of that summary line, so their time is no finer than the summary period. Lines that are still
written when they happen are a start or stop, the daily run and its results (promotions, the export), store
problems, breaker and Apple-side changes, and operator actions, which the operator triggers. It cannot hide the timing of the push it is sending at that moment.

## The holder of the APNs key

Whoever holds the APNs key (the relay operator, an intruder in the signer or with root on the host, or
anyone who obtains the key file) can, for every token they have seen:

- **send a visible plaintext alert with arbitrary text.** APNs does not inspect content, and an alert
  without `mutable-content` never reaches the app's notification service extension. This cannot be
  prevented by any push service; it is the honest limit of the design. A false text about a medication is a
  safety issue, which is why local reminders stay authoritative;
- set a category, `userInfo` fields or a Live Activity content state in such a push.

They cannot:

- **read any data.** There is no content at the relay, and the device keys never leave the device;
- **make the app act.** The HealthLog app takes action only on notifications it decrypted with its own key
  and verified, ignores plaintext fields, registers its action categories under per-installation names and
  accepts Live Activity updates only from local state. These are rules of the app; the relay's part is that
  its own templates carry none of these fields and that it sees a Live Activity token only at the moment of
  the end;
- reach tokens that never passed through the relay. At rest the relay stores only token HMACs.

The relay process never holds the APNs key. It reads a JWT that the signer writes; the relay uses it only
while it is younger than 55 minutes.

## Compromise of the relay process

An attacker who runs code inside the relay process (for example through a parser bug) gets:

- the relay identity key: they can forge responses for as long as they are there. Replace it with the
  pinned `next` key afterwards ([operations.md](operations.md#relay-identity-key));
- the current provider JWT, valid at Apple for at most one hour;
- the token MAC key and the database: they can confirm whether a token they already know is bound, but the
  database holds no tokens;
- the tokens of pushes that pass while they are inside.

They do not get the APNs key, which lives in another container with another user and no network. The signer
parses nothing from the relay; its only input is the modification time of an empty marker file.

## Root on the host

The measures that make this harder on the hosted relay (sandboxing, kernel settings, egress limits, audit
trail) are described in [hardening.md](hardening.md).

Root on the host has everything, including the APNs key file. The separation into two containers does not
help against that. The countermeasures are outside the code: a single-purpose host, key-only administrative
access over a private management network, no provider snapshots, secrets only from a secret store, core
dumps and swap off ([deploy/ansible/README.md](../deploy/ansible/README.md)). After a suspected host
compromise, revoke the APNs key in the Apple developer account and rebuild
([operations.md](operations.md#incident-and-breach)).

## DNS or TLS takeover

If the public name is redirected or a certificate is mis-issued, the attacker receives the requests sent in
that time: device tokens, instance ids, envelopes (unreadable) and timing. They cannot:

- answer in a way an instance or the app accepts: every `/v1` response, `/healthz` and `/version` carries
  `HL-Relay-Signature`, an Ed25519 signature (`hl-relay-resp-v2`) over host, method, path with query, request
  nonce, status and body hash. `HL-Nonce` is mandatory on every `/v1` request, so a recorded answer (for
  example a `204` to an opt-out) cannot be replayed onto another request. A HealthLog server and the app treat
  a missing or wrong signature, and an answer bound to no nonce, as a transport error, and take retry hints
  only from the signed body. `/privacy`, `/terms` and `/` are plain text and not signed;
- replay instance requests elsewhere: the request signature covers the host name, the instance id, method,
  path and query, time, nonce and body hash;
- bind devices: a binding needs a statement signed by the device's binding key for that host and instance.

A takeover therefore becomes an outage with a metadata leak, not a takeover of devices. The hosted relay also
restricts certificate issuance to its own ACME account and to TLS-ALPN-01 with a CAA record.

## Hostile instance operator

An instance operator can push to the devices of its own users until they leave. The device leaves without
the operator's cooperation: `DELETE /v1/bindings/self`, signed with the binding key, deletes the binding and
blocks the pair of token HMAC and instance id for 365 days, so the instance cannot bind that token again with
any statement it holds. Only a statement by the same binding key with a `seq` higher than that of the
binding that left lifts the block, which is the person turning the relay on again in the app. Until then the per-device limits bound the harassment: an alert bucket of 20 that
refills 6 per hour, at most 100 alerts per day, 300 pushes of all classes per day.

An instance that knows a token bound elsewhere learns nothing from the relay: pushes and unbinds for a
token not bound to the asking instance answer exactly as for an unknown token. A different binding key for a
live token is never resolved by last writer wins; the relay sends a challenge push to the token and only the
app holding the new key can answer it. Without an answer, the new key wins only after the existing binding
has had no accepted push for seven days.

## Mass registration and token spam

- Registrations: 3 per day per IPv4 address or IPv6 /64, 10 per /48, 30 per hour and 200 per day globally,
  halved globally after a restart until midnight. The operator can switch to invite-only or close
  registration.
- New instances start in probation with smaller limits and a separate, smaller pool of pushes per minute;
  promotion needs seven days, one push accepted by Apple and no anomaly.
- New bindings are provisional until Apple accepts a push; provisional bindings are capped, do not count as
  devices and expire when they are more than two days old. Instances that never deliver a push are removed
  more than two days after registration.
- An instance whose pushes hit more than its daily budget of invalid tokens gets no new bindings for 24 hours
  and can push only to active bindings (provisional and soft-invalid bindings answer `429 binding_quota`).
  A soft-invalid binding receives at most one probe push per day: on the day it failed it is refused.
- Invented tokens cannot move the breaker: it counts only sends to bindings that have had a push accepted, and
  opens only when the failures come from at least three instances. While it is not closed, failures of other
  bindings still count against the invalid-token budget.
- The operator finds such an instance with the admin command `suspects`, which lists instances with invalid
  tokens, rebinds or challenges in the last seven days, worst first.
- Connections are capped at 2,000 in total and 50 per IPv4 address or IPv6 /64, with at most 16 HTTP/2
  streams each; header size and timeouts are bounded. A request body must declare its length and is checked
  against the endpoint limit before a byte is read; an instance request is checked for a known instance and a
  valid time stamp from the headers before its body is read; all bodies in flight together are capped at
  32 MiB (`503 overloaded` above that), and the Go heap is kept below the container limit.
- Failed signatures are never a reason to refuse a valid request: the per-instance budget for them only
  limits how often failures are counted in the metrics, so knowing an instance id does not allow locking that
  instance out.

## Nobody can prove which code runs

The hosted relay runs a digest-pinned image that was built by a public workflow from a tag and signed
keyless; anyone can verify the signature and the provenance of that image. Nobody outside the host can
verify that this image is what actually answers at `push.healthlog.dev`; `/version` is a statement by the
server being checked. The design therefore does not rely on the code being honest for the content: the relay
has no means to decrypt envelopes, whatever code runs. It does rely on it for metadata handling.

## Availability

There is one relay on one host. A failure means no relay notifications until it is back; nothing queues on
the relay, instances own retries and deadlines. Local reminders on the device stay authoritative, and the
app does not depend on the relay for anything else. Protections against a self-inflicted mass outage:

- the token-failure breaker stops all deletions and marks while more than 30 % of at least 20 sends to
  established bindings in five minutes fail with a token error, from at least three instances, and closes only
  after Apple accepts again;
- a provider token rejected after a renewal stops all sends to Apple (`relay_misconfigured`) instead of
  burning tokens;
- `TooManyProviderTokenUpdates` pauses sends for 20 minutes; Apple throttling of more than 2 % of sends in
  five minutes switches silent pushes off for 15 minutes;
- a store that cannot be written keeps the push path working from memory and refuses only new bindings and
  registrations;
- a database with proven damage is moved aside at start (under a new name, never over an earlier copy) and
  the registry is restored from the export; any other error opening it stops the relay instead, so a held
  lock or a permission problem never costs the bindings;
- `/healthz` and the deploy gate depend only on the relay's own facts (provider token, writable store);
  third parties can move `breaker` and `delivery`, which are shown but never change the status.

## Known limitations

- **The first token failures before the breaker opens are honoured.** The breaker needs at least 20 sends to
  established bindings in its five-minute window, with failures from at least three instances. With a
  misconfiguration that makes every send fail, up to 19 `Unregistered` answers delete their bindings, and
  soft failures mark theirs, before it opens; with fewer than three instances sending, it does not open at
  all. Those devices rebind through their server.
- **A conflict challenge needs the silent push to arrive.** Apple may throttle or drop it, or the device
  may be off. The fallback then waits seven days without an accepted push.
- **Time patterns stay visible** to the relay and to Apple at the moment of sending, as described above.
- **Blocks depend on the configured MAC keys.** Opt-out and token blocks are looked up under the current and
  the previous token MAC key, so they survive one rotation. Once the previous key is removed from the
  secrets, blocks recorded under it no longer match (bindings have moved by then; blocks are not rewritten).
- **A restore needs the same token MAC keys.** All blocks travel in the daily export and are restored, but
  opt-out and token blocks are hashes over the token MAC; a restore with a different MAC key would not match
  them. The MAC keys come from the secret store, never from the old disk.
- **Receipt counts are self-reported.** `POST /v1/receipts` sums counts from `standard` instances, at most
  one report per 45 minutes each, and caps each reported `accepted` at what the relay itself accepted for that
  instance in the last three days. The `delivery` signal needs at least 20 accepted pushes and reports from at
  least three instances in 24 hours. Cooperating `standard` instances can still turn it to `degraded`; it is
  display only and changes neither the `/healthz` status nor the deploy gate.
- **A restart forgets in-memory counters.** Per-device silent and Live Activity limits and the global
  registration caps are halved until midnight to compensate; the alert bucket starts full; the nonce cache
  is empty, which is why time stamps from before the start are refused.
- **Failed app calls share one global bucket** of 100, refilling 20 per second. Only failed attempts are
  charged to it, so flooding it with junk refuses other failing calls (`429 global`) but never a correctly
  signed opt-out, self-read or challenge answer. Verified calls are limited per device token (10, refilling
  10 per hour).
- **Suspended and revoked instance records expire with their denylist entry after 365 days**; after that the
  same key could register again as a new instance in probation.
- **The connection limiter keeps the IPv4 address or IPv6 /64 of open connections in memory** while they are
  open. Nothing writes it to disk or logs.
- **`/privacy`, `/terms` and `/` are not signed.** The authoritative texts are also in this repository.
- **The admin socket trusts the host.** Anyone who can run `docker compose exec` on the host is an operator.
- **One host, one person.** See [operations.md](operations.md#absence-checklist).

## Review findings and the tests that hold them

| Finding | Property | Tests |
|---|---|---|
| The relay must not be able to open envelopes | no HPKE, X25519 or AEAD import anywhere; envelopes checked only by frame | `TestRelayCannotOpenEnvelopes`, `TestEnvelopeFrameChecked`, `TestVectorsEnvelopeFrame`, `FuzzCheckEnvelopeFrame` |
| The APNs key must stay out of the networked process | ECDSA only in the signer and the CLI; signer renews on schedule and at most every 20 minutes on request | `TestECDSAOnlyInSignerAndCLI`, `TestParseKeyFromP8`, `TestJWTShape`, `TestRenewalTiming` |
| Instances must not control visible content | payload keys exist only in the APNs templates; alert and silent templates fixed | `TestPayloadTemplatesOnlyInAPNs`, `TestTemplates`, `TestEndToEndAlert`, `TestSilentTemplateAndPriority` |
| Addresses must not reach logs | `RemoteAddr` read only for the limiters; no forwarding headers | `TestClientAddressConfined` |
| Logs must not carry free text | one logger, closed key set, silent HTTP server error log | `TestOnlyOneLogger`, `TestLogFieldsAreClosed`, `TestServerErrorLogIsSet` |
| Logs, metrics and stats must not identify instances or devices | real traffic, then search for ids, tokens, MACs and addresses | `TestNothingIdentifyingReachesLogsMetricsOrStats` |
| Small populations must not be timeable from metrics | snapshot refreshed hourly below 20 instances | `TestMetricsCoarseBelowThreshold` |
| Usage figures must be counts of completed periods | no current day, no per-instance values | `TestUsageAggregates` |
| Responses must be bound to the request | signature covers host, method, path with query, nonce, status and body; nonce mandatory on every `/v1` request; responses stay within 64 KiB | `TestResponseSignatureBindsNonce`, `TestNonceMandatoryOnV1`, `TestResponseSizeBounded`, `TestStatusFileSigned` |
| Requests must not be replayable or re-targetable | signature scope, nonce cache, time window, start time | `TestRequestSignatureScope`, `TestNonceReplayAndTimeWindow`, `TestUnknownInstance` |
| Forged signatures must not lock out an instance | the signature is always verified; the failure budget only limits counting | `TestForgedSignaturesCannotLockOutAnInstance` |
| Unauthenticated bodies must not exhaust memory | headers checked before the body, declared length, global budget for buffered bodies | `TestHeadersCheckedBeforeBody`, `TestBufferedBodyBudget` |
| Junk must not block a device's opt-out | app calls verified first, only failures charged globally, verified calls limited per device | `TestJunkCannotStarveOptOut`, `TestAppEndpointsLimitedPerDevice` |
| Knowing a token must not allow binding it | device-signed statement, higher sequence for a move | `TestBindingProofOfPossession`, `TestParseBind`, `FuzzParseBind` |
| The relay must not be an oracle for foreign bindings | uniform `404 binding_unknown` and `204` on foreign unbind | `TestUniformAnswers` |
| Conflicts must not be last writer wins | challenge push, seven-day fallback | `TestChallengeFlow`, `TestConflictFallbackAfterSevenQuietDays` |
| A device must be able to leave a hostile instance | direct opt-out and pair block | `TestDirectOptOut` |
| A bad deploy must not delete every binding | only `Unregistered` is final; breaker stops deletion; fixed deletion paths | `TestUnregisteredIsTheOnlyFinalDeletion`, `TestBreakerProtectsBindings`, `TestBreakerHalfOpenDoesNotDelete`, `TestBreakerThresholds`, `TestBreakerStillOpensOnRealMisconfiguration`, `TestDeletionOnlyThroughKnownPaths` |
| Invented tokens must not open the breaker for everybody | only established bindings count, failures from at least three instances, one probe a day for soft-invalid bindings, non-active bindings blocked over the budget | `TestInventedTokensCannotOpenTheBreaker`, `TestBreakerNeedsThreeInstances` |
| Harassment of one device must be bounded | alert bucket, day caps, silent and Live Activity caps, persisted alert count | `TestDeviceAlertBucketAndSilentLimit`, `TestDeviceDayCapAllClasses`, `TestAlertDayCapSurvivesRestart`, `TestLiveActivityEndsPerDay` |
| One instance must not starve the others | instance quotas, binding quotas, probation pool, fair queue | `TestInstanceRateLimits`, `TestPushesPerMinuteProbation`, `TestBindingQuotas`, `TestProvisionalNeedsRoomBelowDeviceLimit`, `TestProbationPoolIsSeparate`, `TestFairAndPrioritised`, `TestAdmissionControl`, `TestEstimatedWaitRefuses`, `TestStaleJobsDropped` |
| Mass registration must be bounded | per-prefix and global caps, finite caps in a recovery window, registration modes, invite spent only on success | `TestRegistrationLimits`, `TestPrefixes`, `TestRegistration`, `TestRegistrationModes`, `TestInviteKeptWhenLimitRefuses`, `TestConnLimiter` |
| Token spam must not pay off | invalid-token budget, provisional expiry, promotion rules | `TestInvalidTokenBudget`, `TestProvisionalAndInstanceRetention`, `TestPromotionAfterSevenDays` |
| Apple's signals must slow the relay down | per-device throttle, silent pause, provider token errors | `TestAppleDeviceThrottle`, `TestSilentPausedOnAppleThrottling`, `TestProviderTokenErrors`, `TestClassify` |
| Retries must not double-send | idempotency by instance and `ref` | `TestIdempotency` |
| Live Activity ends must be device-authorised | activity statement checked against the binding key | `TestLiveActivityEnd` |
| Malformed input must be refused, not guessed | strict JSON, size limits, fuzzed parsers | `TestParsePushBodyRefusesUnknownFields`, `TestValidateItem`, `TestParseRegistration`, `TestParseUnixAndNonce`, `TestParseClient`, `TestRequestLevelRefusals`, `FuzzParseRegistration`, `FuzzPushItems`, `FuzzParseUnbind`, `FuzzParseChallenge`, `FuzzParseSelfRead`, `FuzzHeaders`, `FuzzParseReceipts` |
| The store must hold only what the protocol allows | closed bucket list, retention, weeks start on Monday | `TestStoreBucketsAreClosed`, `TestRetention`, `TestWeeksStartOnMonday` |
| A backup must not contain bindings or tokens | export holds instances, denylist and keyed block hashes only; restore keeps ids | `TestExportRoundTrip`, `TestMigrationExportRestore` |
| An abuse block must survive a restore | token blocks, denylist and blocked instance tiers in the export, 12-month retention on export and import | `TestAbuseBlocksSurviveRestore`, `TestExportBlocksRetention` |
| A device opt-out must survive a restore | opt-out blocks in the export, 12-month retention applied on export and import | `TestOptOutSurvivesRestore`, `TestExportBlocksRetention`, `TestDamagedStoreRecovers` |
| MAC key rotation must not orphan bindings in use | bindings move to the current key on use | `TestMACKeyRotation` |
| An opt-out must survive a MAC key rotation | blocks are checked under every configured MAC key | `TestBlocksSurviveMACRotation` |
| Records of revoked instances must expire | removed with the denylist entry after 365 days | `TestRevokedRecordsExpireWithTheDenylist`, `TestRetention` |
| A storage failure must not stop delivery | push path works from memory, new bindings refused | `TestStorageFailureKeepsSending` |
| The minute flush must not stall the relay | one write transaction for all changes, unchanged instances not written | `TestFlushIsOneTransaction` |
| A start error must not discard the database | moved aside only on proven damage, under a name that is never overwritten | `TestStoreNotMovedWithoutProof`, `TestDamagedAsideNeverOverwritten`, `TestDamagedStoreRecovers` |
| A deleted instance must not keep bindings | binding refused when the instance vanished after authentication | `TestBindAfterInstanceDeletion` |
| A relay that answers 200 and sends nothing must show | receipts feed the `delivery` signal, capped by the relay's own accepted count, display only | `TestReceiptsDriveDeliveryHealth` |
| TLS 1.2 must serve only certificate validation | the 1.2 configuration only for a handshake offering nothing but `acme-tls/1` | `TestTLS12OnlyForPureACMEValidation` |
| `/healthz` must not leak details | exactly five fields, security headers on every page | `TestPublicEndpoints` |
| Operator commands must take closed values | invalid classes, reasons, limits and notice ids refused | `TestAdminCommands`, `TestParse`, `TestPauseNoticeSuspendRevoke`, `TestBlockToken`, `TestRotateAndDelete` |
| Sandbox must be off unless served | bindings for an unserved environment refused | `TestSandboxRefusedWhenNotServed` |
| Implementations must agree | shared vectors for token tags, statements and envelope frames | `TestVectorsTokenTags`, `TestVectorsStatements`, `TestVectorsEnvelopeFrame` |
| Text rules | no forbidden characters in tracked files | `TestTextRules` |
