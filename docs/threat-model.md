# Threat model

This document describes what the relay protects, against whom and what it cannot protect. The tests that
hold each property in place are listed in [SECURITY-INVARIANTS.md](../SECURITY-INVARIANTS.md). It describes the code in this repository. Rules that the HealthLog app and server
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
  directly only to opt out, to read its own binding, to withdraw its Live Activity consent and to answer a
  conflict challenge.
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
template plus an opaque envelope (`internal/apns/apns.go`), or for a Live Activity a fixed template with a
content state (`internal/apns/liveactivity.go`).

## Live Activity start and update

ActivityKit cannot decrypt, so a Live Activity start or update carries its content state in the clear.
The relay sends them only for a binding whose device gave the second, separate Live Activity consent
(`hl-la-consent-v1`, signed by the binding key, passed on by the instance). With that consent:

- **The relay and Apple learn** when a dose is due and its state: `status` (`pending`, `due`, `overdue`,
  `snoozed`, `taken`, `skipped`), `countdownTarget`, `isOverdue`, `confirmed`, `pendingConfirm` and
  `timeFormatRaw`, at the moment of each start and update. They learn no medication name, no dose and no free
  text. Apple can link this, like every push, to the Apple account of the token. The relay also sees the
  app's push-to-start token on every start and the activity's update token on every update; it stores
  neither, nor any state, and keeps only in-memory counters (starts per device, updates per activity keyed by
  an HMAC of the update token, cleared daily).
- **The template is the control.** The relay forwards exactly six keys with fixed types, closed enumerations
  and a `countdownTarget` of `0` or within one day back to two days ahead of the relay clock; an unknown key
  or a wrong type refuses the whole request, a value outside its range the item. The start attributes are
  fixed (`HealthLogDoseAttributes`, `{"v":1}`) and the start alert is a fixed pair of localization keys, so
  an instance cannot place text anywhere in a Live Activity.
- **Statements are not interchangeable.** A start needs `hl-la-start-v1` over the push-to-start token (at
  most 30 days old); an update or end needs `hl-activity-v1` over the update token (at most 12 hours old).
  Neither starts what the other covers, and without the consent no start or update leaves the relay
  (`403 liveactivity_consent_required`); the end needs no extra consent, as before.
- **Withdrawal does not need the instance.** The device removes the consent at the relay directly
  (`DELETE /v1/bindings/self/liveactivity`, `hl-la-withdraw-v1`); the instance can drop it too. It belongs to
  the binding key and goes with the binding.
- **A hostile instance** with the consent can start at most 12 activities per device and day and send at
  most 12 updates per activity and hour and 48 per day, each inside the template. It can show a wrong state
  (a dose as taken, a wrong countdown), not a word of its own.
- **A compromised relay or an APNs key holder** can push a misleading content state to an activity token it
  has seen, or start activities with a push-to-start token it has seen, without any consent check, because
  that check runs in the relay. What the Live Activity can show is still bounded by the template, because the
  app's attributes and content-state types hold only these fields (a rule of the app), so the worst is a misleading state of a known
  activity (for example "taken" for a dose that was not), not free text in the activity. The alert of a
  forged start is a different matter; like any alert from the key holder, it can carry arbitrary text (see
  below). Local reminders stay authoritative.
- **Push-to-start token exposure.** The push-to-start token is long-lived: it stays valid until the system
  issues a new one, and the start statement over it may be up to 30 days old. With the consent it passes
  through the relay on every start. Whoever captures it and holds the APNs key can start dose activities on
  that device until the token changes; the relay can refuse starts of instances, not of an APNs key holder.
  Withdrawing the consent stops the relay and the instances from using the token, not a key holder. An
  intruder in the relay process collects the push-to-start tokens of the starts that pass while they are
  there, as with device tokens.

Metadata is the residual risk. The class and the timing of pushes can reveal behaviour: a Live Activity end
says "a dose was recorded elsewhere, now", and so does the silent intake sync that goes out at once after a
dose is recorded (an accepted limit, see "Known limitations"). With the Live Activity consent, the content state of a start or
update says more, by design (see "Live Activity start and update"). The relay keeps times only as day or week numbers in its store,
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
  accepts remote Live Activity content only inside the closed template, and remote starts and updates only
  after the person gave the Live Activity consent. These are rules of the app; the relay's part is that its
  own templates carry none of these fields, that it forwards only a template-checked content state, and that
  without that consent it sees a Live Activity token only at the moment of the end;
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
- the tokens of pushes that pass while they are inside, and the delivery traces of the last 72 hours
  (Apple's `apns-unique-id` per instance and `ref`, development builds only).

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
  only from the signed body. A non-canonical path gets a signed `404`, never an unsigned redirect.
  `/privacy`, `/terms`, `/.well-known/security.txt` and `/` are plain text and not signed;
- replay instance requests elsewhere: the request signature covers the host name, the instance id, method,
  path and query, time, nonce and body hash;
- bind devices: a binding needs a statement signed by the device's binding key for that host and instance.

A takeover therefore becomes an outage with a metadata leak, not a takeover of devices. The hosted relay also
restricts certificate issuance to its own ACME account and to TLS-ALPN-01 with a CAA record.

## Hostile instance operator

An instance operator can push to the devices of its own users until they leave. The device leaves without
the operator's cooperation: `DELETE /v1/bindings/self`, signed with the binding key, deletes the binding,
blocks the pair of token HMAC and instance id for 365 days, and pins the hash of the binding key to the token
for 365 days. The instance cannot bind that token again with any statement it holds. Only a statement by the
same binding key with a `seq` higher than that of the binding that left, signed after the opt-out and after
the relay start, lifts the block, which is the person turning the relay on again in the app.

The pin closes the way around the pair block: the operator registers a second instance, makes up its own
Ed25519 key and signs a bind statement with it. The relay cannot tell a made-up key from a device key, but
while the token is unbound, any key other than the pinned one is a conflict that needs the challenge push,
and only the app holding the key can answer it. Each instance can trigger at most one challenge per token and
day. A pin restored from the export carries no key, so after a restore every new binding of the token needs
the challenge. Until the person leaves, the per-device limits bound the harassment: an alert bucket of 20
that refills 6 per hour, at most 100 alerts per day, 300 pushes of all classes per day.

An instance that knows a token bound elsewhere learns nothing from the relay: pushes and unbinds for a token
not bound to the asking instance answer exactly as for an unknown token, and the app-direct endpoints verify
the signature first for every request, so the response time does not show whether a binding exists either.
A different binding key for a live token is never resolved by last writer wins; the relay sends a challenge
push to the token and only the app holding the new key can answer it. Without an answer, only the instance
that holds the binding can replace it with a new key directly, and only after the binding has had no
accepted push for seven days (a restored app whose challenge did not arrive). A former instance that kept
the token and the old binding key can never take over a binding that went quiet.

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
- Connections are capped at 2,000 in total, 8 per IPv4 address or IPv6 /64 and 64 per IPv6 /48, with at
  most 16 HTTP/2 streams each (a HealthLog server needs one connection); header size and timeouts are bounded. A request body must declare its length and is checked
  against the endpoint limit before a byte is read; an instance request is checked for a known instance and a
  valid time stamp from the headers before its body is read; all bodies in flight together are capped at
  32 MiB (`503 overloaded` above that), and the Go heap is kept below the container limit.
- Failed signatures are never a reason to refuse a valid request: the per-instance budget for them only
  limits how often failures are counted in the metrics, so knowing an instance id does not allow locking that
  instance out.

## Authorities

An authority can ask the relay operator for what the relay holds, which is bounded by the store and
memory described above; there is no content to hand over. Requests received (none so far), how they are
handled, and every deprecation and key rotation are published in [transparency.md](transparency.md). Apple
can be asked directly for what it sees, without the relay.

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
- the send queue always admits when it is empty, so a run of slow sends during an Apple outage cannot lock it
  shut; the APNs warm-up (one request at a time) ends after the first attempt, whatever its outcome;
- a provider-token rejection is forgotten once Apple accepts a newer token, so an old rejection followed much
  later by a single new one does not stop the relay;
- a store that cannot be written keeps the push path working from memory and refuses only new bindings and
  registrations;
- a database with proven damage is moved aside at start (under a new name, never over an earlier copy) and
  the registry is restored from the export; any other error opening it stops the relay instead, so a held
  lock or a permission problem never costs the bindings;
- the export is the root of trust after a database loss, so it is signed with the relay identity key
  (`hl-relay-export-v1`). An unsigned export is never written; an edited, unsigned or foreign export, or one
  with an instance outside the closed sets (id, key length, tier, reason, device limit), fails the whole
  import and the relay does not start, so a change in the backup path cannot lift a suspension, drop an
  opt-out or create a `standard` instance;
- in a recovery window only the instances from the export keep their tier; any other key registers in
  probation;
- `/healthz` and the deploy gate depend only on the relay's own facts (provider token, writable store);
  third parties can move `breaker` and `delivery`, which are shown but never change the status.

## Known limitations

- **The first token failures before the breaker opens are honoured.** The breaker needs at least 20 sends to
  established bindings in its five-minute window, with failures from at least three instances. With a
  misconfiguration that makes every send fail, up to 19 `Unregistered` answers delete their bindings, and
  soft failures mark theirs, before it opens; with fewer than three instances sending, it does not open at
  all. Those devices rebind through their server.
- **A conflict challenge needs the silent push to arrive.** Apple may throttle or drop it, or the device
  may be off. The fallback then waits seven days without an accepted push, and only the instance that
  holds the binding may use it; a binding of an opted-out token waits for the device in every case.
- **Time patterns stay visible** to the relay and to Apple at the moment of sending, as described above.
- **Blocks depend on the configured MAC keys.** Opt-out blocks, opt-out pins and token blocks are looked up under the current and
  the previous token MAC key, so they survive one rotation. Once the previous key is removed from the
  secrets, blocks recorded under it no longer match (bindings have moved by then; blocks are not rewritten).
- **A restore needs the same token MAC keys.** All blocks travel in the daily export and are restored, but
  opt-out blocks, pins and token blocks are hashes over the token MAC; a restore with a different MAC key would not match
  them. The MAC keys come from the secret store, never from the old disk.
- **Receipt counts are self-reported.** `POST /v1/receipts` sums counts from `standard` instances, at most
  one report per 45 minutes each, and caps each reported `accepted` at what the relay itself accepted for that
  instance in the last three days. The `delivery` signal needs at least 20 accepted pushes and reports from at
  least three instances in 24 hours. Cooperating `standard` instances can still turn it to `degraded`; it is
  display only and changes neither the `/healthz` status nor the deploy gate.
- **A restart forgets in-memory counters.** Per-device silent and Live Activity start and end limits and the global
  registration caps are halved until midnight to compensate; the alert bucket starts full; the nonce cache
  is empty, which is why time stamps from before the start are refused. Only each binding's alert count of
  the day and each instance's push count of the day are restored (and the instance flag, which is stored as
  a day). The per-instance counts of new bindings and challenges of the day, the record of which token each
  instance challenged that day, the 24-hour block after an exceeded invalid-token budget and the
  per-activity Live Activity update counts (not halved) start again from zero, so each restart gives every instance these allowances afresh for the rest of the day.
- **Apple's timestamp on a `410` is compared by day only.** Apple reports when it confirmed that a token
  became invalid. A binding made or renewed on a UTC day that begins more than 10 minutes after that time is
  kept and handled like a soft failure (a second such answer on a later day deletes it); the relay stores no
  finer time of a binding. A binding renewed later on the very day of the invalidation is deleted as before,
  and the device binds again through its server.
- **Silent intake syncs go out at once (accepted).** When a dose is recorded, the server sends the silent
  `MEDICATION_INTAKE_SYNC` to the person's other devices without delay, so Apple and the relay can see when
  a dose was recorded, to the minute, from the time of that background push (the content stays sealed). A
  random delay or batching of a few minutes would blur that time, but in that window another device could
  still fire its local reminder, or offer the dose as open, for a dose that was already taken. Preventing a
  double dose is chosen over hiding the timing. This is a decision, not an oversight: the time of this push
  stays visible, like that of every push (see "Metadata is the residual risk" above).
- **Delivery traces are kept for 72 hours in memory.** For a push to a development build, Apple returns an
  `apns-unique-id`; the relay keeps it with the result, keyed by instance id and `ref`, so the operator can
  trace one lost push in Apple's delivery log (`admin delivery`). It is the only per-push record kept beyond
  the 10-minute idempotency window, it is never stored, exported, logged or counted, and production pushes
  have none because Apple does not send the identifier there. An intruder in the relay process could read
  the traces of the last 72 hours.
- **A panic in a send worker ends the process.** It is not recovered; the container is restarted, with the
  restart rules above.
- **One global lock.** All mutable relay state is guarded by one mutex; signatures are verified and bodies
  read outside it. This keeps the invariants simple to check but bounds throughput to one handler in the
  critical section at a time. The concurrency model is in
  [SECURITY-INVARIANTS.md](../SECURITY-INVARIANTS.md).
- **Failed app calls share one global bucket** of 100, refilling 20 per second. Only failed attempts are
  charged to it, so flooding it with junk refuses other failing calls (`429 global`) but never a correctly
  signed opt-out, self-read, Live Activity withdrawal or challenge answer. Verified calls are limited per device token (10, refilling
  10 per hour).
- **Suspended and revoked instance records expire 365 days after their reason day**; after that the same key
  could register again as a new instance in probation.
- **The connection limiter keeps the IPv4 address or IPv6 /64 of open connections in memory** while they are
  open. Nothing writes it to disk or logs.
- **`/privacy`, `/terms`, `/.well-known/security.txt` and `/` are not signed.** The authoritative texts are
  also in this repository.
- **The admin socket trusts the host.** Anyone who can run `docker compose exec` on the host is an operator.
- **One host, one person.** See [operations.md](operations.md#absence-checklist).

## Properties and the tests that hold them

[SECURITY-INVARIANTS.md](../SECURITY-INVARIANTS.md) is the authoritative map from each invariant to the
tests that fail when it breaks, and a test keeps that map honest: it fails when a test named there no longer
exists. In short, it covers:

- **confidentiality**: the relay cannot open envelopes, and instances cannot choose visible content;
- **authenticity**: requests and responses are signed and bound to each other, nonces are single use, paths
  are canonical, and forged signatures cannot lock out an instance;
- **device bindings**: proof of possession, conflicts resolved only by the device, the seven-day fallback
  only for the holder, the opt-out with its key pin, uniform answers in content and in work done;
- **deletion and failure**: only `410` deletes at once, the breaker, the provider-token rule, store
  failures, the queue and warm-up recovery, races between rotation and deletion;
- **availability and fairness**: body budgets, per-instance, per-device and pool limits, registration and
  connection limits, health that depends only on the relay's own facts;
- **data minimisation**: logs, metrics, the store and the signed export hold only what the protocol allows;
- **implementations and texts**: shared vectors, fuzzed parsers with a committed corpus, one source for the
  legal texts.
