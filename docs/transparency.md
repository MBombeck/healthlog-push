# Transparency

What the hosted relay at `push.healthlog.dev` has been asked for by authorities, how such requests are
handled, and a dated feed of deprecations and key rotations. This file is reviewed with every release and
whenever something below changes; the date of each entry says when it was written.

## Authority requests

As of 2026-11-22: **no request** from a court, a police or intelligence service, or any other authority has
been received, for data or for a change to the relay. No gag order applies to this statement.

| Period | Requests received | Answered with data | Accounts or devices concerned |
|---|---|---|---|
| 2026-11-21 (start of service) to 2026-11-22 | 0 | 0 | 0 |

Each request will be added here as a count, at the latest with the next release after it arrives, and as
far as the law allows its type (for example a court order for subscriber data) and the outcome.

## How a request is handled

- Requests go to privacy@healthlog.dev. Only a request with a legal basis that binds the operator in
  Germany is answered; an informal or foreign request without that basis gets no data.
- Each request is checked for its basis and its scope. An overbroad request is narrowed or contested, and
  nothing is handed over that the request does not name.
- What the relay can hand over is limited by design to what [privacy.md](privacy.md) section 5 lists. It
  holds no notification content and cannot decrypt any; it holds no raw device token, no IP address, no time
  of day, no user name and no host name of an instance. For a device it has only a token HMAC, an instance
  id, a key hash and day numbers. In memory it briefly holds a little more (privacy.md, end of section 5),
  which is gone within days at most.
- No change to the code or the deployment is made to collect more for anyone. A demand to log, to keep data
  longer or to send content would be contested. The code that runs is the signed release image; anyone can
  check its signature and provenance ([release-verification.md](release-verification.md)).
- The operator of an affected HealthLog instance is told about the request, unless the law forbids it.
  The relay cannot tell a person directly, because it does not know who they are.
- Apple delivers every push and can be asked directly; the relay has no influence on that. What Apple sees
  is listed in [threat-model.md](threat-model.md#what-the-relay-sees-and-what-apple-sees).

## Metrics the operator sees

The relay counts its own work and nothing else. The table below is every metric it exposes, the whole of
what the operator can see about the relay's traffic in monitoring; a test in the repository fails if the code
registers a metric that is not in this table. No metric carries an instance id, a device, a token, a topic,
an address, a version of anyone's software or any content, and no metric is per instance, per device or per
person. Every label takes its value from a short fixed list written into the code, and a second test fails if
a label outside that list appears. There is no time-of-day breakdown: the only time is the moment of each
scrape.

`/metrics` listens on `127.0.0.1:9464` on the relay host and is never reachable from the internet. The last
column of the table says how current each metric is, and a test fails if it disagrees with the code:

- **live**: the value at the moment of the scrape. Only seven metrics are live: HTTP responses by status
  class, requests to Apple all kinds together, Apple's refusals by reason, the delivery latency, and the three
  gauges that say whether the relay itself is healthy (breaker, provider token, store). The operator's
  monitoring therefore shows when a request reached the relay, when a push went to Apple and how long Apple
  took, so a delivery problem is visible within a minute. It never shows for which instance or device, and
  it does not show the class or kind of that push. While only very few instances use the relay this is still
  a trace of their traffic in time, in aggregate: with a single active instance, every live count is that
  instance's.
- **every 5 min**: every other metric is shown from a copy taken every five minutes, at every number of
  instances. That covers every split by push class or kind (alert, silent sync, wake, Live Activity start,
  update and end, Live Activity priority), the key slot, the silent budget refusals by type, and the figures
  about who is registered (instances per tier, bindings per state, the usage figures). The moment one instance
  registers, one device binds or a push of one kind passes cannot be read off the scrape. A metric the code
  adds later is held unless it is named live in the code, and then this table has to say so. A tier with
  fewer than three instances is not shown on its own, because that would say which tier a single instance is
  in: its instances are counted under `tier="other"`, and the tier itself reads zero. `admin stats` on the
  relay host keeps the exact sums.

Releases up to 1.0.3 refreshed every value only once an hour while fewer than 20 instances were active. That
hid the timing, and with it every failed or slow delivery, for up to an hour.

The operator's monitoring keeps the scraped values for **6 months**, then deletes them.

| Metric | What it counts | Labels | Why it exists | Refreshed |
|---|---|---|---|---|
| `hlp_push_total` | push items by outcome | `class` (alert, silent, liveactivity), `result` (accepted, a refusal or an Apple outcome) | whether pushes get through, and which limit or answer stops them | every 5 min |
| `hlp_apns_requests_total` | requests the relay sends to Apple, every kind together | none | whether and when pushes go to Apple, without saying which kind | live |
| `hlp_apns_sends_total` | requests the relay sends to Apple | `kind` (alert, silent_sync, silent_wake, la_start, la_update, la_end) | which kind of push the load comes from; `silent_wake` is the relay's own challenge push, `silent_sync` a background push an instance sends | every 5 min |
| `hlp_delivery_latency_seconds` | time from the relay accepting an item to Apple's answer, in nine coarse buckets (0.05 s to 10 s) | none | how long delivery takes, and whether it is slowing down | live |
| `hlp_apns_rejections_total` | Apple's refusals | `reason` (Apple's documented reason codes, anything else as `other`) | telling a relay defect from a token problem | live |
| `hlp_liveactivity_priority_total` | Live Activity pushes | `priority` (10, 5) | checking that only due doses use the device's priority 10 budget | every 5 min |
| `hlp_push_retries_total` | items an instance sent again under a ref the relay still remembered | `answer` (replayed, joined) | whether instances retry too eagerly | every 5 min |
| `hlp_queue_depth` | jobs waiting in the send queue | none | capacity | every 5 min |
| `hlp_queue_dropped_total` | jobs dropped after waiting too long in the queue | none | capacity | every 5 min |
| `hlp_silent_budget_refused_total` | background pushes refused by a silent budget | `kind` (sync: the device's hourly budget or a relay-wide pause; wake: the once-a-day challenge) | seeing whether the budgets are too tight or are being pressed | every 5 min |
| `hlp_silent_paused_total` | times silent pushes were paused for everyone after Apple throttled | none | an alarm about Apple throttling | every 5 min |
| `hlp_rate_limited_total` | requests refused by a rate limit | `surface` (instance_requests, registration, app_global, app_device, push) | which limit is hit, without saying by whom | every 5 min |
| `hlp_deliveries_by_key_slot_total` | accepted deliveries | `slot` (current, next, emergency, unpinned) | confirming during a key rotation which pinned identity key the relay runs with | every 5 min |
| `hlp_registrations_total` | new registrations | `result` (created, limited) | growth and the registration caps | every 5 min |
| `hlp_registrations_rejected_total` | refused new registrations | `reason` (no_invite, bad_signature, rate_limited) | seeing misconfigured servers and probing | every 5 min |
| `hlp_auth_failures_total` | requests with a wrong signature, counted at a capped rate | `reason` (bad_signature) | seeing misconfigured servers and probing | every 5 min |
| `hlp_bindings_total` | binding events | `result` (bound, conflict, challenge_resolved, opt_out_lifted, unbound_instance, unbound_self, liveactivity_consent, liveactivity_consent_withdrawn) | whether binding works | every 5 min |
| `hlp_challenges_total` | challenge pushes sent | `result` (Apple's classified outcome) | whether conflict challenges reach devices | every 5 min |
| `hlp_invalid_budget_exceeded_total` | times an instance exceeded its invalid-token budget | none | an abuse alarm; which instance it was is only in the admin socket | every 5 min |
| `hlp_requests_total` | HTTP responses | `status` (2xx, 4xx, 5xx) | error rates | live |
| `hlp_body_budget_refused_total` | requests refused because the budget for request bodies in flight was full | none | flood detection | every 5 min |
| `hlp_connections_rejected_total` | connections refused at the connection caps | none | flood detection | every 5 min |
| `hlp_http_errors_total` | error lines of the HTTP server, discarded because they carry addresses | none | noticing TLS scans without logging addresses | every 5 min |
| `hlp_breaker_open` | 1 while the token-failure breaker is open or half-open | none | an alarm | live |
| `hlp_apns_misconfigured` | 1 while Apple rejects the relay's provider token | none | an alarm | live |
| `hlp_db_writable` | 1 while the store accepts writes | none | an alarm | live |
| `hlp_instances` | instances | `tier` (probation, standard, suspended, revoked, other: every tier with fewer than three instances, so that no value names the tier of a single instance) | growth and the tiers, as in `admin stats` | every 5 min |
| `hlp_bindings` | bindings | `state` (provisional, active, soft_invalid) | the same sum as `admin stats` | every 5 min |
| `hlp_usage_active_instances` | probation and standard instances | none | the usage figures of [privacy.md](privacy.md) section 6 | every 5 min |
| `hlp_usage_instances_pushed` | instances with an accepted push in the window | `window` (7d, 30d) | usage figures | every 5 min |
| `hlp_usage_active_bindings` | active and soft-invalid bindings | none | usage figures | every 5 min |
| `hlp_usage_pushes_yesterday` | pushes of the last completed day | `class` | usage figures | every 5 min |
| `hlp_usage_outcomes_yesterday` | outcomes of the last completed day | `outcome` (accepted, soft_failed, unregistered) | usage figures | every 5 min |
| `hlp_usage_registrations_last_week` | registrations in the last completed week | none | usage figures | every 5 min |
| `hlp_usage_opt_outs_last_week` | direct opt-outs in the last completed week | none | usage figures | every 5 min |

## Rotations and deprecations

**Key rotations are announced here at least 7 days ahead.** A rotation of the relay identity key (the key
that HealthLog servers and the app pin) is listed below with its date at least 7 days before the relay
signs with the new key; the incoming key is pinned in released server and app builds before that
([key-ceremony.md](key-ceremony.md), [operations.md](operations.md#relay-identity-key)). The one exception
is an emergency rotation after a suspected compromise of the relay process: it happens at once and is
listed here and announced through the relay notice the same day. A rotation of the APNs key, the token MAC
key or the ACME account key is not visible to clients and is listed here after it happened.

Deprecations of an endpoint, a field or a behaviour that clients rely on are listed here with the release
that announces them and the release that removes them, before the removal. A shutdown of the hosted relay
is announced at least 90 days ahead (privacy.md section 12).

Newest first:

- **2026-11-22** Relay v1.0.4. No key rotation and no deprecation. Seven metrics are now current at every
  scrape and every other metric is refreshed every five minutes, as the table above says; until now every
  metric was refreshed hourly while fewer than 20 instances were active. Privacy notice version 1.3 says so,
  and that an instance that never delivered a notification is now deleted once it has been out of contact
  for more than 30 days, instead of two days after registration.
- **2026-11-22** Correction. Earlier versions of this page, the README and the key ceremony said the
  `emergency` identity key is kept offline. The accurate statement is: it is held separately from the relay
  host and from the operational keys, and it is never deployed to the relay. The key and its use are
  unchanged.
- **2026-11-22** Relay v1.0.3. No key rotation and no deprecation. The relay exposes more metrics about its
  own work, all listed above. The release binaries carry SLSA provenance
  ([release-verification.md](release-verification.md)).
- **2026-11-22** Relay v1.0.2. A third identity key is published: `emergency`
  `dcrihMfqGY7srT95DZrVP7sKA-IS3oJPPhOVbbqTvBU`, held separately from the relay host and from `current` and
  `next`, for the case that both are lost. It is pinned beside them; the relay keeps signing with
  `current`. No deprecation. Live Activity pushes now go with Apple priority
  5 unless the dose is due or overdue or the activity ends; a stale `410` from Apple is answered as
  `soft_invalid` with reason `Unregistered` instead of deleting a binding made after it.
- **2026-11-21** Relay v1.0.1. The SLSA provenance moved to the SLSA v1 Sigstore bundle; the provenance of
  v1.0.0 stays in the older `.att` format and needs `--new-bundle-format=false` with cosign 3
  ([release-verification.md](release-verification.md)). New stores start with invite-only registration.
- **2026-11-21** Relay v1.0.0, start of the hosted service. Identity keys published: `current`
  `IU8JGZzcE-O4gp4q2BL2o6YYNJeHyDg8MNmAGL5_Ypo`, `next` `kPhnCqIwrF_cyQIFTAgCHrWnPavdWkcwMB35oi_wCH0`
  (also in [`keys/push.healthlog.dev.json`](../keys/push.healthlog.dev.json)). No rotation is planned.
