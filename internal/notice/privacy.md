# Privacy notice of the HealthLog push relay

Version 1.0, 2026-11-21 (consent text version `2026-11-21`). Served by the relay itself at https://push.healthlog.dev/privacy; this text is the
authoritative one. Earlier versions are kept in the source repository
(https://github.com/MBombeck/healthlog-push, file internal/notice/privacy.md).


## 1. Who is responsible

The controller is the maintainer of the HealthLog project, who operates the hosted relay at
push.healthlog.dev.

- Data protection: privacy@healthlog.dev
- Abuse reports and appeals: abuse@healthlog.dev
- Operation and security reports: relay@healthlog.dev


## 2. What the relay is for, and what it is not

The relay forwards notifications from privately self-hosted HealthLog servers to the HealthLog iOS app
through Apple Push Notification service (APNs). The content of each notification is encrypted on your
HealthLog server for your device. The relay cannot decrypt it.

The hosted relay is for household use only: a person, or a family, running a HealthLog server for
themselves. It is not offered to organisations.

The relay is not a medical service. It does not remind you of anything by itself, and a notification can be
late or lost. Reminders that the app schedules on your device stay the authoritative reminder path.

Using the relay is voluntary. The operator of a HealthLog server first switches it on for the server, then
every person decides in their own app. The app creates its keys and asks for a binding only after you
agree. Without it the app works as before; only the relay notifications are missing.


## 3. What the relay never sees

Medication names, doses, readings, notes, journal text, user names, e-mail addresses, account data, the host
name of your HealthLog server, the encryption key of your device, the content of a Live Activity, or any
plaintext of a notification.


## 4. What the relay sees

- Your device's APNs token, while a request is processed. At rest the relay keeps only an HMAC of it (see
  section 5).
- The instance id of your HealthLog server, its public signing key and the server software name and version
  it reported at registration.
- The IP address of your HealthLog server when it connects. It is held in memory only: hashed with a salt
  that changes every day for the registration limit, and as the address (IPv4) or the /64 and /48 prefixes
  (IPv6) of an open connection for the connection limit. It is not stored and not logged.
- The IP address of your device when your app talks to the relay directly: when you switch the relay off or
  leave a server (opt-out), when you read what the relay holds about you, and when your app answers a
  binding conflict challenge. It is not stored and not logged.
- For every notification: its class (alert, background, or Live Activity end), its lifetime, its size,
  which is fixed per class, and the time it was sent.
- A Live Activity token, only at the moment the activity is ended.
- Counts that HealthLog servers report about delivery (how many accepted notifications a device confirmed).
  These are numbers only, without any id.

To be open about it: the relay cannot read content, but time patterns can say something about health. The
time of a notification, and its class, can reveal for example that a dose was recorded on another of your
devices at that moment. The relay is designed to keep as little of this as possible, as described below.


## 5. What the relay stores, and for how long

All times in the relay's database are day or week numbers (UTC), never a time of day.

- Device binding: the HMAC of your device token (keyed with a secret of the relay), the instance id of your
  server, a SHA-256 hash of the binding key your app created, a sequence number, the APNs environment, the
  state (provisional, active or soft-invalid), the day of binding, the week of last use, the day of the last
  accepted notification, the version of the consent text you accepted and the day you accepted it, and the
  number of alerts sent to the device today.
  Deleted when you opt out, when your server removes it, when your server unregisters or is revoked, when
  Apple reports the token as no longer valid, when the binding has had no notification for about 90 days
  (13 weeks), or when it is still provisional more than two days after it was created.
- Opt-out block: after you opt out directly, a keyed hash of the pair of your device token and that
  server's instance id, with the day, a hash of your app's binding key and the sequence number of the
  binding you left. Kept for 365 days, so that this server cannot bind your device again unless you turn the
  relay on for it again in the app. Neither your token nor its HMAC can be read back from the hash. The exact
  time of your opt-out is kept in memory for 10 minutes only, never stored.
- Opt-out key pin: with the same opt-out, a keyed hash of your device token alone, with the day and the
  hash of your app's binding key. Kept for 365 days, so that no other server, for example a second one
  registered by the operator you left, can bind your device with a key your app does not hold: such a
  binding needs a confirmation that only your app can give.
- Token block: a keyed hash of a token the operator blocked against abuse, with the day. Kept for 365 days.
- HealthLog server (instance): instance id, public key, tier, for a suspended or revoked server the reason
  from a fixed list and its day, the day of registration, the week of last contact, its device limit, the
  day of its first and of its last accepted notification, the day of its last key rotation, and the last day
  it was flagged for an anomaly (a conflict challenge or too many invalid tokens).
  Deleted together with all its bindings when the server unregisters, after about 90 days (13 weeks) without
  contact, or more than two days after registration if it never delivered a notification. The record of a
  suspended or revoked server is kept for 365 days after the suspension or revocation, so that the same key
  cannot simply register again in that time.
- Per-server day counters: notifications sent, invalid tokens and device moves, without class. Kept for
  7 days, used for limits and abuse detection.
- Relay-wide day counters: per day, notification class and result, the number of notifications; per day,
  the number of registrations and of opt-outs; the busiest minute of the day. No instance id, no device.
  Kept for 400 days.
- Operator state: pauses, registration mode, the current notice, the recovery window and one-time
  registration codes (as hashes). No personal data.

Kept in memory only, gone at the latest on restart: the device token during a request, the nonces of recent
requests, recent push results for retries (10 minutes), per-device rate counters, the hashed address
counters of the registration limit (reset daily), pending conflict challenges (30 minutes) and the time of a
direct opt-out (10 minutes).

The daily backup contains only the list of registered servers and the blocks: instance id, public key,
tier, reason and its day, day of registration, device limit and day of first delivery; for each opt-out
block, each opt-out key pin and each operator token block only a keyed hash, the reason code
(`device_opt_out`, `device_opt_out_pin` or `operator_block`) and the expiry day. It carries no binding key
hash. Entries older than 365 days are not exported. The backup contains no device bindings, no tokens or
token HMACs and no counters. It is signed with the relay's key, and the relay refuses a backup that was
changed. Opt-outs and pins are in the backup so that a restore can never silently let a server you left
reach your device again, and abuse blocks stay in force.


## 6. Usage figures

The relay keeps no statistics per person. The usage figures its operator can see are counts only, and they
cover only completed days and weeks:

- the number of active servers, and of servers that sent a notification in the last 7 and 30 days;
- the number of active device bindings;
- per completed day, the number of notifications by class, and how many Apple accepted, reported as no
  longer valid, or refused softly;
- per completed week, the number of new server registrations and of opt-outs.

To handle abuse, the operator can also list, on the relay host only, the servers that had invalid device
tokens, moved bindings or conflict challenges in the last 7 days, with their counts. This list is shown on
request, never logged or exported.

The same counts are available as metrics on the relay host. While fewer than 20 servers are active, the
metrics are refreshed only once an hour, so that the traffic of a single server cannot be read off them.


## 7. Logs

The relay keeps no access log. It logs operational events (a start, a storage problem, an operator command)
by type only, and its log lines have a fixed set of fields, none of which can hold an IP address, a device
token, a token HMAC or an instance id. Registrations, key rotations, server deletions and resolved binding
conflicts get no log line of their own; they are counted in the periodic totals. Totals (number of
notifications, errors by reason, these event counts, latency) are written every minute while at least 20
servers are active, otherwise every hour.
Error messages of the underlying HTTP and TLS libraries, which can contain addresses, are counted and
discarded. On the relay host, logs are limited to three files of 10 MB each.


## 8. Who else receives data

- Apple. APNs delivers every notification. Apple receives the device token, the time, the type of push and
  the app's topic, and can link the token to an Apple account. Apple acts as an independent controller; see
  Apple's own privacy policy.
- Hetzner Online GmbH hosts the relay on a dedicated cloud server in a data centre in Falkenstein, Germany.
  Hetzner sees network connections to the server, not their content.
- The DNS provider of healthlog.dev answers name lookups for push.healthlog.dev. It does not see the traffic
  itself. If the name were redirected, whoever controls the new target would see the device tokens and
  request metadata of requests sent there in that time; they could not read content, and HealthLog servers
  reject answers that are not signed with the relay's key.
- The certificate authority (Let's Encrypt) issues the TLS certificate; it sees only the host name, which is
  published in public certificate logs anyway.

- Log and metric receivers operated by the maintainer receive the relay's logs and metrics. These hold
  counts and event types only (sections 6 and 7), no IP address, device token, token HMAC or instance id.
- The encrypted daily backup (section 5) is stored with a storage service in Germany.
- An external availability check reads the public health endpoint (https://push.healthlog.dev/healthz),
  which contains no personal data.

There is no advertising, no profiling and no automated decision about you.


## 9. Legal bases

- Delivering notifications to your device: your consent (Art. 6(1)(a) and Art. 9(2)(a) GDPR), given in the
  app, recorded with the version of the consent text and the day. You can withdraw it at any time.
- Limits, abuse prevention, suspensions and blocks: the legitimate interest in keeping the service usable and safe
  for everyone (Art. 6(1)(f) GDPR).
- Data about a HealthLog server (instance id, key, address in memory): the terms the server's operator
  accepted when switching the relay on (Art. 6(1)(b) GDPR), otherwise Art. 6(1)(f) GDPR.


## 10. Your rights, and how to use them yourself

You have the right of access, rectification, erasure, restriction, data portability and objection
(Art. 15 to 21 GDPR). The relay does not know who you are; it only knows a token HMAC and a key hash
(Art. 11 GDPR). That is why the app lets you exercise your rights directly:

- Access: in the app, under the relay settings, "My data at the relay". The app sends a request signed with
  its binding key (GET /v1/bindings/self). The relay answers with everything it holds about your binding:
  kind, instance id, state, environment, day of binding, week of last use, consent text version and day of
  consent.
- Erasure and withdrawal of consent: switch the relay off in the app, or leave the server. The app sends a
  signed request directly to the relay (DELETE /v1/bindings/self). The relay deletes the binding at once,
  without the cooperation of your HealthLog server, and blocks that server from binding your device again
  for 365 days, unless you turn the relay on for that server again in the app. For the same time no server
  can bind your device with a key your app does not hold without your app confirming it.

You can also write to privacy@healthlog.dev. Because the relay cannot identify you, include the instance id
your app shows; do not send a device token by e-mail.

You have the right to lodge a complaint with a supervisory authority, in particular the data protection
authority of North Rhine-Westphalia (Landesbeauftragte für Datenschutz und Informationsfreiheit
Nordrhein-Westfalen), or the authority where you live.


## 11. What the relay operator could do

Whoever holds the relay's Apple key (its operator, or someone who steals the key) can show notifications in
the name of the app on a device whose token passed through the relay. They cannot read your data, and the
HealthLog app is built to take no action on a notification it cannot decrypt and verify.

We cannot prove which code runs on the relay. That is why it is built so that it cannot read your content,
whatever code runs. The relay reports its version and image digest at https://push.healthlog.dev/version;
the release images are signed, and the README of the source repository shows how to verify a signature
with cosign. That answer still comes from the server itself.


## 12. Changes, data breaches and shutdown

A new version of this notice gets a new version number and date. HealthLog servers receive a notice
identifier from the relay when something important changes.

If a breach affects personal data, the relay informs all HealthLog servers through that notice, and the
maintainer publishes a statement on the project's public pages, because the people concerned are not known
to the relay.

If the hosted relay is shut down, this is announced at least 90 days in advance. After shutdown all data is
deleted and the relay's Apple key is revoked.


## 13. Hosting and certifications

The relay runs on Hetzner Cloud in a Hetzner Online GmbH data centre in Falkenstein, Germany. Hetzner states
that its data centre parks in Nuremberg, Falkenstein and Helsinki are certified to ISO/IEC 27001:2022 by
SOCOTEC Certification. Hetzner also states that it holds a BSI C5 Type 2 attestation (an attestation, not a
certificate) covering 1 February to 31 August 2025; it was issued by WP Koehler GmbH and covers Hetzner's
European sites, including its cloud servers and volumes. Hetzner states that the BSI classifies it as an
operator of critical services under German KRITIS rules. A data processing agreement under Art. 28 GDPR is
available under Hetzner's standard terms; Hetzner publishes its technical and organisational measures and its
sub-processors. The relay server and its backups are hosted in Germany.

These are Hetzner's own statements, checked on 2026-11-21 against Hetzner's published pages:

- https://www.hetzner.com/unternehmen/zertifizierung/
- https://docs.hetzner.com/general/company-and-policy/information-security-at-hetzner/
- https://www.hetzner.com/de/news/hetzner-receives-bsi-c5-certification/
- https://docs.hetzner.com/general/general-terms-and-conditions/data-privacy-faq/
- https://www.hetzner.com/AV/subunternehmer.pdf

How the host itself is hardened is described in
[docs/hardening.md](https://github.com/MBombeck/healthlog-push/blob/main/docs/hardening.md).
