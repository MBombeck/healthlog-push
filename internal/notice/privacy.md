# Privacy notice of the HealthLog push relay

Version 1.4, 2026-11-24 (consent text version `2026-11-21`). Served by the relay itself at https://push.healthlog.dev/privacy; this text is the
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

The relay only carries what a registered server sends to its own bound devices. The operator never sends
anything through it: no announcements, no update notices, no messages of any kind. The only push the relay
creates itself is the silent check it sends when two keys claim the same device, which carries a random
value and nothing you can read; news about the relay reaches HealthLog servers in its answers to them,
never your device.

Using the relay is voluntary. The operator of a HealthLog server first switches it on for the server, then
every person decides in their own app. The app creates its keys and asks for a binding only after you
agree. Without it the app works as before; only the relay notifications are missing.


## 3. What the relay never sees

Medication names, doses, readings, notes, journal text, user names, e-mail addresses, account data, the host
name of your HealthLog server, the encryption key of your device, or any plaintext of a notification.
Without the separate Live Activity consent (section 4) it never sees the content of a Live Activity either.


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
  binding conflict challenge, and when you withdraw the Live Activity consent directly. It is not stored
  and not logged.
- For every notification: its class (alert, background, or Live Activity start, update or end), its
  lifetime, its size, which is fixed per class, and the time it was sent.
- A Live Activity token, only at the moment the activity is ended, unless you give the Live Activity
  consent below.
- Counts that HealthLog servers report about delivery (how many accepted notifications a device confirmed).
  These are numbers only, without any id.

**Live Activity consent.** The app can show the next dose as a Live Activity on the lock screen. If you
want your HealthLog server to start and update it through the relay, the app asks for a second, separate
consent. Apple's Live Activities cannot decrypt anything, so the content state of a start or an update
travels in the clear. With this consent the relay and Apple see that content state: when a dose is due and
its state (pending, due, overdue, snoozed, taken or skipped), whether it is overdue, confirmed or waiting for
confirmation, the countdown time and the time format of the display. They never see a medication name, a
dose or any free text: the relay forwards only this fixed set of six fields with fixed values and refuses
anything else. With this consent the relay also sees the token your app uses to start Live Activities and
the token of each running activity, while it sends to them. Without this consent nothing changes: your
server can only end an activity, and the relay sees nothing of its content. You can withdraw this consent at
any time in the app; the app then tells the relay directly, without your HealthLog server, and starts and
updates over the relay stop at once.

**Apple Wallet passes.** Your HealthLog server can offer your emergency card as an Apple Wallet pass. The
pass must be signed with the HealthLog project's Apple certificate, so your server asks the relay for that
signature. It sends only the list of the pass's files with a hash of each (`manifest.json`), never a file:
the relay does not see your name, your health data, the link in the QR code or the pass's serial number.
The relay sees which server asked and when. When your pass changes, your server asks the relay to tell
Wallet on your devices; the relay then sees the pass push token Wallet gave your server for that device and
the time, forwards an empty message to Apple and keeps nothing of it except, in memory, a count per token
for the push limit. This service is offered only once the relay operator has set it up.

To be open about it: the relay cannot read content, but time patterns can say something about health. The
time of a notification, and its class, can reveal for example that a dose was recorded on another of your
devices at that moment. The relay is designed to keep as little of this as possible, as described below.


## 5. What the relay stores, and for how long

All times in the relay's database are day or week numbers (UTC), never a time of day.

- Device binding: the HMAC of your device token (keyed with a secret of the relay), the instance id of your
  server, a SHA-256 hash of the binding key your app created, a sequence number, the APNs environment, the
  state (provisional, active or soft-invalid), the day of binding, the week of last use, the day of the last
  accepted notification, the version of the consent text you accepted and the day you accepted it, the
  number of alerts sent to the device today, and, only if you gave the Live Activity consent, the version of
  that consent text and the day you gave it. The relay stores nothing of a Live Activity's content state and
  none of its tokens.
  The Live Activity consent lives and dies with the binding: it is deleted when you withdraw it, when your
  server drops it, when the binding changes to another key or another server, and with the binding itself.
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
  contact, or, if it never delivered a notification, once it has been out of contact for more than 30 days
  (an operator still setting up, whose server keeps checking in, is not deleted). The record of a
  suspended or revoked server is kept for 365 days after the suspension or revocation, so that the same key
  cannot simply register again in that time.
- Per-server day counters: notifications sent, invalid tokens and device moves, without class. Kept for
  7 days, used for limits and abuse detection.
- Relay-wide day counters: per day, notification class and result, the number of notifications; per day,
  the number of registrations and of opt-outs; the busiest minute of the day. No instance id, no device.
  Kept for 400 days.
- Operator state: pauses, registration mode, the current notice, the recovery window and one-time
  registration codes (as hashes). No personal data.
- Wallet signing ledger: for every pass signature, a SHA-256 hash of the file list, the instance id of the
  server that asked and the day. Kept for 400 days, so that a misused pass can be traced to the server that
  had it signed. It is not in the backup, not in any log or metric, and only the operator can look it up.
  It cannot be turned back into the file list or into anything about you.

Kept in memory only, gone at the latest on restart: the device token during a request, the nonces of recent
requests, recent push results for retries (for the lifetime of the notification, at least 10 minutes and at
most 6 hours), per-device rate counters, the update counters of
each running Live Activity (keyed by an HMAC of its token, cleared at the end of each UTC day), the hashed address
counters of the registration limit (reset daily), pending conflict challenges (30 minutes), the time of a
direct opt-out (10 minutes), and delivery traces (72 hours). A delivery trace is the identifier Apple
assigns to one notification (`apns-unique-id`) with its result, keyed by the instance id and the
notification's reference chosen by your server; it lets the operator look up a single lost notification in
Apple's delivery log. Apple sends this identifier only for development builds of the app, so notifications
to the App Store and TestFlight app leave no trace. Traces are never stored, backed up or logged. For
Wallet passes, also in memory only: the pass push token while a push is processed, a count per token
(keyed by an HMAC of it, cleared at the end of each UTC day) and the result of each pass push for 10 minutes,
so that a repeated request is not sent twice.

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

The relay host also exposes metrics to the operator's monitoring. They are counts without any server,
device or person in them. A few of them are current: the requests the relay answered, the notifications it
passed to Apple (all kinds together), Apple's refusals and how long Apple took to answer. So the operator's
monitoring shows at what time a notification passed through the relay and how long Apple took to accept it.
It does not show which server sent it, which device it went to, what kind of notification it was or what it
said. While only very few servers use the relay, these current counts still reflect their traffic in
aggregate: with a single active server, they are that server's. Every other figure, among them every count
by kind of notification and the figures about registered servers and bound devices, is refreshed only every
five minutes, and a tier with fewer than three servers is counted together with the others. The monitoring
keeps these values for 6 months.


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
  the app's topic, and can link the token to an Apple account. With the Live Activity consent, Apple also
  receives the content state of each Live Activity start and update in the clear (section 4). For a Wallet
  pass update, Apple receives the pass push token, the time and an empty message. Apple acts as an
  independent controller; see Apple's own privacy policy.
- Hosting: Hetzner Online GmbH, Germany, as processor under a data processing agreement (Art. 28 GDPR). The
  relay runs on a dedicated cloud server in a data centre in Falkenstein, Germany. Hetzner sees network
  connections to the server, not their content.
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
- Starting and updating Live Activities through the relay, with their content state in the clear: your
  separate Live Activity consent (Art. 6(1)(a) and Art. 9(2)(a) GDPR), given in the app and recorded with
  the version of its text and the day. You can withdraw it at any time.
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
  consent, and, if given, the version and day of the Live Activity consent.
- Withdrawal of the Live Activity consent: switch Live Activities over the relay off in the app. The app
  sends a signed request directly to the relay (DELETE /v1/bindings/self/liveactivity), and the relay
  deletes the consent at once, without the cooperation of your HealthLog server. Your binding and the
  relay notifications stay.
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
the name of the app on a device whose token passed through the relay. With a Live Activity token that
passed through the relay, they could also show a misleading state in your Live Activity, for example a dose
as taken that was not; the app's Live Activity can display only the fixed fields described in section 4,
never a free text. Reminders on your device stay authoritative. They cannot read your data, and the
HealthLog app is built to take no action on a notification it cannot decrypt and verify.

We cannot prove which code runs on the relay. That is why it is built so that it cannot read your content,
whatever code runs. The relay reports its version and image digest at https://push.healthlog.dev/version;
the release images are signed, and the README of the source repository shows how to verify a signature
with cosign. That answer still comes from the server itself.


## 12. Changes, data breaches and shutdown

A new version of this notice gets a new version number and date.

Requests from authorities (none so far), how they are handled, and every deprecation and key rotation are
published in the transparency report:
https://github.com/MBombeck/healthlog-push/blob/main/docs/transparency.md. Rotations of the relay's identity
key are announced there at least 7 days ahead. HealthLog servers receive a notice
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
operator of critical services under German KRITIS rules. Hetzner hosts the relay as a processor: a data
processing agreement under Art. 28 GDPR between the operator and Hetzner Online GmbH was concluded on
2026-11-22. Hetzner publishes its technical and organisational measures and its sub-processors. The relay
server and its backups are hosted in Germany.

These are Hetzner's own statements, checked on 2026-11-21 against Hetzner's published pages:

- https://www.hetzner.com/unternehmen/zertifizierung/
- https://docs.hetzner.com/general/company-and-policy/information-security-at-hetzner/
- https://www.hetzner.com/de/news/hetzner-receives-bsi-c5-certification/
- https://docs.hetzner.com/general/general-terms-and-conditions/data-privacy-faq/
- https://www.hetzner.com/AV/subunternehmer.pdf

How the host itself is hardened is described in
[docs/hardening.md](https://github.com/MBombeck/healthlog-push/blob/main/docs/hardening.md).
