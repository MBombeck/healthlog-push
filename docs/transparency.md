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

- **2026-11-22** Relay v1.0.2. A third identity key is published: `emergency`
  `dcrihMfqGY7srT95DZrVP7sKA-IS3oJPPhOVbbqTvBU`, generated offline and kept apart from `current` and
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
