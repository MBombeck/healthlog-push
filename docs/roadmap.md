# Roadmap

What healthlog-push intends to do over the coming year, and what it does not intend to do. A roadmap is a
statement of direction: items can move or be dropped, and this file changes in the same pull request when
they do. It is reviewed at least once a year.

## Direction

healthlog-push exists for one purpose: a self-hosted HealthLog server can send push notifications to the
HealthLog iOS app without an Apple developer account, and the relay in between cannot read them. The relay
should stay small enough that one person can read all of it.

## Done in v1.0.3

- Aggregate metrics about the relay's own work, with the public list of every metric in
  [transparency.md](transparency.md#metrics-the-operator-sees) and a test that keeps the list and
  the code in step.
- SLSA provenance for the release binaries ([release-verification.md](release-verification.md)).
- A stricter golangci-lint configuration.

## Next

- A scheduled rotation drill for the `next` identity key
  ([key-ceremony.md](key-ceremony.md#drill)).

## Ongoing

- Live Activity delivery refinements, as the HealthLog iOS app adds them.
- Protocol version 1 and envelope version 1 stay stable. A change to the wire format or to a cryptographic
  step comes as a new version with new test vectors.
- A second maintainer is welcome. Until there is one, the project says plainly that it has one
  ([GOVERNANCE.md](../GOVERNANCE.md)).

## Not intended

- **Reading or shaping notification content.** The relay will not gain a key that opens an envelope, and a
  server will not be able to set visible text. Both are security invariants
  ([security-invariants.md](security-invariants.md), C1 and C2), not missing features.
- **Per-server or per-device analytics.** No metric, log line or export will describe a single server,
  device or person beyond what [privacy.md](privacy.md) lists.
- **A service for organisations, or a service level agreement.** The hosted relay is for households and runs
  on a best-effort basis. Organisations run their own relay.
- **Maintenance of old releases.** Only the latest release receives fixes; there are no backports.
- **A bug bounty.**

## How to influence the roadmap

Open an issue and describe the problem you want solved. The maintainer decides
([GOVERNANCE.md](../GOVERNANCE.md)) and records the decision here when it changes the direction.
