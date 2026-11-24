# Roadmap

What healthlog-push intends to do over the coming year, and what it does not intend to do. A roadmap is a
statement of direction: items can move or be dropped, and this file changes in the same pull request when
they do. It is reviewed at least once a year.

## Direction

healthlog-push exists for one purpose: a self-hosted HealthLog server can send push notifications to the
HealthLog iOS app without an Apple developer account, and the relay in between cannot read them. Since
Wallet passes (spec/wallet.md), it also signs Apple Wallet passes of a HealthLog server's emergency card
without seeing their content: the server sends a list of file hashes, the HealthLog brand images are
pinned, and the pass itself never leaves the server. The relay should stay small enough that one person
can read all of it.

## Done in v1.0.3

- Aggregate metrics about the relay's own work, with the public list of every metric in
  [transparency.md](transparency.md#metrics-the-operator-sees) and a test that keeps the list and
  the code in step.
- SLSA provenance for the release binaries ([release-verification.md](release-verification.md)).
- A stricter golangci-lint configuration.

## Done in v1.0.4 to v1.0.8

- Public day aggregates at `/stats` with a floor of three servers ([api.md](api.md#get-stats)), served by
  the hosted relay since 2026-11-24.
- One build recipe for the release binaries and the image, a CI job that builds every change both ways and
  compares the results, and `scripts/verify-release.sh`, which checks a release from public sources
  ([verify.md](verify.md)).
- A watchdog that ends a hung relay or signer so the restart policy brings it back, and a PING that finds
  a silent connection to Apple within two minutes.

## Next

- Wallet passes in service: the pinned hashes of the final HealthLog artwork, the Pass Type ID certificate
  of the hosted relay and the deployment of the `wallet` process. Until then the code is in place and off.
- The first full drill of the emergency path (throwaway APNs key, `next` identity key, restore from a signed
  registry export) by 2027-01-31, then once a year ([key-ceremony.md](key-ceremony.md#drill)).

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
