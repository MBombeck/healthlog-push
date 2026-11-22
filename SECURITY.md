# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through one of these channels:

- Email **relay@healthlog.dev** with a subject line starting with `[security]`.
- GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**.

A useful report contains the affected version or commit, the component (relay, signer, admin interface, spec), steps to reproduce, and the impact you expect. If you have a proof of concept, include it. Never include real instance ids, device tokens or keys from a live system; synthetic values are enough.

## Scope

In scope:

- The relay and signer code in this repository (`cmd/`, `internal/`).
- The protocol specification and test vectors (`spec/`), including weaknesses in the design itself.
- The container image `ghcr.io/mbombeck/healthlog-push` and the release artefacts (signatures, SBOM, provenance).
- The hosted relay at `push.healthlog.dev`.

Out of scope:

- The HealthLog server and apps. Report those to the HealthLog project.
- Apple Push Notification service itself, and other third-party services the relay talks to.
- Volumetric denial of service against the hosted relay, and load testing it. Please test against your own instance.
- Findings that need a compromised host, root on the server, or physical access to a device.
- Missing hardening headers or best-practice notes without a demonstrated impact.
- Social engineering, and anything touching other users' data. Do not access, modify or delete data that is not yours.

## What to expect

This project is maintained by one person. The times below are goals, not promises:

- Acknowledgement of your report within 3 working days.
- A first assessment within 10 working days.
- A fix or mitigation for a confirmed high-severity issue as fast as is practical, usually within 30 days.

You will be kept informed while the issue is open, and credited in the release notes if you wish.

There is no bug bounty.

## Coordinated disclosure

Please give us 90 days from your report before publishing details, or until a fixed release is out, whichever comes first. If a fix needs longer, we will tell you why and agree on a new date with you. If an issue is being exploited in the wild, we may publish earlier together with a fix.

## Supported versions

Only the latest release is supported. It receives bug fixes and security fixes until the next release is published; from that day the older release receives nothing, and there are no long-term support branches and no backports. Support means fixes in a new release. It does not include help with individual installations beyond the issue tracker.

Updating is the upgrade path: pull the new image or binary and restart ([docs/operations.md](docs/operations.md#deploy)). A release that needs a manual step says so in [CHANGELOG.md](CHANGELOG.md).

## Publication and credit

Every fixed vulnerability is listed under "Security" in [CHANGELOG.md](CHANGELOG.md) for the release that fixes it. A vulnerability that affects people who run a released version is also published as a GitHub Security Advisory on this repository, with the affected versions, how to tell whether an installation is affected, and what to do. Reporters are credited in both places unless they ask not to be named.

## Findings from automated analysis

**Dependencies.** `govulncheck` runs on every pull request and every push to `main`, and Dependabot watches the Go modules, the base images and the GitHub Actions. The threshold is zero: a known vulnerability in code the relay can reach blocks the merge, whatever its severity, and no release is tagged while one is open. A vulnerable dependency that the relay does not reach is updated with the next regular update. A new dependency is accepted only under the rules in [docs/dependencies.md](docs/dependencies.md), which exist to keep malicious or abandoned code out; a pull request that adds a module without its entry is not merged.

**Licenses.** Dependencies must be under a permissive license compatible with Apache-2.0 (Apache-2.0, MIT, BSD, ISC). Anything else is refused at review.

**Static analysis.** CodeQL with the `security-and-quality` queries and golangci-lint with `gosec` run on every pull request and are required for a merge. The threshold is zero here as well: an alert is fixed before the merge. An alert may be dismissed only as a false positive or as not exploitable, with the reason written into the alert, and for a security rule also into the changelog.

**Before a release.** The release is tagged from a commit on `main` whose checks are green, so every rule above holds for what is released.

## Secrets and credentials

**The project.** The repository stores no secrets. The workflows sign and publish with short-lived tokens that GitHub issues per job, and releases are signed keyless, so there is no signing key to store, rotate or lose. Should a long-lived credential ever be needed, it is stored as a secret of the `release` environment, readable only by the job that needs it, rotated at least once a year and at once on any suspicion, and never written to the repository, a log or an artefact. GitHub secret scanning with push protection is enabled, and `.gitleaks.toml` configures a local scan.

**Access.** Who can reach which sensitive resource is listed in [MAINTAINERS.md](MAINTAINERS.md). Accounts with access use two-factor authentication.

**The hosted relay.** Its keys, who may read them, and when they are rotated or revoked are described in [docs/key-ceremony.md](docs/key-ceremony.md).

The argument for why the design meets its security requirements, with the evidence, is the assurance case in [docs/assurance-case.md](docs/assurance-case.md).

## Verifying a release

Every release is built by the release workflow from a `vX.Y.Z` tag on `main`. The image is signed keyless with cosign and carries an SBOM attestation and SLSA provenance; the release binaries come with a signed `SHA256SUMS` and, from v1.0.3 on, SLSA provenance of their own. The commands to check all of it are in [docs/release-verification.md](docs/release-verification.md). Verify before you run a release, and report anything that does not verify as a vulnerability.

## Build pipeline

Actions in the workflows are pinned to full commit SHAs. The one exception is the SLSA generator that signs the binary provenance (`slsa-framework/slsa-github-generator`, `generator_generic_slsa3.yml@v2.1.0`): it must be referenced by its release tag, because `slsa-verifier` checks the builder reference against the generator's release tags and the generator does not run from a commit SHA. Workflow tokens start without permissions, and each job is granted only what it needs. Details: [docs/release-verification.md](docs/release-verification.md#how-the-pipeline-is-protected).
