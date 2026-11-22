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

Only the latest release receives security fixes.

## Verifying a release

Every release is built by the release workflow from a `vX.Y.Z` tag on `main`. The image is signed keyless with cosign and carries an SBOM attestation and SLSA provenance; the release binaries come with a signed `SHA256SUMS` and, from v1.0.3 on, SLSA provenance of their own. The commands to check all of it are in [docs/release-verification.md](docs/release-verification.md). Verify before you run a release, and report anything that does not verify as a vulnerability.

## Build pipeline

Actions in the workflows are pinned to full commit SHAs. The one exception is the SLSA generator that signs the binary provenance (`slsa-framework/slsa-github-generator`, `generator_generic_slsa3.yml@v2.1.0`): it must be referenced by its release tag, because `slsa-verifier` checks the builder reference against the generator's release tags and the generator does not run from a commit SHA. Workflow tokens start without permissions, and each job is granted only what it needs. Details: [docs/release-verification.md](docs/release-verification.md#how-the-pipeline-is-protected).
