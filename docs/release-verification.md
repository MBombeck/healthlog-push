# Release verification

What a release consists of, how anyone can check it, and the local rehearsal that exercises the same
pipeline before a tag is pushed.

## What a tag produces

The workflow `.github/workflows/release.yml` runs for a tag `vX.Y.Z` that points to a commit on `main`:

| Artefact | Where | Signed by |
|---|---|---|
| Multi-arch image (linux/amd64, linux/arm64) | `ghcr.io/mbombeck/healthlog-push:vX.Y.Z` | cosign keyless, identity `https://github.com/MBombeck/healthlog-push/.github/workflows/release.yml@refs/tags/vX.Y.Z` |
| SPDX SBOM | attestation on the image digest, type `spdxjson` | same identity |
| SLSA v1 build provenance | attestation on the image digest, type `slsaprovenance1` | the reusable workflow `.github/workflows/provenance.yml` at the same tag (GitHub's `attest-build-provenance`) |
| Linux binaries and `SHA256SUMS` | GitHub release | `SHA256SUMS.sigstore.json` bundle, same identity as the image |
| SLSA v1.0 provenance of the binaries and `SHA256SUMS` (from v1.0.3 on) | GitHub release, `healthlog-push_vX.Y.Z.intoto.jsonl` | the SLSA generic generator `generator_generic_slsa3.yml@refs/tags/v2.1.0` |

BuildKit runs pinned by digest, there is no emulation step, and the SBOM is generated in a job that has no
signing rights; only a separate job with `id-token: write` attests it. The provenance is signed in a reusable
workflow whose own path is the certificate identity, so nothing in the build job can produce a provenance that
verifies. Signature, SBOM and provenance are Sigstore bundles in the registry's referrers (on GHCR the
`sha256-<digest>` tag), the format cosign 3 reads by default.

## Checking a release

With cosign 3 (tested with v3.1.4), from v1.0.1 on, no format flag:

```sh
TAG=vX.Y.Z
IMAGE=ghcr.io/mbombeck/healthlog-push
DIGEST=$(crane digest "$IMAGE:$TAG")   # or the digest from the release notes
ID="https://github.com/MBombeck/healthlog-push/.github/workflows/release.yml@refs/tags/$TAG"
PROV="https://github.com/MBombeck/healthlog-push/.github/workflows/provenance.yml@refs/tags/$TAG"
ISSUER=https://token.actions.githubusercontent.com

cosign verify "$IMAGE@$DIGEST" --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER"
cosign verify-attestation "$IMAGE@$DIGEST" --type spdxjson \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" > /dev/null
cosign verify-attestation "$IMAGE@$DIGEST" --type slsaprovenance1 \
  --certificate-identity "$PROV" --certificate-oidc-issuer "$ISSUER" \
  --certificate-github-workflow-repository MBombeck/healthlog-push > /dev/null

# binaries
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER"
shasum -a 256 -c SHA256SUMS

# binary provenance, from v1.0.3 on (slsa-verifier v2)
for f in healthlog-push_${TAG}_linux_amd64 healthlog-push_${TAG}_linux_arm64 SHA256SUMS; do
  slsa-verifier verify-artifact "$f" --provenance-path "healthlog-push_${TAG}.intoto.jsonl" \
    --source-uri github.com/MBombeck/healthlog-push --source-tag "$TAG"
done
```

The provenance is also stored as a GitHub artifact attestation, so
`gh attestation verify oci://$IMAGE@$DIGEST --repo MBombeck/healthlog-push --signer-workflow MBombeck/healthlog-push/.github/workflows/provenance.yml`
checks it a second way.

### v1.0.0

v1.0.0 got its provenance from the SLSA GitHub generator (v2.1.0), which writes the older format (an `.att`
tag, predicate `https://slsa.dev/provenance/v0.2`) under the generator's own identity. Signature, SBOM and
binaries verify with the commands above. A plain `cosign verify-attestation` finds only the bundles in the
referrers, none of which is the provenance, and fails with "no matching CertificateIdentity"; the provenance
of v1.0.0 needs the legacy lookup:

```sh
cosign verify-attestation "$IMAGE@$DIGEST" --new-bundle-format=false --type slsaprovenance \
  --certificate-identity-regexp '^https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v[0-9.]+$' \
  --certificate-github-workflow-repository MBombeck/healthlog-push --certificate-oidc-issuer "$ISSUER" > /dev/null
```

Checked on 2026-11-21 with cosign v3.1.4 against
`ghcr.io/mbombeck/healthlog-push@sha256:29c0efbf4014b9d6d84ec26465180787583a696d23302670b88bf2f8bafff46b`
(v1.0.0): signature, SBOM and checksum bundle verified; plain provenance lookup refused; the legacy command
above verified.

The hosted relay shows the digest it runs at `https://push.healthlog.dev/version`. That answer comes from
the relay itself, so it proves nothing on its own; the deployment role refuses to start any digest whose
signature or provenance fails the commands above.

## Local rehearsal

`scripts/release-dry-run.sh` runs the same steps against a throwaway local registry. Keyless signing needs
GitHub's OIDC token, so the rehearsal signs with a throwaway key pair and without a transparency log; every
other command is the one the workflow uses. It checks:

1. the image is built for linux/amd64 and linux/arm64 with BuildKit pinned by digest and carries SLSA
   provenance whose materials are all pinned by digest;
2. the image signature verifies;
3. the SPDX SBOM attestation verifies;
4. the provenance attestation verifies;
5. a reference that was not signed (a single platform manifest) is refused;
6. the release binaries match `SHA256SUMS`, whose signature bundle verifies;
7. rebuilding the binary gives a byte-identical file.

Last run, on 2026-11-21 against commit `cd66d8b`:

```
platforms: ['amd64', 'arm64']
signature: verified
SBOM attestation: verified
build type: https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md
provenance attestation: verified
unsigned platform manifest: refused
checksums signature: verified
healthlog-push-linux-amd64: OK
healthlog-push-linux-arm64: OK
binary rebuild: identical
```

What the rehearsal cannot show: the keyless certificate identity, the transparency log entries, and the
provenance workflow's own signature. Those are checked with the commands above after the first real tag.

## How the pipeline is protected

- **Pinned actions.** Every action in every workflow is pinned to a full commit SHA, and Dependabot proposes
  the updates. The one exception is the SLSA generator for the binary provenance,
  `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0`: it is a
  reusable workflow that has to be referenced by its release tag, because `slsa-verifier` checks the builder
  reference in the provenance against the generator's release tags and the generator refuses to run from a
  commit SHA. The comment above the job in `release.yml` records the commit the tag pointed to when it was
  adopted.
- **Least privilege.** Every workflow starts with no token permissions and each job asks for what it needs.
  The job that generates the SBOM cannot sign, and the image provenance is signed in a separate reusable
  workflow, so the build job cannot produce a provenance that verifies.
- **Tags.** A release starts when a `vX.Y.Z` tag is pushed, which needs write access to the repository. A
  ruleset protects `v*` tags from update and deletion, so a published tag cannot be moved to other code, and
  the workflow refuses a tag that does not point to a commit on `main`.
- **The `release` environment.** The job that builds, pushes and signs the image runs in the `release`
  environment, which accepts only `v*` tags, and every later job depends on that job. The environment has no
  required reviewer; no manual approval is part of a release.
- **Signatures bound to the workflow.** The image and `SHA256SUMS` are signed keyless with cosign. The
  certificate names `release.yml` at the release tag, and the provenance names `provenance.yml` or the SLSA
  generator at their tags, so nothing built elsewhere, or from another ref, verifies with the commands above.
- **Releases are not marked immutable.** GitHub's immutable releases lock a release when it is published.
  The binary provenance is attached by the SLSA generator after that, because it has to cover the files
  exactly as they were published, so the setting stays off. What protects a published release is the tag
  ruleset and the signatures: a file that was replaced no longer matches `SHA256SUMS`, its signature bundle
  or the provenance.
- **`main`.** Changes reach `main` only through a pull request with green CI and CodeQL checks; force pushes
  and deletion are blocked ([CONTRIBUTING.md](../CONTRIBUTING.md#commits-and-pull-requests)).
- Private vulnerability reporting is enabled (see [SECURITY.md](../SECURITY.md)).
