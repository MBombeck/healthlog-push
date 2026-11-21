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

## Before the first tag

- The `release` environment exists and requires the maintainer's approval.
- A ruleset protects `v*` tags from update and deletion; releases are immutable.
- Private vulnerability reporting is enabled (see `SECURITY.md`).
