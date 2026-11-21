# Release verification

What a release consists of, how anyone can check it, and the local rehearsal that exercises the same
pipeline before a tag is pushed.

## What a tag produces

The workflow `.github/workflows/release.yml` runs for a tag `vX.Y.Z` that points to a commit on `main`:

| Artefact | Where | Signed by |
|---|---|---|
| Multi-arch image (linux/amd64, linux/arm64) | `ghcr.io/mbombeck/healthlog-push:vX.Y.Z` | cosign keyless, identity `https://github.com/MBombeck/healthlog-push/.github/workflows/release.yml@refs/tags/vX.Y.Z` |
| SPDX SBOM | attestation on the image digest, type `spdxjson` | same identity |
| SLSA build provenance | attestation on the image digest, type `slsaprovenance` | the SLSA GitHub generator's reusable workflow |
| Linux binaries and `SHA256SUMS` | GitHub release | `SHA256SUMS.sigstore.json` bundle, same identity as the image |

BuildKit runs pinned by digest, there is no emulation step, and the SBOM is generated in a job that has no
signing rights; only a separate job with `id-token: write` attests it.

## Checking a release

```sh
TAG=vX.Y.Z
IMAGE=ghcr.io/mbombeck/healthlog-push
DIGEST=$(crane digest "$IMAGE:$TAG")
ID="https://github.com/MBombeck/healthlog-push/.github/workflows/release.yml@refs/tags/$TAG"
ISSUER=https://token.actions.githubusercontent.com

cosign verify "$IMAGE@$DIGEST" --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER"
cosign verify-attestation "$IMAGE@$DIGEST" --type spdxjson \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER"
cosign verify-attestation "$IMAGE@$DIGEST" --type slsaprovenance \
  --certificate-identity-regexp '^https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v[0-9.]+$' \
  --certificate-github-workflow-repository MBombeck/healthlog-push --certificate-oidc-issuer "$ISSUER"

# binaries
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER"
shasum -a 256 -c SHA256SUMS
```

The hosted relay shows the digest it runs at `https://push.healthlog.dev/version`. That answer comes from
the relay itself, so it proves nothing on its own; the deployment role refuses to start any digest that
fails the first two commands above.

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
SLSA generator's own signature. Those are checked with the commands above after the first real tag.

## Before the first tag

- The `release` environment exists and requires the maintainer's approval.
- A ruleset protects `v*` tags from update and deletion; releases are immutable.
- Private vulnerability reporting is enabled (see `SECURITY.md`).
