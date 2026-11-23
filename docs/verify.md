# Verify it yourself

A push relay for health data should not ask to be trusted. This page shows how anyone can check, from
public sources only, that the hosted relay runs a binary that was built in public from a tagged commit,
and that rebuilding that commit gives the same file, byte for byte.

## One command

```sh
git clone https://github.com/MBombeck/healthlog-push && cd healthlog-push && scripts/verify-release.sh
```

It needs git, Go (any recent release; the build fetches the exact Go release that `go.mod` names), curl,
jq, tar, [cosign](https://github.com/sigstore/cosign) 3 and [crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane).
A run takes a minute or two, most of it the two builds. A successful run ends with

```
vX.Y.Z verified: signed, rebuilt from source, and the image runs exactly the released binaries.
```

and any mismatch stops it with a line that starts with `FAIL`. `scripts/verify-release.sh vX.Y.Z` checks a
given release; `RELAY=https://push.example.org` asks another relay, and `RELAY=` asks none and checks the
image tag of the release instead.

## What it checks

| Step | Check | What it proves |
|---|---|---|
| 1 | `GET /version` of the relay | which version, commit and image digest the relay says it runs, and the SHA-256 of its own executable (from the release after v1.0.6) |
| 2 | `cosign verify-blob` on `SHA256SUMS`, then the two downloaded binaries against it | the checksums were signed by `release.yml` of this repository at this tag, in GitHub Actions, and the binaries are the ones it listed |
| 3 | a fresh clone of the tag, built twice with `scripts/build.sh` (linux/amd64, linux/arm64) | the source at the tag gives exactly these binaries; nothing else went into them |
| 4 | `cosign verify` and `cosign verify-attestation --type slsaprovenance1` on the image digest | the image was built and signed by the release workflow at this tag, with SLSA build provenance |
| 5 | the binary extracted from each platform image | the image contains the same file as the release, so steps 2 and 3 also describe the image |
| 6 | `binarySha256` and `platform` from step 1 against `SHA256SUMS` | the relay's own process reports the hash of exactly that release binary |

Every step can fail, and the script exits with status 1 when one does.

## Why the files are identical

There is one build recipe, [`scripts/build.sh`](../scripts/build.sh). The Dockerfile runs it, the release
workflow runs it for the release binaries, CI runs it on every pull request, and step 3 runs it on your
machine. It pins the Go release to the one in `go.mod`, builds without cgo, strips paths, the build id and
the symbol table, and leaves out the VCS stamp, so a checkout with `.git` and a Docker build context
without it give the same output. Version and commit come only from `-ldflags`.

Two checks keep that true:

- CI job **Reproducible binary (image = release)** builds every pull request and every push to `main` both
  ways, for both platforms, and fails when one byte differs.
- Release job **Image binary equals release binary** extracts the binary from each platform image of the
  pushed digest and compares it with the release binary before the GitHub release is created. A mismatch
  leaves the tag without a release.

## Without the script

The same steps by hand, for a tag `$TAG`:

```sh
TAG=vX.Y.Z
IMAGE=ghcr.io/mbombeck/healthlog-push
WF=https://github.com/MBombeck/healthlog-push/.github/workflows
ISSUER=https://token.actions.githubusercontent.com
DIGEST=$(curl -s https://push.healthlog.dev/version | jq -r .imageDigest)

# signed checksums
for f in SHA256SUMS SHA256SUMS.sigstore.json; do
  curl -fsSLO "https://github.com/MBombeck/healthlog-push/releases/download/$TAG/$f"
done
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "$WF/release.yml@refs/tags/$TAG" --certificate-oidc-issuer "$ISSUER"

# rebuild from source
git clone --depth 1 --branch "$TAG" https://github.com/MBombeck/healthlog-push src
src/scripts/build.sh "$TAG" "$(git -C src rev-parse HEAD)" amd64 rebuilt
shasum -a 256 rebuilt; grep linux_amd64 SHA256SUMS

# the image and the binary in it
cosign verify "$IMAGE@$DIGEST" --certificate-identity "$WF/release.yml@refs/tags/$TAG" --certificate-oidc-issuer "$ISSUER"
crane export --platform linux/amd64 "$IMAGE@$DIGEST" - | tar -xOf - healthlog-push | shasum -a 256
```

All three hashes are the same. Without Go installed, the rebuild also runs in the builder image the
Dockerfile names:

```sh
docker run --rm -v "$PWD/src:/src" -w /src golang:1.27.4-alpine \
  sh scripts/build.sh "$TAG" "$(git -C src rev-parse HEAD)" amd64 /src/rebuilt
```

The checks of the SBOMs and of the binary provenance are in [release-verification.md](release-verification.md).

## Releases up to v1.0.6

Up to v1.0.6 the release job built the binaries in a checkout with `.git`, so Go stamped VCS details into
them, while the Docker build had no `.git`. Both builds were reproducible on their own, but the release
binary was not the file in the image: for v1.0.6, linux/amd64, the image holds
`83830217ce24e5decc115d185fdad02f15fd96af0fc28e0a5580020ee284d45e` and the release lists
`3b32835fb21d8351e6e3d5e0e6f377a665aa430a64725f22cba0aee763e61dfb`. Those tags have no `scripts/build.sh`, and the script says so. The image binary of
v1.0.6 is still reproducible: copy `scripts/build.sh` from `main` into a checkout of v1.0.6 and run
`scripts/build.sh v1.0.6 8b6f25f980a38fbe324d9862cc3c5a00d62f3298 amd64 out`, which gives the
`83830217...` file above.

## What this does not prove

The relay answers `/version` itself, so step 1 is a statement by the relay, signed with its identity key
but not an attestation by anyone else: a relay that runs other code could report the expected values.
What the checks do prove is that the published digest, the published binaries and the tagged source belong
together, and that the operator cannot have published a different binary under a release without the
signatures or the rebuild failing. The hosted relay starts only digests whose signature and provenance
verify ([release-verification.md](release-verification.md)), and the remaining limit is stated in the
[threat model](threat-model.md).
