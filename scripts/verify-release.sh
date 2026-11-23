#!/usr/bin/env bash
# Checks a release end to end, from nothing but public sources, and fails at the first mismatch:
#
#   1. what the relay reports at /version (version, commit, image digest);
#   2. the signature on SHA256SUMS and the downloaded release binaries against it;
#   3. a rebuild of the tagged source with scripts/build.sh, which must give the same two files;
#   4. the signature and SLSA provenance of the image digest;
#   5. the binary inside each platform image, which must be the same file again;
#   6. the hash the relay reports for its own executable, which must be that file too.
#
# Needs: bash, git, go (any recent release; the build fetches the exact one go.mod names), curl, jq, tar,
# cosign 3 and crane. docs/verify.md explains each step.
#
# Usage: scripts/verify-release.sh [vX.Y.Z]
#   Without a tag, the version the relay reports is checked. RELAY (default https://push.healthlog.dev)
#   names the relay to ask; RELAY= skips the relay and takes the digest of the image tag instead.
set -euo pipefail

REPO=MBombeck/healthlog-push
IMAGE=ghcr.io/mbombeck/healthlog-push
WORKFLOWS="https://github.com/$REPO/.github/workflows"
ISSUER=https://token.actions.githubusercontent.com
RELAY="${RELAY-https://push.healthlog.dev}"

for tool in git go curl jq tar cosign crane; do
  command -v "$tool" > /dev/null || { echo "verify: $tool is not installed" >&2; exit 2; }
done

sha256() {
  if command -v sha256sum > /dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}
ok() { printf 'ok   %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

tag="${1:-}"
digest=""
reported_commit=""
if [ -n "$RELAY" ]; then
  curl -fsS --max-time 15 "$RELAY/version" -o "$work/version.json" || fail "$RELAY/version did not answer"
  reported="$(jq -r .version "$work/version.json")"
  digest="$(jq -r .imageDigest "$work/version.json")"
  reported_commit="$(jq -r .commit "$work/version.json")"
  ok "$RELAY reports $reported, commit $reported_commit, image $digest"
  if [ -z "$tag" ]; then
    tag="$reported"
  elif [ "$tag" != "$reported" ]; then
    fail "$RELAY runs $reported, not $tag; run without a tag or with RELAY="
  fi
fi
[ -n "$tag" ] || fail "no tag given and no relay to ask"
printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || fail "$tag is not a release tag vX.Y.Z"
if [ -z "$digest" ]; then
  digest="$(crane digest "$IMAGE:$tag")"
  ok "image tag $tag has digest $digest"
fi
printf '%s' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || fail "$digest is not an image digest"

# 2. Signed checksums and the release binaries.
cd "$work"
base="https://github.com/$REPO/releases/download/$tag"
for f in SHA256SUMS SHA256SUMS.sigstore.json "healthlog-push_${tag}_linux_amd64" "healthlog-push_${tag}_linux_arm64"; do
  curl -fsSL --max-time 120 -o "$f" "$base/$f" || fail "could not download $f from the $tag release"
done
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "$WORKFLOWS/release.yml@refs/tags/$tag" --certificate-oidc-issuer "$ISSUER" > /dev/null 2>&1 \
  || fail "the signature on SHA256SUMS does not verify for release.yml at $tag"
ok "SHA256SUMS is signed by release.yml at $tag"
want() { awk -v f="healthlog-push_${tag}_linux_$1" '$2 == f { print $1 }' SHA256SUMS; }
for arch in amd64 arm64; do
  [ -n "$(want "$arch")" ] || fail "SHA256SUMS has no line for linux/$arch"
  [ "$(sha256 "healthlog-push_${tag}_linux_$arch")" = "$(want "$arch")" ] || fail "the downloaded linux/$arch binary does not match SHA256SUMS"
done
ok "both release binaries match SHA256SUMS"

# 3. Rebuild from the tagged source.
git clone --quiet --depth 1 --branch "$tag" "https://github.com/$REPO.git" src 2> /dev/null || fail "could not clone $tag"
commit="$(git -C src rev-parse HEAD)"
if [ -n "$reported_commit" ] && [ "$reported_commit" != "$commit" ]; then
  fail "the relay reports commit $reported_commit, the tag $tag is $commit"
fi
[ -x src/scripts/build.sh ] || fail "$tag has no scripts/build.sh; releases before it are checked as docs/verify.md describes"
for arch in amd64 arm64; do
  src/scripts/build.sh "$tag" "$commit" "$arch" "rebuilt_$arch" || fail "the rebuild for linux/$arch failed"
  got="$(sha256 "rebuilt_$arch")"
  [ "$got" = "$(want "$arch")" ] || fail "the rebuild for linux/$arch is $got, SHA256SUMS says $(want "$arch")"
done
ok "rebuilt both binaries from $tag ($commit): identical to the release"

# 4. Image signature and provenance.
cosign verify "$IMAGE@$digest" \
  --certificate-identity "$WORKFLOWS/release.yml@refs/tags/$tag" --certificate-oidc-issuer "$ISSUER" > /dev/null 2>&1 \
  || fail "the image signature does not verify for release.yml at $tag"
cosign verify-attestation "$IMAGE@$digest" --type slsaprovenance1 \
  --certificate-identity "$WORKFLOWS/provenance.yml@refs/tags/$tag" --certificate-oidc-issuer "$ISSUER" \
  --certificate-github-workflow-repository "$REPO" > /dev/null 2>&1 \
  || fail "the image provenance does not verify for provenance.yml at $tag"
ok "image $digest is signed and has SLSA provenance from $tag"

# 5. The binary inside each platform image.
for arch in amd64 arm64; do
  crane export --platform "linux/$arch" "$IMAGE@$digest" - | tar -xOf - healthlog-push > "image_$arch" \
    || fail "could not read the binary from the linux/$arch image"
  got="$(sha256 "image_$arch")"
  [ "$got" = "$(want "$arch")" ] || fail "the binary in the linux/$arch image is $got, SHA256SUMS says $(want "$arch")"
done
ok "the binary in both platform images is the release binary"

# 6. The hash the relay reports of its own executable.
if [ -n "$RELAY" ]; then
  reported_sum="$(jq -r '.binarySha256 // empty' "$work/version.json")"
  platform="$(jq -r '.platform // empty' "$work/version.json")"
  if [ -z "$reported_sum" ]; then
    echo "note $RELAY does not report a binary hash (a release before this field, or the file was unreadable)"
  else
    case "$platform" in
      linux/amd64 | linux/arm64) ;;
      *) fail "$RELAY reports platform $platform" ;;
    esac
    [ "$reported_sum" = "$(want "${platform#linux/}")" ] \
      || fail "$RELAY reports binary $reported_sum for $platform, SHA256SUMS says $(want "${platform#linux/}")"
    ok "$RELAY reports the hash of the $platform release binary for its own executable"
  fi
fi

printf '\n%s verified: signed, rebuilt from source, and the image runs exactly the released binaries.\n' "$tag"
