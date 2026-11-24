#!/bin/sh
# Compares the relay binary in each platform image of a pushed multi-platform image with the release
# binary of that platform, byte for byte. The release workflow runs it before it creates a GitHub release.
#
# Each platform manifest is resolved from the index and pulled by its own digest, so every pull has a
# unique target: pulling the index a second time for another platform fails in the containerd image store
# ("cannot overwrite digest").
#
# Needs docker (with buildx), jq and sha256sum or shasum.
# Usage: scripts/compare-image-binaries.sh <image@sha256:index-digest> <version> <directory of release binaries>
set -eu

usage='usage: scripts/compare-image-binaries.sh <image@sha256:digest> <version> <dir>'
ref=${1:?$usage}
version=${2:?$usage}
dir=${3:?$usage}
image=${ref%@*}

sum() { if command -v sha256sum > /dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
docker buildx imagetools inspect --raw "$ref" > "$work/index.json"

for arch in amd64 arm64; do
  digest=$(jq -r --arg a "$arch" '[.manifests[] | select(.platform.os == "linux" and .platform.architecture == $a) | .digest] | if length == 1 then .[0] else "" end' "$work/index.json")
  if [ -z "$digest" ]; then
    echo "FAIL linux/$arch: not exactly one manifest in $ref" >&2
    exit 1
  fi
  docker pull -q --platform "linux/$arch" "$image@$digest" > /dev/null
  id=$(docker create --platform "linux/$arch" "$image@$digest")
  docker cp -q "$id:/healthlog-push" "$work/image_$arch"
  docker rm "$id" > /dev/null
  want=$(sum "$dir/healthlog-push_${version}_linux_${arch}")
  got=$(sum "$work/image_$arch")
  echo "linux/$arch ($digest) image $got release $want"
  if [ "$got" != "$want" ]; then
    echo "FAIL linux/$arch: the binary in the image differs from the release binary" >&2
    exit 1
  fi
done
