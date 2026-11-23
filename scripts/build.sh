#!/bin/sh
# The one build recipe of the relay binary. The Dockerfile, the release workflow, CI and anyone who checks a
# release (docs/verify.md) run this script, so the binary in the image, the release binary and a rebuild
# on another machine are the same file, byte for byte.
#
# What makes the output depend only on the source, the version and the commit:
# - the Go release named in go.mod, nothing else (GOTOOLCHAIN; a different local Go fetches that release
#   from the Go module proxy, checked against the checksum database);
# - no VCS stamp (-buildvcs=false): a checkout with .git and a build context without it give the same file;
#   version and commit come from -ldflags only;
# - no paths, no build id, no symbol table (-trimpath, -buildid=, -s -w), no cgo, and every GOxxx setting
#   that could come from the caller's environment fixed here.
#
# Usage: scripts/build.sh <version> <commit> <amd64|arm64> <output file>
set -eu

usage='usage: scripts/build.sh <version> <commit> <amd64|arm64> <output file>'
version=${1:?$usage}
commit=${2:?$usage}
arch=${3:?$usage}
out=${4:?$usage}

case "$arch" in
  amd64 | arm64) ;;
  *) echo "build.sh: architecture $arch is not amd64 or arm64" >&2; exit 2 ;;
esac
case "$out" in
  /*) ;;
  *) out="$(pwd)/$out" ;;
esac

cd "$(dirname "$0")/.."
gover=$(sed -n 's/^go \([0-9][0-9.]*\)$/\1/p' go.mod)
if [ -z "$gover" ]; then
  echo "build.sh: no go line in go.mod" >&2
  exit 2
fi

export GOTOOLCHAIN="go$gover"
export CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOAMD64=v1 GOARM64=v8.0
export GOFLAGS='' GOEXPERIMENT='' GOWORK=off
pkg=github.com/MBombeck/healthlog-push/internal/buildinfo

exec go build -mod=readonly -trimpath -buildvcs=false \
  -ldflags "-s -w -buildid= -X $pkg.Version=$version -X $pkg.Commit=$commit" \
  -o "$out" ./cmd/healthlog-push
