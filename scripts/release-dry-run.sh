#!/usr/bin/env bash
# Rehearses the release pipeline locally against a throwaway registry: multi-arch image build with BuildKit
# provenance, signature, SBOM attestation, provenance attestation, release binaries with their SBOMs and
# signed checksums, and verification of each. Keyless signing needs GitHub's OIDC token, so this run signs with a throwaway
# key pair; everything else is the same command the release workflow runs.
#
# Needs: docker with buildx, cosign, syft, crane, go. Usage: scripts/release-dry-run.sh [version]
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:-v0.0.0-dryrun}"
commit="$(git rev-parse HEAD)"
work="$(mktemp -d)"
port=5055
registry="localhost:${port}"
image="${registry}/healthlog-push"
builder="hlp-dryrun"
buildkit="moby/buildkit@sha256:baf6138eb8c37644800c7c913fba051e840ebb9ba13eaf92d92ef9a1712d0b4c"

cleanup() {
  docker rm -f hlp-dryrun-registry > /dev/null 2>&1 || true
  docker buildx rm "$builder" > /dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }

# quiet runs a command and shows its output only when it fails.
quiet() {
  local out
  if ! out="$("$@" 2>&1)"; then
    printf '%s\n' "$out" >&2
    return 1
  fi
}

step "throwaway registry on ${registry}"
docker run -d --rm --name hlp-dryrun-registry -p "${port}:5000" registry:2 > /dev/null 2>&1
sleep 1

step "BuildKit pinned by digest, as in the release workflow"
docker buildx create --name "$builder" --driver docker-container \
  --driver-opt "image=${buildkit}" --driver-opt network=host > /dev/null

step "build and push linux/amd64 and linux/arm64 with provenance"
docker buildx build --builder "$builder" --platform linux/amd64,linux/arm64 \
  --build-arg VERSION="$version" --build-arg COMMIT="$commit" \
  --provenance=mode=max --sbom=false --push -t "${image}:${version}" \
  --metadata-file "$work/meta.json" . > "$work/build.log" 2>&1
digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$work/meta.json")"
ref="${image}@${digest}"
echo "image ${ref}"
crane manifest "$ref" | python3 -c 'import json,sys; m=json.load(sys.stdin); print("platforms:", sorted({x["platform"]["architecture"] for x in m["manifests"] if x.get("platform", {}).get("os") == "linux"}))'

step "throwaway signing key (the workflow signs keyless instead)"
(cd "$work" && COSIGN_PASSWORD="" cosign generate-key-pair > /dev/null)
export COSIGN_PASSWORD=""

step "sign the image and verify the signature"
quiet cosign sign --yes --use-signing-config=false --tlog-upload=false --key "$work/cosign.key" "$ref"
quiet cosign verify --insecure-ignore-tlog=true --key "$work/cosign.pub" "$ref" && echo "signature: verified"

step "SBOM (SPDX JSON), attested and verified"
syft -q "$ref" -o spdx-json > "$work/sbom.spdx.json"
echo "SBOM packages: $(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["packages"]))' "$work/sbom.spdx.json")"
quiet cosign attest --yes --use-signing-config=false --tlog-upload=false --key "$work/cosign.key" --type spdxjson --predicate "$work/sbom.spdx.json" "$ref"
quiet cosign verify-attestation --insecure-ignore-tlog=true --key "$work/cosign.pub" --type spdxjson "$ref" && echo "SBOM attestation: verified"

step "provenance: BuildKit SLSA provenance attached to the image, attested and verified"
docker buildx imagetools inspect "$ref" --format '{{ json (index .Provenance "linux/amd64").SLSA }}' > "$work/provenance.json"
python3 - "$work/provenance.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
print("build type:", p.get("buildType") or p.get("buildDefinition", {}).get("buildType", "?"))
mats = p.get("materials") or p.get("buildDefinition", {}).get("resolvedDependencies", [])
print("materials pinned by digest:", all("digest" in m for m in mats), f"({len(mats)} materials)")
PY
quiet cosign attest --yes --use-signing-config=false --tlog-upload=false --key "$work/cosign.key" --type slsaprovenance --predicate "$work/provenance.json" "$ref"
quiet cosign verify-attestation --insecure-ignore-tlog=true --key "$work/cosign.pub" --type slsaprovenance "$ref" && echo "provenance attestation: verified"

step "a tampered reference is refused"
other="$(crane digest "${image}:${version}" --platform linux/amd64)"
if cosign verify --insecure-ignore-tlog=true --key "$work/cosign.pub" "${image}@${other}" > /dev/null 2>&1; then
  echo "ERROR: a platform manifest without its own signature verified" >&2
  exit 1
fi
echo "unsigned platform manifest: refused"

step "release binaries and their SBOMs with signed checksums"
mkdir -p "$work/dist"
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -mod=readonly -trimpath \
    -ldflags "-s -w -buildid= -X github.com/MBombeck/healthlog-push/internal/buildinfo.Version=${version} -X github.com/MBombeck/healthlog-push/internal/buildinfo.Commit=${commit}" \
    -o "$work/dist/healthlog-push-linux-${arch}" ./cmd/healthlog-push
  (cd "$work/dist" && syft -q "file:healthlog-push-linux-${arch}" -o "spdx-json=healthlog-push-linux-${arch}.spdx.json")
  python3 - "$work/dist/healthlog-push-linux-${arch}.spdx.json" \
    "$(shasum -a 256 < "$work/dist/healthlog-push-linux-${arch}" | cut -d' ' -f1)" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
names = {p["name"] for p in doc["packages"]}
sums = {c["checksumValue"] for f in doc.get("files", []) for c in f.get("checksums", [])}
assert "stdlib" in names and "go.etcd.io/bbolt" in names, "the SBOM lacks the compiled-in modules"
assert sys.argv[2] in sums, "the SBOM does not carry the hash of its binary"
print("binary SBOM:", len(doc["packages"]), "packages, hash of the binary present")
PY
done
(cd "$work/dist" && shasum -a 256 healthlog-push-linux-* > SHA256SUMS)
quiet cosign sign-blob --yes --use-signing-config=false --tlog-upload=false --key "$work/cosign.key" --bundle "$work/dist/SHA256SUMS.bundle" "$work/dist/SHA256SUMS"
quiet cosign verify-blob --insecure-ignore-tlog=true --key "$work/cosign.pub" --bundle "$work/dist/SHA256SUMS.bundle" "$work/dist/SHA256SUMS" && echo "checksums signature: verified"
(cd "$work/dist" && shasum -a 256 -c SHA256SUMS)

step "reproducible binary: a second build gives the same hash"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath \
  -ldflags "-s -w -buildid= -X github.com/MBombeck/healthlog-push/internal/buildinfo.Version=${version} -X github.com/MBombeck/healthlog-push/internal/buildinfo.Commit=${commit}" \
  -o "$work/again" ./cmd/healthlog-push
if [ "$(shasum -a 256 < "$work/again")" = "$(shasum -a 256 < "$work/dist/healthlog-push-linux-amd64")" ]; then
  echo "binary rebuild: identical"
else
  echo "binary rebuild: differs" >&2
  exit 1
fi

printf '\ndry run complete: %s %s\n' "$version" "$commit"
