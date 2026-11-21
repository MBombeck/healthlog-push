# Dependencies

The relay handles push traffic for a health app, so every line of third-party code is part of what a
reviewer has to trust. The list is short on purpose. This page names every module in `go.mod`, why it is
there, and the tools that build and check the code.

## Go modules

The Go version is pinned in `go.mod` (`go 1.27.4`). Everything else comes from the standard library:
HTTP/1.1 and HTTP/2 server and client (`net/http`), TLS, Ed25519, ECDSA, HMAC, SHA-256, JSON and the
Prometheus text output, which is written by hand in `internal/metrics`.

### Direct

| Module | Version | Used by | Why |
|---|---|---|---|
| `go.etcd.io/bbolt` | v1.5.0 | `internal/store` | Storage. One process, a few thousand records, transactions and a built-in consistency check, in pure Go with no cgo. SQLite was considered and rejected: the cgo driver brings a C toolchain into a static distroless build, and the pure-Go port is a large tree of C code translated to Go, so either way the dependency would dwarf the relay; a separate database server is more moving parts than the relay itself. Maintained by the etcd project. |
| `golang.org/x/crypto` | v0.59.0 | `cmd/healthlog-push` | Only the packages `acme` and `acme/autocert`: certificates from Let's Encrypt over TLS-ALPN-01 on port 443, so the relay needs no port 80 and no separate ACME client. Maintained by the Go team. The relay code imports no cryptographic primitive from this module; a structural test refuses its `chacha20poly1305`, `curve25519` and `hkdf` packages. |

### Indirect

| Module | Version | Pulled in by | Why |
|---|---|---|---|
| `golang.org/x/net` | v0.62.0 | `golang.org/x/crypto/acme/autocert` | `idna` for host name handling in autocert. |
| `golang.org/x/text` | v0.44.0 | `golang.org/x/net/idna` | Unicode tables (`secure/bidirule`) used by `idna`. |
| `golang.org/x/sys` | v0.50.0 | `go.etcd.io/bbolt` | `unix` system calls for memory mapping and file locking. |

`go mod why -m <module>` shows the same chains. CI runs `go mod verify` and `go mod tidy -diff`, builds with
`-mod=readonly`, and runs `govulncheck` on every push to `main` and every pull request.

## Container images

| Image | Pinned by | Why |
|---|---|---|
| `golang:1.27.4-alpine` | digest in `Dockerfile` | build stage only; cross-compiles a static binary (`CGO_ENABLED=0`, `-trimpath`) |
| `gcr.io/distroless/static-debian12:nonroot` | digest in `Dockerfile` | runtime: no shell, no package manager, CA certificates for the connections to Apple and the ACME server |

## Build, CI and release tools

All GitHub Actions are pinned by commit SHA, with the version in a comment. The SLSA generator is the one
exception: its reusable workflow must be referenced by tag (`v2.1.0`) because it verifies its own reference
when it signs.

| Tool | Where | Purpose |
|---|---|---|
| `actions/checkout`, `actions/setup-go`, `actions/setup-node` | all workflows | check out, install Go from `go.mod`, install Node 22 |
| `golangci-lint` v2.15.0 (`golangci/golangci-lint-action`) | `ci.yml` | linters, configured in `.golangci.yml` |
| `golang.org/x/vuln/cmd/govulncheck` v1.10.0 | `ci.yml` | known vulnerabilities in reachable code |
| Go fuzzing (`go test -fuzz`) | `ci.yml` | every `Fuzz` target for 20 seconds; the job fails if none is found |
| Node 22, no npm packages | `ci.yml` | `spec/tools/check-vectors.mjs` regenerates and checks the test vectors with `node:crypto` only |
| `scripts/check-text.sh` | `ci.yml` | text rules for every tracked file |
| `docker/setup-qemu-action`, `docker/setup-buildx-action`, `docker/build-push-action`, `docker/login-action` | `ci.yml`, `release.yml` | multi-arch image builds (amd64, arm64) and the push to GHCR |
| `sigstore/cosign-installer` | `release.yml` | keyless signing of the image, the SBOM attestation and the binaries' checksum file |
| `anchore/sbom-action` | `release.yml` | SPDX SBOM of the released image |
| `slsa-framework/slsa-github-generator` v2.1.0 | `release.yml` | SLSA provenance for the image |
| `github/codeql-action` | `codeql.yml` | CodeQL analysis of the Go code |
| `ossf/scorecard-action`, `actions/upload-artifact` | `scorecard.yml` | OpenSSF Scorecard |
| Dependabot | `.github/dependabot.yml` | weekly updates for Go modules, GitHub Actions and Docker base images |

On the relay host, the Ansible role installs cosign at a pinned version and checks the download against a
pinned SHA-256 before it verifies an image ([deploy/ansible/README.md](../deploy/ansible/README.md)).

## Adding a dependency

A new module, direct or indirect, is accepted only with an entry on this page in the same pull request,
saying:

1. what it does for the relay, and which packages of it are imported;
2. why the standard library, or code that already is a dependency, is not enough;
3. who maintains it, how active it is, and whether it needs cgo (it should not);
4. what it pulls in indirectly.

Preferences, in order: the standard library; a `golang.org/x` module maintained by the Go team; a small,
widely used module with few dependencies of its own. Not accepted: modules that implement envelope
cryptography (HPKE, X25519, AEAD) in the relay, logging or error-reporting SDKs that collect request
context, and code generators or frameworks for the HTTP layer.

Dependabot updates of existing modules are reviewed like any other change: read the changelog, check the
diff of the module for anything that touches the network, files or cryptography, and keep `go.sum`
consistent with `go mod verify`.
