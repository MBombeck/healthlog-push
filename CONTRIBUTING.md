# Contributing

Thanks for taking the time to contribute. This relay handles push traffic for health apps, so the bar for changes is careful rather than fast. Small, focused pull requests with tests are the easiest to review.

## Building and testing

You need the Go version named in `go.mod` and Node 22 for the vector check.

```sh
go build ./...
go vet ./...
go test -race ./...
```

Fuzz targets run in CI for 20 seconds each. To run one locally:

```sh
go test -list '^Fuzz' ./...                      # list the targets
go test -run '^$' -fuzz '^FuzzName$' -fuzztime 60s ./internal/somepkg
```

Lint and vulnerability checks:

```sh
golangci-lint run            # golangci-lint v2, config in .golangci.yml
go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...
```

Spec vectors:

```sh
node spec/tools/check-vectors.mjs
```

Text rules:

```sh
scripts/check-text.sh
```

The container image builds with:

```sh
docker build -t healthlog-push:dev .
```

The release pipeline (multi-arch build, signature, SBOM and provenance attestations, signed binary checksums,
and their verification) is rehearsed locally against a throwaway registry and key with:

```sh
scripts/release-dry-run.sh [version]
```

It needs docker with buildx, cosign, syft, crane and Go. Run it before tagging a release; what a real
release produces and how to verify it is in [docs/release-verification.md](docs/release-verification.md).

## Tests

A change to a rule (a limit, a validation, a protocol check) comes with a test that fails when the rule is broken. Write the test, break the rule on purpose, watch the test fail, then restore it. A test that cannot fail does not count.

A change to a security property also updates [SECURITY-INVARIANTS.md](SECURITY-INVARIANTS.md), which maps every invariant to the tests that hold it; `TestInvariantsNameRealTests` fails when a test named there does not exist.

## Privacy notice and terms

The served texts have one source: `internal/notice/privacy.md` and `internal/notice/terms.md`. Edit only those, then copy them to `docs/` with:

```sh
scripts/sync-notice.sh
```

`TestLegalTextsInSync` fails while the copies differ.

## Dependencies

The dependency list is kept short on purpose. Every new dependency, direct or indirect, needs a written justification in `docs/dependencies.md`: what it does, why the standard library is not enough, and who maintains it. Pull requests that add a module without that entry will not be merged. Dependabot updates of existing dependencies are reviewed like any other change.

## Spec changes

The specification under `spec/` is a contract between independent implementations. A change to the wire format or to a cryptographic step needs a new version of the affected test vectors; existing vector files are never edited in place. Explain the reason for the change in the pull request.

## Commits and pull requests

- English, imperative mood, short subject line: `Reject registrations with an unknown key id`.
- One logical change per commit where practical.
- No sign-off line is required (no DCO). By submitting a contribution you agree that it is licensed under the Apache License 2.0, as stated in section 5 of the license.
- Do not force-push over review comments; add commits and squash at the end if asked.

## Text rules

Every file and every commit message follows a few plain-text rules, checked by `scripts/check-text.sh`:

- English only.
- No em dash, en dash, arrow or middle dot characters; use plain hyphens and words.
- No tool attribution lines in commits or files.
- No personal names, no real instance ids, tokens, keys, IP addresses or host names. Use `push.example.org`, `203.0.113.10` and `2001:db8::10` in examples.

## Security issues

Do not file them as issues or pull requests. See [SECURITY.md](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
