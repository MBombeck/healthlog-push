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

## Coding style

Go code follows [Effective Go](https://go.dev/doc/effective_go) and the [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments), and is formatted with `gofmt -s` and `goimports`. `golangci-lint run` enforces the formatting and the linters configured in `.golangci.yml`; CI runs it on every pull request and a finding blocks the merge. An exception needs a `//nolint` comment that names the linter and gives the reason at the line it applies to.

Deploy code under `deploy/` follows `yamllint` and `ansible-lint` with the configuration in that directory. Every file follows the [text rules](#text-rules).

## Tests

Policy: every pull request that adds major new functionality adds tests for it to the automated test suite in the same pull request. Major new functionality is anything a user, a server or an operator can observe: an endpoint, a field, a statement type, a push class, an admin command, a limit, a configuration variable. A pull request without those tests is not merged.

A change to a rule (a limit, a validation, a protocol check) comes with a test that fails when the rule is broken. Write the test, break the rule on purpose, watch the test fail, then restore it. A test that cannot fail does not count. A bug fix comes with a regression test that fails without the fix.

A change to a security property also updates [SECURITY-INVARIANTS.md](SECURITY-INVARIANTS.md), which maps every invariant to the tests that hold it; `TestInvariantsNameRealTests` fails when a test named there does not exist.

When tests run: locally with the commands under [Building and testing](#building-and-testing), and in CI on every pull request and on every push to `main` (`.github/workflows/ci.yml`: build, vet, tests with the race detector, lint, govulncheck, every fuzz target for 20 seconds, the spec vectors, the image build). A pull request is merged only when all of them and CodeQL are green. The result of every run is public on the pull request and under the repository's Actions tab.

Coverage: CI measures statement coverage across all packages (`go test -coverpkg=./... -coverprofile=cover.out ./...`), prints the figure in the run summary and fails below 80 %. A change that lowers coverage below that floor needs tests, not a lower floor.

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
- Every commit carries a `Signed-off-by` line with the author's name and e-mail address (`git commit -s`). With it you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/): that you wrote the change or otherwise have the right to submit it under the Apache License 2.0. The check `DCO sign-off` on the pull request fails when a commit has no sign-off by its author (`scripts/check-dco.sh`). Commits by bots and merge commits are exempt.
- Do not force-push over review comments; add commits and squash at the end if asked.
- `main` changes only through a pull request whose CI and CodeQL checks are green. Pull requests are merged by squash or rebase, so the history of `main` stays linear.

## Text rules

Every file and every commit message follows a few plain-text rules, checked by `scripts/check-text.sh`:

- English only.
- No em dash, en dash, arrow or middle dot characters; use plain hyphens and words.
- No tool attribution lines in commits or files.
- No personal names, no real instance ids, tokens, keys, IP addresses or host names. Use `push.example.org`, `203.0.113.10` and `2001:db8::10` in examples. The `Signed-off-by` line of a commit is the one place a name belongs.

## Review

The maintainer reviews every pull request before it is merged. What the review checks, and how the maintainer's own changes are handled, is in [GOVERNANCE.md](GOVERNANCE.md#how-changes-are-reviewed).

## Security issues

Do not file them as issues or pull requests. See [SECURITY.md](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
