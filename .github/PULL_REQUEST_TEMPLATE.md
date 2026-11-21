## What and why

<!-- What does this change do, and why is it needed? Link the issue if there is one. -->

## Checklist

- [ ] Tests cover the change, and they fail when the rule they check is broken (I broke it on purpose and watched them fail).
- [ ] `go test -race ./...`, `golangci-lint run` and `govulncheck ./...` pass locally.
- [ ] Docs and README are updated where behaviour, configuration or the admin interface changed.
- [ ] No new dependency, or its justification is added to `docs/dependencies.md`.
- [ ] Spec changes come with a new vector version; no existing vector file was edited.
- [ ] `scripts/check-text.sh` passes, and no real instance ids, tokens, keys or host data appear anywhere.
