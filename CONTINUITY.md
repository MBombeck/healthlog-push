# Continuity

healthlog-push has one maintainer. This page says what is in place for the case that the maintainer dies,
is incapacitated, or is otherwise unable to continue.

## What is in place

- A continuity arrangement exists. A trusted contact designated by the maintainer holds sealed emergency
  access.
- A successor is set for the maintainer's GitHub account, which owns this repository.
- The arrangement is reviewed at least once a year.

Its purpose is that the project does not stop with one person: that issues can still be created and closed,
changes accepted and a new version released within a week of the loss being confirmed. Who the contact is
and how the access works is not published.

## What does not need to be handed over

No release key exists. Releases are signed keyless by the release workflow, and the signing identity is the
workflow at the release tag, not a person
([docs/release-verification.md](docs/release-verification.md)). Whoever can push a `vX.Y.Z` tag to `main`
can release, under the same rulesets and the same required checks as before.

Self-hosted relays do not depend on the maintainer or on the hosted relay. They hold their own keys.

## The hosted relay

The hosted relay at `push.healthlog.dev` is a service run by the maintainer, separate from the project. Who
can do what on it while the maintainer is away is described in
[docs/key-ceremony.md](docs/key-ceremony.md#roles) and in the
[absence checklist](docs/operations.md#absence-checklist).

## What this is not

It does not give the project a second maintainer. Nobody besides the maintainer knows the code well enough
to develop it further today, and no second person reviews changes
([GOVERNANCE.md](GOVERNANCE.md#how-changes-are-reviewed)). The arrangement makes sure the project can be
kept safe and handed over, not that development continues at the same pace. A second maintainer is welcome
([GOVERNANCE.md](GOVERNANCE.md#adding-people)).
