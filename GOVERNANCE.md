# Governance

How decisions are made in healthlog-push, which roles exist, and what each role has to do. Who holds a role
today is listed in [MAINTAINERS.md](MAINTAINERS.md). What happens when the maintainer is not available is in
[CONTINUITY.md](CONTINUITY.md).

## Model

healthlog-push is a single-maintainer project. The maintainer makes every final decision about the code,
the specification, the releases and the repository settings. There is no committee, no vote and no
organisation behind the project.

Decisions are made in the open wherever they concern the code or the protocol:

- A change is proposed as an issue or a pull request. Anyone may propose one and anyone may comment.
- The maintainer decides and gives the reason in the issue or pull request.
- The decision is recorded where the change lands: in the pull request, in [CHANGELOG.md](CHANGELOG.md), and
  in the document it affects. Accepted risks go into the "Known limitations" section of
  [docs/threat-model.md](docs/threat-model.md), dependency decisions into
  [docs/dependencies.md](docs/dependencies.md).
- A decision can be reopened with new facts. Repeating the same argument does not reopen it.

If you disagree with a decision, say so in the issue or pull request. The maintainer answers and the answer
stands. The code is licensed under Apache-2.0, so a fork is always possible.

Decisions about the hosted relay at `push.healthlog.dev` (abuse handling, suspensions, requests from
authorities, maintenance) are made by its operator, who is the maintainer. They follow
[docs/operations.md](docs/operations.md) and [docs/terms.md](docs/terms.md), and they are reported in
[docs/transparency.md](docs/transparency.md). Running the hosted relay is not a project role: the software
does not depend on it.

## Roles and responsibilities

| Role | Responsibilities | Access |
|---|---|---|
| Maintainer | Triage issues. Review and merge pull requests. Keep the specification, the test vectors and the documentation consistent with the code. Cut releases. Answer security reports and publish fixes ([SECURITY.md](SECURITY.md)). Keep the dependencies current. Own the repository settings and the rulesets. Keep [ROADMAP.md](ROADMAP.md) and this document current. | Owner of the repository and of the container package. Receives private vulnerability reports. |
| Contributor | Propose changes that meet [CONTRIBUTING.md](CONTRIBUTING.md): tests, text rules, a justification for every new dependency. Follow the [code of conduct](CODE_OF_CONDUCT.md). | None. Contributions arrive as pull requests from forks. |
| Security reporter | Report privately, give the project time to fix ([SECURITY.md](SECURITY.md)). | None. |
| Continuity contact | A trusted person designated by the maintainer. No part in day-to-day work; acts only if the maintainer can no longer do so ([CONTINUITY.md](CONTINUITY.md)). | Sealed emergency access, unused in normal operation. |

The maintainer is also the operator and the key holder of the hosted relay. Those duties are described in
[docs/operations.md](docs/operations.md) and [docs/key-ceremony.md](docs/key-ceremony.md).

## How changes are reviewed

- Every change reaches `main` through a pull request. Direct pushes, force pushes and deletion of `main` are
  blocked by a ruleset.
- A pull request is merged only when the required checks are green: build, vet and tests with the race
  detector and the coverage floor, golangci-lint, govulncheck, every fuzz target, the spec vectors, the image
  build, the text rules, the deploy lint, the sign-off check and CodeQL.
- The maintainer reviews every pull request from a contributor before it is merged. The review checks that
  the change does what it says, that a test fails when the rule it adds is broken, that no security
  invariant in [SECURITY-INVARIANTS.md](SECURITY-INVARIANTS.md) is weakened, that the documentation matches
  the behaviour, and that no dependency arrives without its entry in
  [docs/dependencies.md](docs/dependencies.md).
- The maintainer's own changes pass the same checks and the checklist in the pull request template. Nobody
  else reviews them. With one maintainer there is no second reviewer, and this document does not claim one.

## Releases

Only the maintainer releases. A release is a `vX.Y.Z` tag on `main`; the release workflow builds, signs and
publishes everything from that tag. What a release contains and how to verify it is in
[docs/release-verification.md](docs/release-verification.md). Only the latest release receives fixes.

## Adding people

The project has no second maintainer today. Contributors who want to take on more are welcome. Before
anyone receives write access, a part in handling security reports, or any other access to a sensitive
resource, the maintainer checks all of the following:

1. The person has a history of reviewed and merged contributions to this repository.
2. The maintainer can establish who the person is, through a long-standing public account, a known
   affiliation or personal contact.
3. The account is protected by two-factor authentication with a passkey, a security key or an
   authenticator app. SMS alone is not accepted.
4. The access granted is the smallest that fits the task. Write access to the repository never includes the
   keys or the host of the hosted relay.

The grant is recorded in [MAINTAINERS.md](MAINTAINERS.md) in the same pull request that announces it.
Access is reviewed once a year and removed when it is no longer used.

## Changing this document

Through a pull request, decided by the maintainer like any other change.
