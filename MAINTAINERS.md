# Maintainers

Who holds which role in healthlog-push, and who has access to what. The roles and their duties are defined
in [GOVERNANCE.md](GOVERNANCE.md).

## People

| Role | GitHub account | Since |
|---|---|---|
| Maintainer | `MBombeck` | 2026-11 |

There are no other maintainers, committers or triagers.

A continuity arrangement exists: a trusted contact designated by the maintainer holds sealed emergency
access, and a successor is set for the maintainer's GitHub account. The contact takes no part in day-to-day
work and is not named here ([docs/continuity.md](docs/continuity.md)).

## Access to sensitive resources

| Resource | Who has access | Notes |
|---|---|---|
| Repository `MBombeck/healthlog-push`: settings, rulesets, release environment, tags | Maintainer (owner) | |
| Private vulnerability reports and security advisories on GitHub | Maintainer | |
| Security mailbox `relay@healthlog.dev` and abuse mailbox `abuse@healthlog.dev` | Maintainer | |
| Container package `ghcr.io/mbombeck/healthlog-push` | Maintainer; the release workflow, with a token that lives for one job | No long-lived registry credential exists. |
| Release signing | Nobody holds a key | Releases are signed keyless by the release workflow. The signing identity is the workflow at the release tag ([docs/release-verification.md](docs/release-verification.md)). |
| Domain and DNS of `healthlog.dev` | Maintainer | |
| Host, secret store and keys of the hosted relay, and the Apple developer account | Maintainer, as operator and key holder | [docs/key-ceremony.md](docs/key-ceremony.md). Not needed to develop or release the software. |
| Project entries at bestpractices.dev and scorecard.dev | Maintainer | |

Automation: GitHub Actions runs with a token that starts without permissions and is granted per job.
Dependabot opens pull requests and cannot merge them. The repository has no deploy keys, no stored secrets
and no webhooks.

## Contact

- Bugs and questions: [issues](https://github.com/MBombeck/healthlog-push/issues).
- Security: see [SECURITY.md](SECURITY.md). Never in a public issue.
- Abuse of the hosted relay: `abuse@healthlog.dev`.
