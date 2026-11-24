---
description: Technical contributions to Bifröst and corresponding guidelines.
---
# Contributing Guidelines

Bug fixes, features and documentation improvements are welcome via [GitHub pull requests](https://docs.github.com/articles/about-pull-requests) (PRs). [Engity](https://engity.com) reviews proposals for relevance and scope before accepting them.

## How to Contribute

1. [Fork this repository](https://github.com/engity-com/bifroest/fork) and develop your changes from `main`.
2. Add or update tests and documentation affected by your change.
3. [Submit a pull request](https://docs.github.com/articles/creating-a-pull-request) describing the motivation, related issues and how you verified the changes.
4. Read and agree to our <<asset_link("CLA.md", "Contributor License Agreement")>> as requested in the pull request.

### Technical Requirements

- Your PR must pass the required CI checks.
- Go changes must follow [Go best practices](https://go.dev/doc/effective_go).
- Sign off your commits with `Signed-off-by: <Your-Name> <Your-email>`. [Learn more about signing off on commits](https://docs.github.com/en/organizations/managing-organization-settings/managing-the-commit-signoff-policy-for-your-organization).

Signing off a commit is different from cryptographically signing it, for example with GPG.

### PR Approval

Engity's Bifröst team reviews the PR and may request changes. Once it is approved and the required checks pass, a reviewer merges it into [`main`](https://github.com/engity-com/bifroest/tree/main).

### Release process

Releases have no fixed schedule. Merging a PR into `main` does not publish a release; the maintainers decide when contributions are included in one.

If your change requires users to adapt their configuration or installation when upgrading, include the necessary instructions in the [upgrade notes](../setup/upgrade.md) with your PR.

You do not need to create release tags, write release announcements or publish artifacts. Follow [GitHub releases](https://github.com/engity-com/bifroest/releases) to see when your contribution becomes available.
