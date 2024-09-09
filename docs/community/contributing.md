---
description: How to contribute to Bifröst technically and which guidelines are in place.
---
# Contributing Guidelines

Contributions are welcome via [GitHub Pull Requests](https://docs.github.com/articles/about-pull-requests) ("PR"). This document outlines the process to help you get your contribution accepted.

Any kind of contribution is welcome, from adding new features or bug fixes to improving the documentation. However, [Engity](https://engity.com) will review the proposals and perform a triage over them. By doing so, we will ensure that the most valuable contributions for the community will be implemented in due time.

## How to Contribute

1. [Fork this repository](https://github.com/engity-com/bifroest/fork), develop, and test your changes.
2. [Submit a pull request](https://docs.github.com/articles/creating-a-pull-request).
3. Read and agree to our <<asset_link("CLA.md", "Contributor License Agreement")>> as requested in the pull request.

### Technical Requirements

When submitting a PR, make sure that it:

- Must pass CI jobs/actions.
- Must follow [Golang best practices](https://go.dev/doc/effective_go).
- Is signed off with the line `Signed-off-by: <Your-Name> <Your-email>`. [Learn more about signing off on commits](https://docs.github.com/en/organizations/managing-organization-settings/managing-the-commit-signoff-policy-for-your-organization).

    !!! note
        Signing off on a commit is different from signing a commit, such as with a GPG key.

### PR Approval

1. Changes are manually reviewed by [Engity's Bifröst](https://echocat.org) team members.
2. When the PR passes all tests, the PR is merged by the reviewer(s) in the GitHub [`main` branch](https://github.com/engity-com/bifroest/tree/main).

### Release process

#### Schedule

There are no fixed cycles for releases. Currently, they are triggered as soon bugfixes, security updates or main features arrive.

#### Creation

First of all prepare the release notes as usual and merge them.

Once the release notes are ready, a release train is launched by *tagging* from `main` to `vX.Y.Z`.

#### Validation

The `vX.Y.Z` tag will go through the release CI.
