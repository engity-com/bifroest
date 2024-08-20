# Contributing Guidelines

Contributions are welcome via [GitHub Pull Requests](https://docs.github.com/articles/about-pull-requests). This document outlines the process to help get your contribution accepted.

Any type of contribution is welcome; from new features, bug fixes, or documentation improvements. However, [Engity](https://engity.com) will review the proposals and perform a triage over them. By doing so, we will ensure that the most valuable contributions for the community will be implemented in due time.

## How to Contribute

1. [Fork this repository]((https://github.com/engity-com/bifroest/fork)), develop, and test your changes.
2. [Submit a pull request](https://docs.github.com/articles/creating-a-pull-request).
3. You have read and agreed to our [Contributor License Agreement](CLA.md) which are checked as part of the created pull request pipelines.

### Technical Requirements

When submitting a PR make sure that it:

- Must pass CI jobs/actions.
- Must follow [Golang best practices](https://go.dev/doc/effective_go).
- Is signed off with the line `Signed-off-by: <Your-Name> <Your-email>`. [Learn more about signing off on commits](https://docs.github.com/en/organizations/managing-organization-settings/managing-the-commit-signoff-policy-for-your-organization).
  > [!Note]
  > Signing off on a commit is different from signing a commit, such as with a GPG key.

### PR Approval

1. Changes are manually reviewed by [Engity's Bifröst](https://echocat.org) team members.
2. When the PR passes all tests, the PR is merged by the reviewer(s) in the GitHub [`main` branch](https://github.com/engity-com/bifroest/tree/main).

### Release process

#### Schedule

There are no fixed cycles for releases. Currently, they are triggered as soon bugfixes, security updates or main features arriving. 

#### Creation

First of all, prepare the release notes as usual, and merge them.

Once the release notes are ready, a release train is launched by *tagging* from `main` to `vX.Y.Z`.

#### Validation

The `vX.Y.Z` tag will go through the release CI.

If anything fails the release tag is dropped, the issue fixed in `main` and a new release train is started on a new tag.
