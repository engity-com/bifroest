# Contributing Guidelines

Contributions are welcome via [GitHub Pull Requests](https://docs.github.com/articles/about-pull-requests) ("PR"). This document outlines the process to help get your contribution accepted.

Any kind of contribution is welcome, from new features to bug fixes to documentation improvements. However, [Engity](https://engity.com) will review the proposals and perform a triage over them. By doing so, we will ensure that the most valuable contributions for the community will be implemented in due time.

## How to Contribute

1. [Fork this repository](https://github.com/engity-com/bifroest/fork), develop, and test your changes.
2. [Submit a pull request](https://docs.github.com/articles/creating-a-pull-request).
3. Read and agree to our [Contributor License Agreement](CLA.md) as requested in the pull request.

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

There are no fixed cycles for releases. Currently, they are triggered as soon bugfixes, security updates, or main features arrive.

#### Creation

Prepare the GitHub Release notes separately from the versioned upgrade notes.
Release notes belong in the GitHub Release description; `docs/setup/upgrade.md`
contains only operator-relevant upgrade instructions and behavior. Merge any
required upgrade documentation before tagging the release.

For a new minor release, replace the contents of `docs/setup/upgrade.md` with the
upgrade notes from the preceding minor series. If no action is necessary, say so
explicitly. Patch releases normally reuse their minor series' upgrade notes;
document exceptional patch-specific upgrade requirements when they arise. The
documentation is published separately for every release, so older upgrade notes
remain available in the corresponding versioned documentation. Link the
versioned upgrade page from the GitHub Release description when publishing it.
Keep the target version in the page derived from the release tag rather than
hard-coding it in the Markdown.

Once the release notes are ready, a release train is launched by *tagging* from `main` to `vX.Y.Z`, `vX.Y.Z-alphaN`, or `vX.Y.Z-betaN` (positive integers without leading zeros). Mark alpha and beta GitHub releases as prereleases, and stable releases as non-prereleases. The GitHub "Latest" selection remains a manual release decision. OCI images for prereleases use only full version tags; moving tags such as `latest` are reserved for stable releases.

#### Validation

The release tag will go through the release CI, which checks the tag syntax and GitHub prerelease flag before building or publishing.

If anything fails the release tag is dropped, the issue fixed in `main` and a new release train is started on a new tag.
