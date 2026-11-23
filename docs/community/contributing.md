---
description: Technical contributions to Bifröst and corresponding guidelines.
---
# Contributing Guidelines

Contributions are welcome via [GitHub Pull Requests](https://docs.github.com/articles/about-pull-requests) ("PR"). This document outlines the process to help you get your contribution accepted.

Any kind of contribution is welcome, from adding new features or bug fixes to improving the documentation. However, [Engity](https://engity.com) will review the proposals and perform a triage over them. By doing so, we will ensure that the most valuable contributions for the community will be implemented in due time.

## How to Contribute

1. [Fork this repository](https://github.com/engity-com/bifroest/fork), develop, and test your changes.
2. [Submit a pull request](https://docs.github.com/articles/creating-a-pull-request).
3. Read and agree to our <<asset_link("CLA.md", "Contributor License Agreement")>> as requested in the pull request.

### Technical Requirements

When submitting a Pull Request ("PR"), make sure that it:

- Must pass CI jobs/actions.
- Must follow [Golang best practices](https://go.dev/doc/effective_go).
- Is signed off with the line `Signed-off-by: <Your-Name> <Your-email>`. [Learn more about signing off on commits](https://docs.github.com/en/organizations/managing-organization-settings/managing-the-commit-signoff-policy-for-your-organization).

    !!! Note
        Signing-off a commit is different from signing a commit, such as with a GPG key.

### PR Approval

1. Changes are manually reviewed by [Engity's Bifröst](https://echocat.org) team members.
2. When the PR passes all tests, the PR is merged by the reviewer(s) in the GitHub [`main` branch](https://github.com/engity-com/bifroest/tree/main).

### Offline testing checks

The <<asset_link("pkg/test/README.md", "testing package and examples")>> live
together under `pkg/test`. To write configuration tests, use the
[guide](../guides/testing.md) and [reference](../reference/testing/index.md).
The repository's <<asset_link("test/policyci/README.md", "CLI comparison harness")>>
documents prerequisites, commands and output artifacts for developer-only
native/container checks. Attach verification results to CI runs or the PR,
rather than maintaining execution logs in the repository.

The separate service integration tests that invoke `ssh` need a client native
to the OS running the tests. In WSL/Linux, a Windows `ssh.exe` cannot use Linux
temporary paths. Select a suitable client through the test process's `PATH`
without replacing the user's global SSH installation. The offline runner itself
does not launch SSH clients.

Lua source checks are repository tools, not Bifröst subcommands:

```shell
mise run lint:lua
mise run format:lua
```

StyLua is pinned in `.tool-versions`. Install [Luacheck 1.2.0](https://github.com/lunarmodules/luacheck)
separately: `luarocks install luacheck 1.2.0-1` on Linux/macOS, or the upstream
native `luacheck.exe` release on Windows (no WSL required). Both must be on
`PATH` for `mise run lint:lua`. CI installs the same Luacheck version and runs
the read-only lint/format checks. `.luacheckrc` declares only the runner's real
read-only globals; unknown globals, unused code and formatting drift still fail.

The examples stay within Lua 5.4-compatible syntax for these tools; Bifröst's
embedded GoLua runtime remains unchanged. Static analysis is not policy execution
or a security sandbox. The Lua tools are not runtime/distribution dependencies.

Optional <<asset_link("pkg/test/types/README.md", "Lua editor declarations")>>
provide completion/navigation hints for compatible GoLand Lua plugins and LuaLS,
without changing runtime globals or committing personal IDE settings.

### Release process

#### Schedule

There are no fixed cycles for releases. Currently, they are triggered as soon as bugfixes, security updates or main features arrive.

#### Creation

Prepare release notes for the GitHub Release description separately from
operator-facing upgrade instructions in `docs/setup/upgrade.md`. For a new minor
release, replace that upgrade page with guidance from the preceding minor
series, or state explicitly that no action is necessary. Patch releases
normally retain their minor series' upgrade instructions. Merge changes to
the versioned documentation before tagging, and link the published upgrade
page from the GitHub Release description.

Once the release notes are ready, a release train is launched by *tagging* from `main` to `vX.Y.Z`.

#### Validation

The `vX.Y.Z` tag will go through the release CI.
