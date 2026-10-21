---
description: Print Bifröst version and build information.
---

# `bifroest version` {: #version }

Prints the version of the current Bifröst executable. Long output additionally includes build, revision, edition, platform, vendor, and feature information.

## Syntax

<<cli_syntax("version")>>

<<cli_syntax("version", remote=True)>>

## Arguments

None.

## Flags {: #version-flags }

Includes [all general flags](index.md#general-flags).

<<flag("long", "bool", default=True, id_prefix="version-", heading=3)>>
Controls whether detailed build information is printed. Detailed output is the default. Use `--long=false` for the short version format; `--long` (or `--long=true`) selects detailed output explicitly. This also applies to remote management commands.

## Output

Version text on stdout. Long output includes the build, revision, edition, platform, vendor and enabled features. There is no `--format` flag.

## Examples

### Compare workstation and server versions

1. Inspect the workstation binary:

    ```shell
    bifroest version --long=false
    ```

2. With the [management alias](../../guides/management.md) configured, inspect the server:

    ```shell
    bifroest @bifroest-admin version --long=false
    ```

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>

Remote queries report the server's version; they do not require artifact-transfer permission.
