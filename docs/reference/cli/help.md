---
description: Show help for Bifröst CLI commands.
---

# `bifroest --help`

Shows command-line help for Bifröst or for a selected command path.

## Syntax

<<cli_syntax("", "[<command>...] --help", flag_prefix="help")>>

<<cli_syntax("", "<command>... --help", remote=True, flag_prefix="help")>>

## Arguments

### `command` {: #argument-command }

`command` is an optional sequence such as `audit verify` or `key export public`. Without it, Bifröst shows the root help.

## Flags {: #help-flags }

<<flag("help", "bool", default=False, aliases=["h"], id_prefix="help-", heading=3)>>
Shows help without running the selected command. For a remote target, help describes the commands and flags available to the integrated management client and does not open an SSH connection. See [general flags](index.md#general-flags).

## Examples

```shell
bifroest --help
bifroest audit verify --help
bifroest @bifroest-admin recording play --help
```

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>
