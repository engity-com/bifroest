---
description: Show help for Bifröst CLI commands.
---

# `bifroest --help`

Shows command-line help for Bifröst or for a selected command path.

## Syntax

`bifroest [<command>...] --help`

`bifroest @target <command>... --help`

## Arguments

`command` is an optional sequence such as `audit verify` or `key export public`. Without it, Bifröst shows the root help.

## Flags

`-h` and `--help` show help for the selected command without executing its handler. For a remote target, help describes the commands and flags available to the integrated management client and does not open an SSH connection. See [general flags](index.md#general-flags).

## Example

```shell
bifroest --help
bifroest audit verify --help
bifroest @bifroest-admin recording play --help
```
