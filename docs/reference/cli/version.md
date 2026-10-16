---
description: Print Bifröst version and build information.
---

# `bifroest version` {: #version }

Prints the version of the current Bifröst executable. Long output additionally includes build, revision, edition, platform, vendor, and feature information.

## Syntax

`bifroest version [flags]`

## Flags {: #version-flags }

Includes [all general flags](index.md#general-flags).

<<flag("long", "bool", default=True, id_prefix="version-", heading=3)>>
Controls whether detailed build information is printed. Detailed output is the default. Use `--long=false` for the short version format; `--long` (or `--long=true`) selects detailed output explicitly. This also applies to remote management commands.
