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
Controls whether detailed build information is printed. Use `--no-long` for the short version format.
