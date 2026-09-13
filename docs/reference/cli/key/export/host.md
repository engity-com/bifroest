---
description: Export Bifröst host keys as known_hosts entries.
---

# `bifroest key export host`

Creates `known_hosts` entries for an address without network access. With `--identityFile`, that key is loaded or generated. Otherwise all host keys from the selected configuration are loaded or generated.

## Syntax

`bifroest key export host [flags]`

## Flags {: #key-export-host-flags }

Includes [all general flags](../../index.md#general-flags).

<<flag("configuration", "File Path", "../../../data-type.md#file-path", aliases=["c"], id_prefix="key-export-host-", heading=3)>>
Configuration to load when `identityFile` is absent. It uses the same platform default as `bifroest run`.

<<flag("identityFile", "File Path", "../../../data-type.md#file-path", id_prefix="key-export-host-", heading=3)>>
Specific host private-key file to load or create. This cannot be combined with `configuration`.

<<flag("address", "string", required=True, id_prefix="key-export-host-", heading=3)>>
Host represented by the generated entries. Port `22` can be omitted; non-default IPv6 ports use `[address]:port`.

<<flag("output", ref("File Path", "../../../data-type.md#file-path"), default="-", id_prefix="key-export-host-", heading=3)>>
Output file. `-` writes to stdout.

<<flag("force", "bool", default=False, id_prefix="key-export-host-", heading=3)>>
Replaces an existing output file.

## Example

See [Bifröst delegation authorization](../../../authorization/bifroest.md) for a host-key bootstrap sequence.
