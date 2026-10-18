---
description: Export Bifröst host keys as known_hosts entries.
---

# `bifroest key export host`

Creates `known_hosts` entries for an address without network access. With `--identityFile`, that key is loaded or generated. Otherwise all host keys from the selected configuration are loaded or generated.

## Syntax

<<cli_syntax("key export host")>>

## Arguments

None.

## Flags {: #key-export-host-flags }

Includes [all general flags](../../index.md#general-flags).

<<flag("configuration", "File Path", "../../../data-type.md#file-path", aliases=["c"], id_prefix="key-export-host-", heading=3)>>
Configuration to load when `identityFile` is absent. Defaults to the [platform path](../../usage.md#configuration).

<<flag("identityFile", "File Path", "../../../data-type.md#file-path", id_prefix="key-export-host-", heading=3)>>
Specific host private-key file to load or create. This cannot be combined with `configuration`.

<<flag("address", "string", required=True, id_prefix="key-export-host-", heading=3)>>
Host represented by the generated entries. Port `22` can be omitted; non-default IPv6 ports use `[address]:port`.

<<flag("output", ref("File Path", "../../../data-type.md#file-path"), default="-", id_prefix="key-export-host-", heading=3)>>
Output file. `-` writes to stdout.

<<flag("force", "bool", default=False, id_prefix="key-export-host-", heading=3)>>
Replaces an existing output file.

## Output

OpenSSH `known_hosts` entries on stdout or in the requested file. Configured or explicit local host keys are loaded or created; the command does not discover a server key over the network.

## Examples

### Provision trusted host keys for a management workstation

1. On the Bifröst host, use its actual configuration and address:

    ```shell
    bifroest key export host \
      --address bifroest.example.org \
      --output /srv/ssh-trust/bifroest-known-hosts
    ```

2. Transfer the public entries over an independently trusted channel and import them on the workstation with [`key import host`](../import/host.md).

    The [management guide](../../../../guides/management.md) uses these entries for SSH host-key checking. See [Bifröst delegation](../../../authorization/bifroest.md) for a complete host-key bootstrap sequence.

## Availability

<<cli_availability()>>

`--address` labels the generated entry; it does not connect to that host.
