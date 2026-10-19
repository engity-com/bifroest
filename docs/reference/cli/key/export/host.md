---
description: Export Bifröst host keys as known_hosts entries.
---

# `bifroest key export host`

Exports `known_hosts` entries for the supplied address. Locally, `--identityFile` selects a key to load or create; otherwise the configured host keys are loaded or created. With `@target` or direct SSH, the running server's active host keys are exported without creating or changing any key.

## Syntax

<<cli_syntax("key export host")>>

<<cli_syntax("key export host", "[flags]", remote=True)>>

`--address` labels the exported entries; it does not connect to that address. A remote invocation connects only to the management target.

## Arguments

None.

## Flags {: #key-export-host-flags }

Includes [all general flags](../../index.md#general-flags).

<<flag("configuration", "File Path", "../../../data-type.md#file-path", aliases=["c"], id_prefix="key-export-host-", heading=3)>>
Local configuration to load when `identityFile` is absent. Defaults to the [platform path](../../usage.md#configuration). Not accepted with `@target` or direct SSH.

<<flag("identityFile", "File Path", "../../../data-type.md#file-path", id_prefix="key-export-host-", heading=3)>>
Specific local host private-key file to load or create. This cannot be combined with `configuration` and is not accepted with `@target` or direct SSH.

<<flag("address", "string", required=True, id_prefix="key-export-host-", heading=3)>>
Host represented by the generated entries. Port `22` can be omitted; non-default IPv6 ports use `[address]:port`.

<<flag("output", ref("File Path", "../../../data-type.md#file-path"), default="-", id_prefix="key-export-host-", heading=3)>>
Output file on the CLI machine. `-` writes to stdout. Direct SSH always writes to stdout and does not accept `output` or `force`.

<<flag("force", "bool", default=False, id_prefix="key-export-host-", heading=3)>>
Replaces an existing output file.

## Output

OpenSSH `known_hosts` entries on stdout or in the requested file. Remote export returns the keys already used by the running Bifröst server; it is not a host-key discovery or unknown-key acceptance command.

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

### Export active host keys over an already trusted connection

1. Provision management SSH trust and configure the workstation alias as in [the management guide](../../../../guides/management.md).
2. Export the server's active public keys:

    ```shell title="Administrator workstation"
    bifroest @bifroest-admin key export host \
      --address bifroest.example.org \
      --output bifroest-known-hosts
    ```

    The initial management connection still needs a trusted `known_hosts` entry. This command cannot bootstrap its own unknown host key. Direct SSH supports `ssh management@bifroest.example.org 'key export host --address=bifroest.example.org'`.

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>
