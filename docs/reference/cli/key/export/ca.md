---
description: Export the SSH certificate authority of a Bifröst flow.
---

# `bifroest key export ca`

Loads the selected configuration and exports the effective SSH certificate authority of the selected flow. If the private CA does not exist, it is generated before its public key is exported. No `.pub` companion file is created.

## Syntax

<<cli_syntax("key export ca", "[flags] <flowName>")>>

## Arguments

### `flowName` {: #argument-flowName }

`flowName` is the name of an SSH-environment flow with certificate authentication enabled.

## Flags {: #key-export-ca-flags }

Includes [all general flags](../../index.md#general-flags).

<<flag("configuration", "File Path", "../../../data-type.md#file-path", aliases=["c"], id_prefix="key-export-ca-", heading=3)>>
Configuration to load; defaults to the [platform path](../../usage.md#configuration).

<<flag("output", ref("File Path", "../../../data-type.md#file-path"), default="-", id_prefix="key-export-ca-", heading=3)>>
Output file. `-` writes exactly one LF-terminated OpenSSH public-key line to stdout.

<<flag("force", "bool", default=False, id_prefix="key-export-ca-", heading=3)>>
Replaces an existing output file.

## Output

One OpenSSH CA public-key line, on stdout or in the requested file. A missing effective private CA is generated as part of this bootstrap command.

## Examples

### Export the CA of an SSH-environment flow

1. Configure the certificate-authenticated `openssh` flow in [the SSH-environment example](../../../environment/ssh.md#openssh-certificate-authentication).
2. Export the effective public CA:

    ```shell
    bifroest key export ca openssh --output /srv/ssh-trust/bifroest-ca.pub
    ```

    Use the actual configured flow name and an existing output directory. Continue with the target's CA setup in that example, or the full [Bifröst delegation workflow](../../../authorization/bifroest.md).

## Availability

<<cli_availability()>>
