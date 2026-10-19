---
description: Export the SSH certificate authority of a Bifröst flow.
---

# `bifroest key export ca`

Exports the public SSH certificate authority of the selected flow. Locally, Bifröst loads the selected configuration and creates a missing private CA. With `@target` or direct SSH, it exports the running flow's existing CA without creating or changing a key. No `.pub` companion file is created on the server.

## Syntax

<<cli_syntax("key export ca", "[flags] <flowName>")>>

<<cli_syntax("key export ca", "[flags] <flowName>", remote=True)>>

## Arguments

### `flowName` {: #argument-flowName }

`flowName` is the name of an SSH-environment flow with certificate authentication enabled.

## Flags {: #key-export-ca-flags }

Includes [all general flags](../../index.md#general-flags).

<<flag("configuration", "File Path", "../../../data-type.md#file-path", aliases=["c"], id_prefix="key-export-ca-", heading=3)>>
Local configuration to load; defaults to the [platform path](../../usage.md#configuration). Not accepted with `@target` or direct SSH.

<<flag("output", ref("File Path", "../../../data-type.md#file-path"), default="-", id_prefix="key-export-ca-", heading=3)>>
Output file on the CLI machine. `-` writes exactly one LF-terminated OpenSSH public-key line to stdout. Direct SSH always writes to stdout and does not accept `output` or `force`.

<<flag("force", "bool", default=False, id_prefix="key-export-ca-", heading=3)>>
Replaces an existing output file.

## Output

One OpenSSH CA public-key line, on stdout or in the requested file. Only a local bootstrap invocation can generate a missing effective private CA.

## Examples

### Export the CA of an SSH-environment flow

1. Configure the certificate-authenticated `openssh` flow in [the SSH-environment example](../../../environment/ssh.md#openssh-certificate-authentication).
2. Export the effective public CA:

    ```shell
    bifroest key export ca openssh --output /srv/ssh-trust/bifroest-ca.pub
    ```

    Use the actual configured flow name and an existing output directory. Continue with the target's CA setup in that example, or the full [Bifröst delegation workflow](../../../authorization/bifroest.md).

### Export the running server's CA

1. Configure the `gateway` flow and management alias in [the public-key export guide](../../../../guides/keys.md).
2. Export its active CA to a file on the workstation:

    ```shell title="Administrator workstation"
    bifroest @bifroest-admin key export ca gateway --output gateway-ca.pub
    ```

    An authorized management flow can perform this public export without `allowArtifactTransfer` or `includingCredentials`. Direct SSH supports `ssh management@bifroest.example.org 'key export ca gateway'`.

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>
