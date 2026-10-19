---
description: Export the public key of a private SSH identity.
---

# `bifroest key export public`

Writes exactly one LF-terminated OpenSSH public-key line. Standard output is used by default. An existing destination file is not replaced unless `--force` is set.

Locally, select a private-key file. With `@target` or direct SSH, select a configured SSH flow: Bifröst exports its certificate subject identity, or the selected static `environment.identityFiles` entry. Private keys stay on the source machine; exporting never creates a missing server identity.

## Syntax

<<cli_syntax("key export public")>>

<<cli_syntax("key export public", "[flags] <flowName>", remote=True)>>

## Arguments

### `flowName` {: #argument-flowName }

Required with `@target` and direct SSH; not accepted locally. The SSH-environment flow whose configured identity is exported. Certificate flows have one subject identity at index `0`. Other SSH flows require an explicit, static `identityFiles` entry; session-dependent paths and implicit host-key fallback are not selected by this command.

## Flags {: #key-export-public-flags }

Includes [all general flags](../../index.md#general-flags).

<<flag("identityFile", "File Path", "../../../data-type.md#file-path", required=True, id_prefix="key-export-public-", heading=3)>>
Private key file whose public key is exported. Required locally; not accepted with `@target` or direct SSH.

<<flag("identityIndex", "unsigned integer", default="0", id_prefix="key-export-public-", heading=3)>>
Zero-based index in the selected server flow's `identityFiles`. Available with `@target` and direct SSH. For a certificate subject identity, only `0` is accepted.

<<flag("comment", "string", id_prefix="key-export-public-", heading=3)>>
Optional OpenSSH public-key comment. Line breaks are not accepted.

<<flag("output", ref("File Path", "../../../data-type.md#file-path"), default="-", id_prefix="key-export-public-", heading=3)>>
Output file on the CLI machine. `-` writes to stdout. Direct SSH always writes to stdout and does not accept `output` or `force`.

<<flag("force", "bool", default=False, id_prefix="key-export-public-", heading=3)>>
Replaces an existing output file. Without this flag, an existing file is never modified.

## Output

One LF-terminated OpenSSH public-key line, on stdout or in the requested file. The private key is not modified or emitted.

## Examples

### Export a recipient's public key after generating its private key

1. Generate a recipient with [`key generate`](../generate.md), or select an existing private identity.
2. Export its public half on the workstation:

    ```shell
    bifroest key export public \
      --identityFile /srv/audit-keys/recipient-key \
      --output /srv/audit-keys/recipient-key.pub
    ```

    Choose a new output path; `--force` is required to replace an existing public-key file. See [the encrypted-evidence guide](../../../../guides/evidence.md) for server configuration using this public key.

### Export a configured server identity

1. Configure the `gateway` certificate flow and workstation alias in [Export server public keys remotely](../../../../guides/keys.md).
2. Export its subject public key to the workstation:

    ```shell title="Administrator workstation"
    bifroest @bifroest-admin key export public gateway --output gateway-subject.pub
    ```

    For an SSH flow using several static identity files, add `--identityIndex=1` to select its second entry. The server does not accept an `identityFile` path from the client.

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>
