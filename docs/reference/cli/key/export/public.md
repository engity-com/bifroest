---
description: Export the public key of a private SSH identity.
---

# `bifroest key export public`

Writes exactly one LF-terminated OpenSSH public-key line. Standard output is used by default. An existing destination file is not replaced unless `--force` is set.

## Syntax

<<cli_syntax("key export public")>>

## Arguments

None.

## Flags {: #key-export-public-flags }

Includes [all general flags](../../index.md#general-flags).

<<flag("identityFile", "File Path", "../../../data-type.md#file-path", required=True, id_prefix="key-export-public-", heading=3)>>
Private key file whose public key is exported.

<<flag("comment", "string", id_prefix="key-export-public-", heading=3)>>
Optional OpenSSH public-key comment. Line breaks are not accepted.

<<flag("output", ref("File Path", "../../../data-type.md#file-path"), default="-", id_prefix="key-export-public-", heading=3)>>
Output file. `-` writes to stdout.

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

## Availability

<<cli_availability()>>
