---
description: Generate a new Ed25519 key pair.
---

# `bifroest key generate`

Creates an Ed25519 private key in OpenSSH format. The command never replaces an existing file and never writes private key material to stdout. Private files use mode `0400` on Unix and a protected DACL on Windows.

If `--publicFile` is set, the corresponding public key is additionally written as one LF-terminated OpenSSH public-key line.

## Syntax

<<cli_syntax("key generate")>>

## Arguments

None.

## Flags {: #key-generate-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("identityFile", "File Path", "../../data-type.md#file-path", required=True, id_prefix="key-generate-", heading=3)>>
Private key file to create.

<<flag("publicFile", "File Path", "../../data-type.md#file-path", id_prefix="key-generate-", heading=3)>>
Optional public key file to create. It has to differ from `identityFile` and is never replaced. This explicit output does not enable automatic `.pub` companion files.

## Output

The requested private key and optional public-key file. Private key material is never written to stdout. Existing destination files are not replaced.

## Examples

### Create a dedicated evidence-encryption recipient

1. On the trusted workstation, prepare a private directory for the recipient key.
2. Generate the pair:

    ```shell
    bifroest key generate \
      --identityFile /srv/audit-keys/recipient-key \
      --publicFile /srv/audit-keys/recipient-key.pub
    ```

3. Transfer only the public key and configure its server-side use following [the encrypted-evidence guide](../../../guides/evidence.md). The full [audit configuration example](../../auditlog/index.md#encrypted-audit-events) also covers disconnected verification.

## Availability

<<cli_availability()>>
