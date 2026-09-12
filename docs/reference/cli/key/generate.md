---
description: Generate a new Ed25519 key pair.
---

# `bifroest key generate`

Creates an Ed25519 private key in OpenSSH format. The command never replaces an existing file and never writes private key material to stdout. Private files use mode `0400` on Unix and a protected DACL on Windows.

If `--publicFile` is set, the corresponding public key is additionally written as one LF-terminated OpenSSH public-key line.

## Syntax

`bifroest key generate [flags]`

## Flags {: #key-generate-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("identityFile", "File Path", "../../data-type.md#file-path", required=True, id_prefix="key-generate-", heading=3)>>
Private key file to create.

<<flag("publicFile", "File Path", "../../data-type.md#file-path", id_prefix="key-generate-", heading=3)>>
Optional public key file to create. It has to differ from `identityFile` and is never replaced. This explicit output does not enable automatic `.pub` companion files.

## Example

See [Encrypted audit events](../../auditlog/index.md#encrypted-audit-events) for an example that creates a dedicated audit-encryption key pair.
