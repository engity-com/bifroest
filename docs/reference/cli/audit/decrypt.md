---
description: Verify and decrypt a Bifröst audit journal.
---

# `bifroest audit decrypt`

Decrypts and fully verifies the selected configured journal before writing plaintext JSON Lines. For an unencrypted journal this is equivalent to `audit export`. The command never modifies the source journal and never emits partial output after a verification or decryption failure.

## Syntax

`bifroest audit decrypt [flags] <auditlogName>`

## Arguments

`auditlogName` selects one configured audit log.

## Flags {: #audit-decrypt-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-decrypt-", heading=3)>>
Configuration to load. It uses the same platform default as `bifroest run`.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-decrypt-", heading=3)>>
Private SSH key used to decrypt encrypted event payloads. Repeat the flag when needed. A matching key is required for an encrypted audit log.

<<flag("output", ref("File Path", "../../data-type.md#file-path"), default="-", id_prefix="audit-decrypt-", heading=3)>>
Output file. `-` writes plaintext JSON Lines to stdout. Output paths inside the journal or equal to a signing identity, decryption identity, or referenced encryption public-key file are rejected.

<<flag("force", "bool", default=False, id_prefix="audit-decrypt-", heading=3)>>
Replaces an existing output file.

## Example

See [Encrypted audit events](../../auditlog/index.md#encrypted-audit-events) for a decryption example.
