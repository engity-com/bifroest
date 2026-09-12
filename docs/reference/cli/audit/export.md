---
description: Verify and export a Bifröst audit journal.
---

# `bifroest audit export`

Verifies the selected journal completely before writing its records as JSON Lines in cryptographic chain order. Export uses bounded in-memory materialization and refuses histories exceeding its safety limit; `audit verify` remains available for larger journals without materializing records.

Encrypted audit logs require the matching `--decryptionIdentityFile`; exported event payloads are always plaintext.

## Syntax

`bifroest audit export [flags] <auditlogName>`

## Arguments

`auditlogName` selects one configured audit log.

## Flags {: #audit-export-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-export-", heading=3)>>
Configuration to load. It uses the same platform default as `bifroest run`.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-export-", heading=3)>>
Private SSH key used to decrypt encrypted event payloads. Repeat the flag when needed.

<<flag("output", ref("File Path", "../../data-type.md#file-path"), default="-", id_prefix="audit-export-", heading=3)>>
Output file. `-` writes JSON Lines to stdout. Output paths inside the journal or equal to its signing identity, a supplied decryption identity, or its referenced encryption public-key file are rejected.

<<flag("force", "bool", default=False, id_prefix="audit-export-", heading=3)>>
Replaces an existing output file.
