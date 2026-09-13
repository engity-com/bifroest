---
description: Verify and export a Bifröst audit journal.
---

# `bifroest audit export`

Verifies the selected journal completely before writing its records as JSON Lines in cryptographic chain order. Export uses bounded in-memory materialization and refuses output exceeding 128 MiB; `audit verify` remains available for larger journals without materializing records.

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

<<flag("expectedProducerId", "string", id_prefix="audit-export-", heading=3)>>
External trust anchor in the form `<auditlogName>=<64-hex-producer-id>`. Repeat when needed. For a source with this flag, the configured signing private key is not opened and may be absent. The value must come from an independently trusted channel.

<<flag("output", ref("File Path", "../../data-type.md#file-path"), default="-", id_prefix="audit-export-", heading=3)>>
Output file. `-` writes JSON Lines to stdout. The output file's immediate parent directory must already exist; the command does not create missing output directories. The parent is opened without following links where the platform supports it and remains pinned through the final safety check and atomic installation. Output paths inside any enabled configured journal, or equal to the signing identity or referenced encryption public-key file of any enabled configured audit log, are rejected. Supplied decryption identities are also protected.

<<flag("force", "bool", default=False, id_prefix="audit-export-", heading=3)>>
Replaces an existing output file.
