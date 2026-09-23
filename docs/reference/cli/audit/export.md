---
description: Verify and export a Bifröst audit journal.
---

# `bifroest audit export`

Verifies the selected journal before writing its records as JSON Lines in cryptographic chain order. By default only the signed public event fields and provenance metadata are included, for both `.baudit` and `.beaudit`. Export uses bounded in-memory materialization and refuses output exceeding 128 MiB; `audit verify` remains available for larger journals without materializing records.

Use `--with-sensitive` to include confidential event fields. For `.beaudit`, this also requires the matching `--decryptionIdentityFile` and verifies the decrypted content. A redacted export of `.beaudit` needs no decryption identity. JSON Lines are an unsigned view, not a substitute for the original container.

## Syntax

`bifroest audit export [flags] <auditlogName>`

## Arguments

`auditlogName` selects one configured audit log.

## Flags {: #audit-export-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-export-", heading=3)>>
Configuration to load. It uses the same platform default as `bifroest run`.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-export-", heading=3)>>
Private SSH key required together with `--with-sensitive` for encrypted event fields. Repeat the flag when needed.

<<flag("with-sensitive", "bool", default=False, id_prefix="audit-export-", heading=3)>>
Explicitly include confidential event fields in the JSON Lines output. This does not make the output encrypted; protect the destination accordingly.

<<flag("expectedProducerId", "string", id_prefix="audit-export-", heading=3)>>
External trust anchor in the form `<auditlogName>=<64-hex-producer-id>`. Repeat when needed. For a source with this flag, the configured signing private key is not opened and may be absent. The value must come from an independently trusted channel.

<<flag("output", ref("File Path", "../../data-type.md#file-path"), default="-", id_prefix="audit-export-", heading=3)>>
Output file. `-` writes JSON Lines to stdout. The output file's immediate parent directory must already exist; the command does not create missing output directories. The parent is opened without following links where the platform supports it and remains pinned through the final safety check and atomic installation. Output paths inside any enabled configured journal, or equal to the signing identity or referenced encryption public-key file of any enabled configured audit log, are rejected. Supplied decryption identities are also protected.

<<flag("force", "bool", default=False, id_prefix="audit-export-", heading=3)>>
Replaces an existing output file.
