---
description: Verify and export a Bifröst audit journal.
---

# `bifroest audit export`

Verifies the selected complete journal, including its signed head, before writing its records as JSON Lines in cryptographic chain order. By default the event contains only `name`, `domain`, and `outcome` when present; timestamps, record IDs, and chain provenance appear in a separate envelope. This applies to both clear `.baudit` and encrypted `.beaudit`. Even redacted metadata may be sensitive; protect the output. Export uses bounded in-memory materialization and refuses output exceeding 128 MiB; `audit verify` remains available for larger journals without materializing records.

Use `--with-sensitive` to include confidential event fields. For `.beaudit`, this also requires the matching `--decryptionIdentityFile` and verifies the decrypted content. A redacted export of `.beaudit` needs no decryption identity. JSON Lines are an unsigned view, not a substitute for the original container.

## Syntax

`bifroest audit export [flags] <auditlogName>`

## Arguments

`auditlogName` selects one configured audit log by name, not a segment path. Remote sealed segments alone lack the signed head and cannot be exported with this command.

## Flags {: #audit-export-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-export-", heading=3)>>
Configuration to load. It uses the same platform default as `bifroest run`.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-export-", heading=3)>>
Private SSH key required together with `--with-sensitive` for encrypted event fields. Repeat the flag when needed. Without `--with-sensitive`, supplied decryption identities are not loaded or used for the redacted export.

<<flag("with-sensitive", "bool", default=False, id_prefix="audit-export-", heading=3)>>
Explicitly include confidential event fields in the JSON Lines output. This does not make the output encrypted; protect the destination accordingly.

<<flag("expectedProducerId", "string", id_prefix="audit-export-", heading=3)>>
External trust anchor in the form `<auditlogName>=<64-hex-producer-id>`. Repeat when needed. For a source with this flag, the configured signing private key is not opened and may be absent. The value must come from an independently trusted channel.

<<flag("output", ref("File Path", "../../data-type.md#file-path"), default="-", id_prefix="audit-export-", heading=3)>>
Output file. `-` writes JSON Lines to stdout. The output file's immediate parent directory must already exist; the command does not create missing output directories. The parent is opened without following links where the platform supports it and remains pinned through the final safety check and atomic installation. Output paths inside any enabled configured journal or enabled recording repository, or aliasing a journal file, the loaded configuration file, a signing identity or a referenced encryption public-key file are rejected. Supplied decryption identities are also protected. When stdout is a regular file, the command rejects descriptors pointing to protected files, including journal heads and segments; normal pipes remain supported. Shell redirection with `>` can truncate a file before the command starts, so do not redirect stdout to protected files.

<<flag("force", "bool", default=False, id_prefix="audit-export-", heading=3)>>
Replaces an existing output file.
