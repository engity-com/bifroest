---
description: Verify and merge multiple Bifröst audit journals.
---

# `bifroest audit merge`

Verifies every selected journal before producing one deterministic JSON Lines stream. Records are ordered by their producer-signed timestamp and stable origin and chain-position tie-breakers. Timestamps are statements by their producers and are not an independently trusted clock. Merge refuses inputs exceeding its bounded materialization safety limit.

Clear and encrypted journals can be merged together. The default JSON Lines output contains only public fields. To include private fields, supply `--with-sensitive` and the decryption identities for every encrypted source.

## Syntax

`bifroest audit merge [flags] <auditlogName>...`

## Arguments

`auditlogName` selects one or more configured audit logs.

## Flags {: #audit-merge-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-merge-", heading=3)>>
Configuration to load. It uses the same platform default as `bifroest run`.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-merge-", heading=3)>>
Private SSH key required with `--with-sensitive` for encrypted event fields. Repeat for sources encrypted for different keys. Without `--with-sensitive`, supplied decryption identities are not loaded or used for the redacted merge.

<<flag("with-sensitive", "bool", default=False, id_prefix="audit-merge-", heading=3)>>
Explicitly include confidential event fields in the merged JSON Lines stream. The output is plaintext and must be protected.

<<flag("expectedProducerId", "string", id_prefix="audit-merge-", heading=3)>>
External trust anchor in the form `<auditlogName>=<64-hex-producer-id>`. Repeat for selected sources whose configured signing private keys must not be opened or are absent. Every mapping must name a selected source, and the values must come from independently trusted channels.

<<flag("output", ref("File Path", "../../data-type.md#file-path"), default="-", id_prefix="audit-merge-", heading=3)>>
Output file. `-` writes JSON Lines to stdout. The output file's immediate parent directory must already exist; the command does not create missing output directories. The parent is opened without following links where the platform supports it and remains pinned through the final safety check and atomic installation. Output paths inside any enabled configured journal, or aliasing a journal file, the loaded configuration file, a signing identity or a referenced encryption public-key file are rejected, including logs not selected for the merge. Supplied decryption identities are also protected. When stdout is a regular file, the command rejects descriptors pointing to protected files, including journal heads and segments; normal pipes remain supported. Shell redirection with `>` can truncate a file before the command starts, so do not redirect stdout to protected files.

<<flag("force", "bool", default=False, id_prefix="audit-merge-", heading=3)>>
Replaces an existing output file.
