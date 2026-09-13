---
description: Verify and merge multiple Bifröst audit journals.
---

# `bifroest audit merge`

Verifies every selected journal before producing one deterministic JSON Lines stream. Records are ordered by their producer-signed timestamp and stable origin and chain-position tie-breakers. Timestamps are statements by their producers and are not an independently trusted clock. Merge refuses inputs exceeding its bounded materialization safety limit.

Plaintext and encrypted journals can be merged together. Supply every required private key by repeating `--decryptionIdentityFile`.

## Syntax

`bifroest audit merge [flags] <auditlogName>...`

## Arguments

`auditlogName` selects one or more configured audit logs.

## Flags {: #audit-merge-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-merge-", heading=3)>>
Configuration to load. It uses the same platform default as `bifroest run`.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-merge-", heading=3)>>
Private SSH key used to decrypt encrypted event payloads. Repeat the flag for journals encrypted for different keys.

<<flag("expectedProducerId", "string", id_prefix="audit-merge-", heading=3)>>
External trust anchor in the form `<auditlogName>=<64-hex-producer-id>`. Repeat for selected sources whose configured signing private keys must not be opened or are absent. Every mapping must name a selected source, and the values must come from independently trusted channels.

<<flag("output", ref("File Path", "../../data-type.md#file-path"), default="-", id_prefix="audit-merge-", heading=3)>>
Output file. `-` writes JSON Lines to stdout. Output paths inside any enabled configured journal, or equal to the signing identity or referenced encryption public-key file of any enabled configured audit log, are rejected, including logs not selected for the merge. Supplied decryption identities are also protected.

<<flag("force", "bool", default=False, id_prefix="audit-merge-", heading=3)>>
Replaces an existing output file.
