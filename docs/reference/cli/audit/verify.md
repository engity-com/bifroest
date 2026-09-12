---
description: Verify a Bifröst audit journal.
---

# `bifroest audit verify`

Verifies the journal head, embedded Ed25519 keys, record signatures, record and segment hash chains, segment seals, file-name hashes, and the configured producer identity. Success produces no output and exits with status `0`.

For an audit log configured with encryption, supply the matching private SSH key. Verification decrypts and authenticates every event payload in memory in addition to checking the journal structure.

## Syntax

`bifroest audit verify [flags] <auditlogName>`

## Arguments

`auditlogName` selects one configured audit log.

## Flags {: #audit-verify-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-verify-", heading=3)>>
Configuration to load. It uses the same platform default as `bifroest run`.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-verify-", heading=3)>>
Private SSH key used to decrypt encrypted event payloads. Repeat the flag when verifying journals encrypted for different keys. It is required when an encryption recipient is configured.

## Example

See [Encrypted audit events](../../auditlog/index.md#encrypted-audit-events) for a verification example.
