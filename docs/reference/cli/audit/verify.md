---
description: Verify a Bifröst audit journal.
---

# `bifroest audit verify`

Verifies the signed `head.cbor`, embedded Ed25519 keys, record signatures, record and segment hash chains, segment seals, file-name hashes, and the configured producer identity. Success produces no output and exits with status `0`.

For `.beaudit`, the outer signatures and encrypted bytes can be verified without a private decryption key. Supply a matching private SSH key to additionally authenticate and validate the confidential event fields in memory. Outer-only verification does not prove that the private fields can be decrypted.

## Syntax

`bifroest audit verify [flags] <auditlogName>`

## Arguments

`auditlogName` selects one configured audit log.

## Flags {: #audit-verify-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-verify-", heading=3)>>
Configuration to load. It uses the same platform default as `bifroest run`.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-verify-", heading=3)>>
Optional private SSH key for full verification of encrypted event fields. Repeat the flag when verifying journals encrypted for different keys. Without it, `.beaudit` verification covers the signed outer structure only.

<<flag("expectedProducerId", "string", id_prefix="audit-verify-", heading=3)>>
External trust anchor in the form `<auditlogName>=<producer-id>`, where the producer ID contains exactly 64 hexadecimal characters. This command selects exactly one source, and the mapping must name that selected `auditlogName`. When supplied, the configured signing private key for that source is not opened and may be absent. Obtain the value through an independently trusted channel; a value read only from the journal being verified is not a trust anchor.

## Example

Verify without granting access to the production signing private key:

```shell
bifroest audit verify \
  --expectedProducerId default=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  default
```

See [Encrypted audit events](../../auditlog/index.md#encrypted-audit-events) for an encrypted-journal example.
