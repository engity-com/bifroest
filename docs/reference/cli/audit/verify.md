---
description: Verify a Bifröst audit journal.
---

# `bifroest audit verify`

Verifies signed `head.cbor`, producer identity, record and segment chains, seals, and file-name hashes up to a captured committed state. Bifröst can keep writing. Success produces no output and exits with status `0`. A sealed segment alone is not an accepted input.

For `.beaudit`, the outer signatures and encrypted bytes can be verified without a private decryption key. Supply a matching private SSH key with `--decryptionIdentityFile` to additionally authenticate and validate the confidential event fields in memory. Outer-only verification does not prove that the private fields can be decrypted. For clear `.baudit`, verification includes the private fields without a decryption key.

## Syntax

`bifroest audit verify [flags] <auditlogName>`

## Arguments

`auditlogName` selects a configured audit log by name, not a journal or segment path. A complete offline copy includes signed `head.cbor`.

## Flags {: #audit-verify-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-verify-", heading=3)>>
Configuration to load. It uses the same platform default as `bifroest run`.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-verify-", heading=3)>>
Optional private SSH key for full verification of encrypted event fields. Repeat the flag when verifying journals encrypted for different keys. Without it, `.beaudit` verification covers the signed outer structure only.

<<flag("expectedProducerId", "string", id_prefix="audit-verify-", heading=3)>>
Optional external trust anchor in the form `<auditlogName>=<producer-id>`, where the producer ID contains exactly 64 hexadecimal characters. On the Bifröst host, omit it to use the configured signing key. For an offline copy without that key, obtain the ID from [`audit producer-id`](producer-id.md) on the server and retain it through an independently trusted channel. A value read only from the journal being verified is not a trust anchor.

## Example

On the Bifröst host, verify without stopping the service. The default configuration and signing identity are used automatically:

```shell
bifroest audit verify default
```

For an offline copy without the signing private key, supply `--configuration` pointing to the copy and `--expectedProducerId "default=<trusted-64-hex-id>"`. See [Encrypted audit events](../../auditlog/index.md#encrypted-audit-events) for that workflow.
