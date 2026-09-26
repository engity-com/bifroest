---
description: Verify a Bifröst audit journal.
---

# `bifroest audit verify`

Verifies signed `head.cbor`, producer identity, record and segment chains, seals, and file-name hashes up to a captured committed state without exporting records. Bifröst can keep writing. On success, the command reports `verified (scope: outer)` or `verified (scope: full)` on stdout and exits with status `0`. A sealed segment alone is not an accepted input.

When stdout is a regular file, the command refuses to write into protected journal, Recording, or identity files. Shell `>` redirection can truncate a file before Bifröst starts, so do not redirect verification output to protected files.

For `.beaudit`, the outer signatures and encrypted bytes can be verified without a private decryption key. Supply a matching private SSH key with `--decryptionIdentityFile` to additionally authenticate and validate the confidential event fields in memory. Outer-only verification does not prove that the private fields can be decrypted. For clear `.baudit`, verification includes the private fields without a decryption key.

## Syntax

`bifroest audit verify [flags] [auditlogName]`

## Arguments

`auditlogName` selects a configured audit log by name and is required locally. With `--source`, it is an optional label for the offline source, defaulting to `default`, not a journal or segment path. A complete offline copy includes signed `head.cbor`.

## Flags {: #audit-verify-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-verify-", heading=3)>>
Configuration to load. Without this flag, local verification uses the same platform default as `bifroest run`. Cannot be combined with `--source`; offline verification needs no configuration file.

<<flag("source", "File Path", "../../data-type.md#file-path", id_prefix="audit-verify-", heading=3)>>
Complete auditlog copy to verify without a configuration file or signing private key, including the signed head and all segments. Requires `--expectedProducerId` from an independent trust source. A downloaded sealed segment alone is not a complete journal.

<<flag("encryptionPublicKeyFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-verify-", heading=3)>>
Expected recipient public key for outer verification of an encrypted offline journal without a private decryption key. With one private key, the recipient is derived from that key; with multiple keys, this flag is required.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-verify-", heading=3)>>
Optional private SSH key for full verification of encrypted event fields. Repeat the flag when verifying journals encrypted for different keys. Without it, `.beaudit` verification covers the signed outer structure only.

<<flag("require-full", "bool", default=False, id_prefix="audit-verify-", heading=3)>>
Require full verification. For encrypted `.beaudit`, verification fails without a matching private decryption identity instead of accepting outer-only verification.

<<flag("expectedProducerId", "string", id_prefix="audit-verify-", heading=3)>>
External trust anchor as a 64-hex producer ID. On the Bifröst host, omit it to use the configured signing key. With `--source`, it is required. Obtain the ID from [`audit producer-id`](producer-id.md) on the server and retain it through an independently trusted channel. A value read only from the journal being verified is not a trust anchor.

## Examples

On the Bifröst host, verify without stopping the service. The default configuration and signing identity are used automatically:

```shell
bifroest audit verify default
```

For a complete offline copy without the signing private key, use the independently obtained producer ID:

```shell
bifroest audit verify \
  --source /srv/audit-evidence/auditlog \
  --expectedProducerId "<trusted-64-hex-id>"
```

For encrypted journals, add `--encryptionPublicKeyFile /srv/audit-keys/recipient-key.pub` for outer-only verification, or add `--decryptionIdentityFile /srv/audit-keys/recipient-key --require-full` to require full verification. See [Encrypted audit events](../../auditlog/index.md#encrypted-audit-events) for the copy workflow.
