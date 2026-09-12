---
description: Import trusted SSH certificate authorities.
---

# `bifroest key import ca`

Validates and atomically merges plain OpenSSH certificate-authority public keys. Certificates, private keys, and authorized-key options are rejected. Concurrent merge operations are locked, and any fingerprint mismatch leaves the destination unchanged.

## Syntax

`bifroest key import ca [flags]`

## Flags {: #key-import-ca-flags }

Includes [all general flags](../../index.md#general-flags).

<<flag("trustedCAsFile", "File Path", "../../../data-type.md#file-path", required=True, id_prefix="key-import-ca-", heading=3)>>
Public-key file containing the trusted SSH certificate authorities to update.

<<flag("input", ref("File Path", "../../../data-type.md#file-path"), default="-", id_prefix="key-import-ca-", heading=3)>>
File containing the public CA keys. `-` reads from stdin.

<<flag("expectedFingerprint", "string", id_prefix="key-import-ca-", heading=3)>>
Expected OpenSSH SHA256 fingerprint of every imported CA, or `unknown`. Omission implies `unknown`.

## Example

See [Bifröst delegation authorization](../../../authorization/bifroest.md) for a complete CA exchange.
