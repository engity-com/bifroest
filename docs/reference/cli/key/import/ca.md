---
description: Import trusted SSH certificate authorities.
---

# `bifroest key import ca`

Validates and merges plain OpenSSH certificate-authority public keys into a local trust file. Certificates, private keys, and authorized-key options are rejected. A fingerprint mismatch leaves the destination unchanged.

## Syntax

<<cli_syntax("key import ca")>>

## Arguments

None.

## Flags {: #key-import-ca-flags }

Includes [all general flags](../../index.md#general-flags).

<<flag("trustedCAsFile", "File Path", "../../../data-type.md#file-path", required=True, id_prefix="key-import-ca-", heading=3)>>
Public-key file containing the trusted SSH certificate authorities to update.

<<flag("input", ref("File Path", "../../../data-type.md#file-path"), default="-", id_prefix="key-import-ca-", heading=3)>>
File containing the public CA keys. `-` reads from stdin.

<<flag("expectedFingerprint", "string", id_prefix="key-import-ca-", heading=3)>>
Expected OpenSSH SHA256 fingerprint of every imported CA, or `unknown`. Omission implies `unknown`.

## Output

A CA trust file containing the successfully imported public keys. Input validation or fingerprint failure leaves the destination unchanged; no private key is imported.

## Examples

### Import a separately provisioned CA

1. Obtain the CA public key and its SHA256 fingerprint through a trusted channel, as in [the delegation example](../../../authorization/bifroest.md).
2. Import it, replacing `CA_FINGERPRINT` with that value:

    ```shell
    bifroest key import ca \
      --trustedCAsFile /etc/engity/bifroest/trusted-cas.pub \
      --input /srv/ssh-trust/bifroest-ca.pub \
      --expectedFingerprint CA_FINGERPRINT
    ```

    The destination's parent directory must already exist.

## Availability

<<cli_availability()>>
