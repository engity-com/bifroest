---
description: Inspect the verified public metadata of a copied Recording artifact as JSON.
---

# `bifroest recording inspect`

Verifies a local Recording artifact and emits its public metadata as one JSON object.

```shell
bifroest recording inspect --expectedProducerId PRODUCER_ID session.bcast
```

## Syntax

<<cli_syntax("recording inspect", "[flags] <file>")>>

## Arguments

### `file` {: #argument-file }

`file` is a required local `.bcast`, `.becast` or signed `.cast` artifact. Content determines the format, not the extension. The input must be regular, non-symlinked and unchanged in identity, size, mode and modification time throughout inspection. Standard input is unsupported.

## Flags {: #recording-inspect-flags }

Includes [general executable flags](../index.md#general-flags).

<<flag("expectedProducerId", "string", id_prefix="recording-inspect-", heading=3)>>
Independent 64-hex producer trust anchor. A mismatch fails inspection; a matching value sets `signature.trusted` to `true`. Without this flag, inspection verifies self-consistency and reports `signature.trusted: false`. An artifact-embedded ID is not independent trust.

## Output

One `bifroest.session-recording-inspection/v1` JSON object; there is no `--format` flag. Invalid evidence produces no JSON result. Emitted `signature.valid` is always `true`, while `signature.trusted` records whether an independent matching producer ID was supplied.

### Verification scope

* **Clear `.bcast`:** full verification, including reconstructed Cast content, with verified `status` and `castDigest`.
* **Encrypted `.becast`:** outer verification only. `claimedStatus` and `claimedCastDigest` are signed outer-seal claims, not verified inner-Cast results. `status`, `castDigest` and `cast` are omitted.
* **Signed `.cast`:** full verification, with a `cast` object containing event counts rather than session metadata or reasons.

Format values are `bcast/v1`, `becast-cbor/v1` and `cast/v3`. Native containers also report chunk count and claimed Cast size. Event payloads are not emitted, but public metadata still needs appropriate protection.

### Output safety

Regular-file stdout must not refer to the inspected input. A shell `>` redirection can truncate a file before the command starts; see [protected destinations](../verification.md#protected-destinations).

## Examples

### Inspect an encrypted original and its full export

1. Obtain a sealed `.becast` original and retain its producer ID independently using [the encrypted evidence workflow](../../../guides/evidence.md).
2. Inspect the copied original without a decryption key:

    ```shell
    bifroest recording inspect --expectedProducerId PRODUCER_ID session.becast
    ```

    The result has outer scope and a signed `claimedCastDigest`.
3. Fully verify and export with the matching local recipient key:

    ```shell
    bifroest recording export session.becast \
      --expectedProducerId PRODUCER_ID \
      --decryptionIdentityFile /srv/audit-keys/recipient-key \
      --with-sensitive \
      --output session.cast
    bifroest recording inspect --expectedProducerId PRODUCER_ID session.cast
    ```

    The exported Cast has full scope and a verified `castDigest`. Compare that digest with the original's claimed digest. See the [Recording format](../../../formats/recording.md#recording-identity-and-chain) and [native vectors](../../../formats/recording-vectors.md) for format details.

## Availability

<<cli_availability()>>

This command inspects local files. For a configured repository or remote Recording ID, use [`recording show`](show.md). For full verification of encrypted content, use [`recording verify`](verify.md).
