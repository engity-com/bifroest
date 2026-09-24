---
description: Download byte-exact native-v1 CBOR session recording vectors.
---

# Native recording format vectors

This page covers **native-v1 only**: clear CBOR `.bcast` and age-encrypted CBOR
`.becast`. Both start with `\x89BCAST\n`. For their wire maps and hash chain see
[native recording](recording.md). For the signed plaintext export see
[Canonical standalone Cast](cast.md#canonical-standalone-cast); for shared framing see
[container.md](container.md).

The [audit format](audit.md) is a separate family. For operational verification
and export see the
[recording guide](../reference/auditlog/recording.md).

The native collection uses public test signing and recipient seeds that must never be
used in production. Go tests compare fresh deterministic encodings byte-for-byte,
authenticate and decrypt the frozen age fixtures, and validate the exact artifact
inventory, sizes, and SHA-256 values against the manifest.

Treat any change to deterministic vector bytes as a wire-format change,
even if the new file still round-trips. A Zstd dependency upgrade can
change deterministic compressed bytes. Review and explicitly update the
affected vectors before publishing.

## Clear `.bcast` downloads

| Vector | Purpose |
| --- | --- |
| [`manifest.json`](../assets/recording-format-vectors/native-v1/manifest.json) | Native-v1 schema, public test seeds, exact filenames, formats, byte lengths, SHA-256 values, and reproducibility flags. |
| [`bcast-v1.bcast`](../assets/recording-format-vectors/native-v1/bcast-v1.bcast) | Deterministic signed clear native recording. |
| [`bcast-v1.cast`](../assets/recording-format-vectors/native-v1/bcast-v1.cast) | Verified signed Cast export of the clear recording. |
| [`bcast-head.cbor`](../assets/recording-format-vectors/native-v1/bcast-head.cbor) | Signed checkpoint for the clear container's committed continuation prefix. |
| [`bcast-header.unit`](../assets/recording-format-vectors/native-v1/bcast-header.unit) | Complete framed signed header from the clear container. |
| [`bcast-continuation.unit`](../assets/recording-format-vectors/native-v1/bcast-continuation.unit) | Complete framed signed checkpoint/continuation chunk. |
| [`bcast-final.unit`](../assets/recording-format-vectors/native-v1/bcast-final.unit) | Complete framed signed final chunk. |
| [`bcast-seal.unit`](../assets/recording-format-vectors/native-v1/bcast-seal.unit) | Complete framed signed seal. |

## Age-encrypted native `.becast` downloads

| Vector | Purpose |
| --- | --- |
| [`becast-v1.becast`](../assets/recording-format-vectors/native-v1/becast-v1.becast) | Frozen age-encrypted CBOR recording for decoder tests. |
| [`becast-v1.cast`](../assets/recording-format-vectors/native-v1/becast-v1.cast) | Verified Cast export of the frozen native age recording. |
| [`becast-head.cbor`](../assets/recording-format-vectors/native-v1/becast-head.cbor) | Frozen signed checkpoint matching the age recording's committed prefix. |
| [`becast-header.unit`](../assets/recording-format-vectors/native-v1/becast-header.unit) | Complete signed age header frame; deterministic across fresh encodings with the same inputs. |
| [`becast-continuation.unit`](../assets/recording-format-vectors/native-v1/becast-continuation.unit) | Complete signed continuation frame from the frozen encrypted container. |
| [`becast-final.unit`](../assets/recording-format-vectors/native-v1/becast-final.unit) | Complete signed final chunk frame from the frozen encrypted container. |
| [`becast-seal.unit`](../assets/recording-format-vectors/native-v1/becast-seal.unit) | Complete signed seal frame from the frozen encrypted container. |

Download the manifest above for exact byte lengths, SHA-256 values, and
public test seeds. It is the machine-readable source of truth for the
complete native fixture inventory.

## Read the native fixtures

Both native containers start with `\x89BCAST\n`, followed by a header frame, a
continuation content frame, a final content frame, and a seal frame.

Each `.unit` download is the **entire actual signed frame** extracted from its
corresponding container. It includes its type, big-endian payload length,
committed-state byte, canonical CBOR payload, CRC32C, and `BFCOMMIT` marker. These are
not synthetic signatures or unframed CBOR.

Each `head.cbor` is a separate signed canonical CBOR checkpoint, not a frame within the
sealed container. The continuation records the Cast hash state at the committed prefix.
The final chunk and seal bind the signed Cast digest and result.

Both native containers encode the same logical CBOR setup, terminal output (including
an invalid UTF-8 byte), resize, marker, checkpoint padding, and final result with fixed
elapsed times. Their verified `.cast` exports are byte-identical and contain the signed
asciicast v3 representation, not raw CBOR.

The native age container encrypts separately compressed CBOR chunks. Outer verification
checks its signed envelope without a decryption key. Full verification and export
require the private key derived from `becastRecipientSeedHex` in the native manifest.
A missing or wrong identity fails full verification and emits no export.

### Identify frozen age ciphertext

Age encryption is intentionally randomized. `becast-v1.becast`, its matching
`becast-head.cbor`, and its continuation, final, and seal `.unit` files are
**frozen decoder vectors**, not reproducible encoder bytes.

The signed age header frame is deterministic: tests require a freshly encrypted writer
to produce byte-identical `becast-header.unit` bytes. A new encoding of the same CBOR
events has different ciphertext, signed chunk frames, checkpoint, and seal, but exports
the same deterministic Cast.

Normal tests never rewrite fixtures.

### Regenerate and review vectors

To regenerate the deterministic native files and manifest explicitly, run:

```sh
mise exec -- go test ./pkg/recording -run '^TestNativeRecordingFormatVectors$' -count=1 -args -generate-native-recording-vectors
```

This extracts missing encrypted `.unit` files only from the existing frozen container
and refuses to overwrite mismatching excerpts. Only an additional
`-generate-native-recording-age-vector` deliberately replaces the frozen age container,
checkpoint, and encrypted unit excerpts. Review every resulting hash change before
publishing.

The opt-in generator writes multiple files and is not transactional. If it fails,
resolve the cause, regenerate and pass the complete vector test suite before publishing
anything.
