---
description: Download byte-exact reference vectors for native CBOR and legacy Bifröst session recording formats.
---

# Recording format vectors

Two independent version 1 collections are available: current native CBOR `.bcast` and age-encrypted native CBOR `.becast` in `native-v1/`, and earlier `.cast.zst` and **legacy binary** `.becast` in `v1/`. The identical `.becast` extension does not imply the same wire format: native recordings begin with `\x89BCAST\n`, while legacy binary BECast begins with `\x89BECAST\n`. Both collections use public test signing and recipient seeds that must never be used in production.

The Go tests compare fresh deterministic encodings byte-for-byte, authenticate and decrypt the frozen age fixtures, and validate the exact artifact inventory, sizes, and SHA-256 values against each manifest. A change to deterministic encoder bytes requires an explicit, reviewable vector update.

## Native CBOR downloads

### Clear `.bcast`

| Vector | Purpose |
| --- | --- |
| [`manifest.json`](../../assets/recording-format-vectors/native-v1/manifest.json) | Native-v1 schema, public test seeds, exact filenames, formats, byte lengths, SHA-256 values, and reproducibility flags. |
| [`bcast-v1.bcast`](../../assets/recording-format-vectors/native-v1/bcast-v1.bcast) | Deterministic signed clear native recording. |
| [`bcast-v1.cast`](../../assets/recording-format-vectors/native-v1/bcast-v1.cast) | Verified signed Cast export of the clear recording. |
| [`bcast-head.cbor`](../../assets/recording-format-vectors/native-v1/bcast-head.cbor) | Signed checkpoint for the clear container's committed continuation prefix. |
| [`bcast-header.unit`](../../assets/recording-format-vectors/native-v1/bcast-header.unit) | Complete framed signed header from the clear container. |
| [`bcast-continuation.unit`](../../assets/recording-format-vectors/native-v1/bcast-continuation.unit) | Complete framed signed checkpoint/continuation chunk. |
| [`bcast-final.unit`](../../assets/recording-format-vectors/native-v1/bcast-final.unit) | Complete framed signed final chunk. |
| [`bcast-seal.unit`](../../assets/recording-format-vectors/native-v1/bcast-seal.unit) | Complete framed signed seal. |

### Age-encrypted native `.becast`

| Vector | Purpose |
| --- | --- |
| [`becast-v1.becast`](../../assets/recording-format-vectors/native-v1/becast-v1.becast) | Frozen age-encrypted native CBOR decoder vector; not legacy binary BECast. |
| [`becast-v1.cast`](../../assets/recording-format-vectors/native-v1/becast-v1.cast) | Verified Cast export of the frozen native age recording. |
| [`becast-head.cbor`](../../assets/recording-format-vectors/native-v1/becast-head.cbor) | Frozen signed checkpoint matching the age recording's committed prefix. |
| [`becast-header.unit`](../../assets/recording-format-vectors/native-v1/becast-header.unit) | Complete signed age header frame; deterministic across fresh encodings with the same inputs. |
| [`becast-continuation.unit`](../../assets/recording-format-vectors/native-v1/becast-continuation.unit) | Complete signed continuation frame from the frozen encrypted container. |
| [`becast-final.unit`](../../assets/recording-format-vectors/native-v1/becast-final.unit) | Complete signed final chunk frame from the frozen encrypted container. |
| [`becast-seal.unit`](../../assets/recording-format-vectors/native-v1/becast-seal.unit) | Complete signed seal frame from the frozen encrypted container. |

```json
--8<-- "docs/assets/recording-format-vectors/native-v1/manifest.json"
```

Both native containers start with `\x89BCAST\n`, followed by a header frame, a continuation content frame, a final content frame, and a seal frame. Each `.unit` download is the **entire actual signed frame** extracted from its corresponding container, including its type, big-endian payload length, committed-state byte, canonical CBOR payload, CRC32C, and `BFCOMMIT` marker. These are not synthetic signatures or unframed CBOR. Each `head.cbor` is a separate signed canonical CBOR checkpoint, not a frame within the sealed container. The continuation records the Cast hash state at the committed prefix; the final chunk and seal bind the signed Cast digest and result.

Both native containers encode the same logical CBOR setup, terminal output (including an invalid UTF-8 byte), resize, marker, checkpoint padding, and final result with fixed elapsed times. Their verified `.cast` exports are byte-identical and contain the signed asciicast v3 representation, not raw CBOR. The native age container encrypts separately compressed CBOR chunks; outer verification checks its signed envelope without a decryption key, while full verification and export require the private key derived from `becastRecipientSeedHex` in the native manifest. A missing or wrong identity fails full verification and emits no export.

Age encryption is intentionally randomized. `becast-v1.becast`, its matching `becast-head.cbor`, and its continuation, final, and seal `.unit` files are **frozen decoder vectors**, not reproducible encoder bytes. The signed age header frame is deterministic: tests require a freshly encrypted writer to produce byte-identical `becast-header.unit` bytes. A new encoding of the same CBOR events has different ciphertext, signed chunk frames, checkpoint, and seal, but exports the same deterministic Cast. Normal tests never rewrite fixtures. To regenerate the deterministic native files and manifest explicitly, run `mise exec -- go test ./pkg/recording -run '^TestNativeRecordingFormatVectors$' -count=1 -args -generate-native-recording-vectors`; this extracts missing encrypted `.unit` files only from the existing frozen container and refuses to overwrite mismatching excerpts. Only an additional `-generate-native-recording-age-vector` deliberately replaces the frozen age container, checkpoint, and encrypted unit excerpts. Review every resulting hash change before publishing.

The opt-in generator writes multiple files and is not transactional. If it fails, resolve the cause, regenerate and pass the complete vector test suite before publishing anything.

## Legacy downloads

| Vector | Purpose |
| --- | --- |
| [`manifest.json`](../../assets/recording-format-vectors/v1/manifest.json) | Machine-readable paths, formats, sizes, SHA-256 values, reproducibility flags, and public test seeds. |
| [`cast-v3.cast`](../../assets/recording-format-vectors/v1/cast-v3.cast) | Deterministic signed plain asciicast v3 example. |
| [`cast-zstd-v1.cast.zst`](../../assets/recording-format-vectors/v1/cast-zstd-v1.cast.zst) | Deterministic signed and compressed Cast Zstandard container. |
| [`cast-zstd-v1.cast`](../../assets/recording-format-vectors/v1/cast-zstd-v1.cast) | Exact Cast exported from the Cast Zstandard container. |
| [`becast-v1.becast`](../../assets/recording-format-vectors/v1/becast-v1.becast) | Frozen signed, compressed, and age-encrypted BECast decoder vector. |
| [`becast-v1.cast`](../../assets/recording-format-vectors/v1/becast-v1.cast) | Exact Cast decrypted from the BECast vector. |
| [`becast-header.unit`](../../assets/recording-format-vectors/v1/becast-header.unit) | Deterministic BECast header encoding unit. |
| [`becast-chunk.unit`](../../assets/recording-format-vectors/v1/becast-chunk.unit) | Deterministic BECast chunk encoding unit with a five-byte synthetic ciphertext. |
| [`becast-seal.unit`](../../assets/recording-format-vectors/v1/becast-seal.unit) | Deterministic BECast final-seal encoding unit. |

The legacy manifest is the canonical index for `v1/` only:

```json
--8<-- "docs/assets/recording-format-vectors/v1/manifest.json"
```

## Plain Cast

`cast-v3.cast` is a complete asciicast v3 stream. The first line remains the standard header. Bifröst metadata, result, and signature records are comments so players that tolerate unknown comments can consume the event stream. The signature covers the domain-separated content through the result line, not the final signature line.

```text
--8<-- "docs/assets/recording-format-vectors/v1/cast-v3.cast"
```

## Legacy Cast Zstandard

`cast-zstd-v1.cast.zst` consists of independently committed units:

1. A Zstandard skippable header frame with skippable ID `8`.
2. One or more skippable chunk descriptors with ID `9`, each immediately followed by one complete Zstandard frame.
3. A final skippable seal frame with ID `10`.

The header binds the Recording and producer identities. Each chunk descriptor binds its compressed frame, plaintext range, previous-unit hash, and signature. The seal binds the final status, byte and chunk counts, Cast digest, stream hash, and unit chain. `cast-zstd-v1.cast` is the byte-exact signed Cast obtained by passing the container through a standard Zstandard decoder or `bifroest recording export`.

The vector uses the production `default` compression profile, CRC-enabled single-segment frames, one encoder worker, a 2 MiB window limit, and a deliberately small 300-byte chunk target to expose multiple committed chunks.

## Legacy Binary BECast

A BECast file starts with the eight bytes `89 42 45 43 41 53 54 0a`, or `\x89BECAST\n`, followed by header, chunk, and seal units. Every unit contains:

```text
"BECU" | type-u8 | flags-u8 | reserved-be-u16 | body-length-be-u32
body
crc32c-be-u32 | "BECOMMIT"
```

Unit types `1`, `2`, and `3` identify the header, encrypted chunk, and final seal. CRC uses the Castagnoli polynomial. Multibyte BECast fields are big-endian.

`becast-v1.becast` is a complete valid container. Its chunks are independently compressed and age-encrypted, then bound by signed descriptors and a signed final seal. The corresponding private test identity is derived from the public `becastRecipientSeedHex` in the manifest. `becast-v1.cast` is its verified plaintext export.

Age encryption intentionally uses fresh randomness. Re-running the BECast writer with the same inputs produces a different valid container, so the complete BECast file is a frozen decoder and interoperability vector rather than a reproducible encoder vector. Its decrypted Cast is deterministic.

The three standalone `.unit` files isolate deterministic binary encoding, CRC, and commit-marker behavior. They use synthetic fixed signatures and, for the chunk, synthetic ciphertext. They are encoding vectors and are not independently valid cryptographic artifacts. Their complete raw bytes, including prefix and trailer, produce the hashes listed in the manifest.

## Compatibility rules

Treat a byte change in a deterministic vector as a wire-format change, even when the new artifact still round-trips through the current encoder and decoder. A dependency upgrade can change the deterministic Zstandard bytes and therefore also requires explicit review of the updated vector.

Readers should reject malformed lengths, CRCs, signatures, hash chains, unsupported versions, trailing data, and decompression beyond declared limits. A full BECast decoder must select the decryption identity through the signed recipient fingerprint and reject chunks that cannot be decrypted by that identity; outer-only verification intentionally does not require a private identity or decrypt ciphertext. Applications must independently establish trust in the producer ID; successful self-signature verification alone does not establish that trust.
