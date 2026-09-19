---
description: Download byte-exact reference vectors for Bifröst session recording formats.
---

# Recording format vectors

These version 1 vectors publish byte-exact examples of the Recording formats emitted and accepted by Bifröst. They are documentation and compatibility fixtures, not private recordings. Their signing and encryption seeds are public test values and must never be used in production.

The Go test suite regenerates every deterministic vector through the production encoders, compares the resulting bytes with these files, verifies the complete BECast fixture, decrypts it with the published test identity, and validates every size and SHA-256 value in the manifest. A change to deterministic encoder bytes therefore requires an explicit, reviewable vector update.

## Downloads

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

The manifest is the canonical index:

```json
--8<-- "docs/assets/recording-format-vectors/v1/manifest.json"
```

## Plain Cast

`cast-v3.cast` is a complete asciicast v3 stream. The first line remains the standard header. Bifröst metadata, result, and signature records are comments so players that tolerate unknown comments can consume the event stream. The signature covers the domain-separated content through the result line, not the final signature line.

```text
--8<-- "docs/assets/recording-format-vectors/v1/cast-v3.cast"
```

## Cast Zstandard

`cast-zstd-v1.cast.zst` consists of independently committed units:

1. A Zstandard skippable header frame with skippable ID `8`.
2. One or more skippable chunk descriptors with ID `9`, each immediately followed by one complete Zstandard frame.
3. A final skippable seal frame with ID `10`.

The header binds the Recording and producer identities. Each chunk descriptor binds its compressed frame, plaintext range, previous-unit hash, and signature. The seal binds the final status, byte and chunk counts, Cast digest, stream hash, and unit chain. `cast-zstd-v1.cast` is the byte-exact signed Cast obtained by passing the container through a standard Zstandard decoder or `bifroest recording export`.

The vector uses the production `default` compression profile, CRC-enabled single-segment frames, one encoder worker, a 2 MiB window limit, and a deliberately small 300-byte chunk target to expose multiple committed chunks.

## BECast

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
