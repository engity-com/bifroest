---
description: Download signed native audit format version 1 reference vectors.
---

# Native audit format vectors

These are **audit journal**, not session recording, vectors. Version 1 includes a complete sealed clear `.baudit` and a complete sealed age-encrypted `.beaudit`, with separate signed `head.cbor` checkpoints. The signing and age-recipient seeds in the manifest are **public test data** and must never be used to protect production data. The age recipient key is distinct from the producer signing key.

## Downloads

| Vector | Purpose |
| --- | --- |
| [`manifest.json`](../../assets/audit-format-vectors/v1/manifest.json) | Strict v1 inventory with public test seeds, producer/recipient identity, sizes, file SHA-256, reproducibility, and audit domain hashes. |
| [`baudit-v1.baudit`](../../assets/audit-format-vectors/v1/baudit-v1.baudit) | Complete deterministic signed clear segment: magic, header, two records, seal. |
| [`baudit-v1-head.cbor`](../../assets/audit-format-vectors/v1/baudit-v1-head.cbor) | Raw signed head checkpoint for the clear segment. |
| [`baudit-header.unit`](../../assets/audit-format-vectors/v1/baudit-header.unit) | Exact framed header excerpt from the clear segment. |
| [`baudit-records.unit`](../../assets/audit-format-vectors/v1/baudit-records.unit) | Exact two consecutive framed record excerpts from the clear segment. |
| [`baudit-seal.unit`](../../assets/audit-format-vectors/v1/baudit-seal.unit) | Exact framed seal excerpt from the clear segment. |
| [`baudit-v1-redacted.jsonl`](../../assets/audit-format-vectors/v1/baudit-v1-redacted.jsonl) | Clear journal export without private event fields. |
| [`baudit-v1-with-sensitive.jsonl`](../../assets/audit-format-vectors/v1/baudit-v1-with-sensitive.jsonl) | Clear journal export with private event fields. |
| [`beaudit-v1.beaudit`](../../assets/audit-format-vectors/v1/beaudit-v1.beaudit) | Complete frozen signed age-encrypted segment. |
| [`beaudit-v1-head.cbor`](../../assets/audit-format-vectors/v1/beaudit-v1-head.cbor) | Raw signed head checkpoint for the encrypted segment. |
| [`beaudit-header.unit`](../../assets/audit-format-vectors/v1/beaudit-header.unit) | Exact framed signed mode-1 header excerpt; independently reproducible with the public signing seed. |
| [`beaudit-records.unit`](../../assets/audit-format-vectors/v1/beaudit-records.unit) | Exact two frozen framed record excerpts, including randomized age ciphertext. |
| [`beaudit-seal.unit`](../../assets/audit-format-vectors/v1/beaudit-seal.unit) | Exact frozen framed seal excerpt from the encrypted segment. |
| [`beaudit-v1-redacted.jsonl`](../../assets/audit-format-vectors/v1/beaudit-v1-redacted.jsonl) | Encrypted journal outer-only export, no decryption key. |
| [`beaudit-v1-with-sensitive.jsonl`](../../assets/audit-format-vectors/v1/beaudit-v1-with-sensitive.jsonl) | Full verified export after decryption with the public test recipient identity. |

All `.unit` files are **real signed CBOR units**, not synthetic bodies: each is an exact framed excerpt from its corresponding complete `.baudit` or `.beaudit` (each records file contains two adjacent units). The encrypted header declares mode `1` and recipient `SHA256:ZsrOVCtcb1bouzun0GIHz5vL5oCjVhVIQ3jfIBIgZ8g`; its framed bytes are independently deterministic. The encrypted record and seal excerpts depend on the frozen ciphertext. Both segment types start with `\x89BAUDIT\n` (8 bytes); each subsequent unit is `type:u8 | length:u32be | commit-state:u8 | deterministic-CBOR | crc32c:u32be | BFCOMMIT`. The CRC32C excludes the commit-state byte. Types 1, 2, 3 denote header, record, seal. The separate head is *raw CBOR*, not a framed unit. See the [native format contract](native-format-contract.md) for field keys and validation rules.

The fixtures contain two fixed UUIDv4 record IDs, `34e34ab8-7457-4d88-a5e4-c57791775c3a` and `6d05798f-b877-4191-8aa0-4576a30411ad`, recorded on `2026-09-13T12:34:56.123456789Z` and `2026-09-13T12:35:01.987654321Z`. The public event fields are `custom.authentication` / `authentication` / `success` and `custom.session` / `session` / `denied`. With sensitive output, the first also has flow `fixture-flow`, connection ID, public-key authentication method and verified phase; the second has the same flow, session ID, exec task and `authorized-key-policy` reason. Redacted JSONL excludes all of these private fields, even for the clear segment.

## Known values

The public signing seed is `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`; the **distinct** public age-recipient seed is `4242424242424242424242424242424242424242424242424242424242`. The trusted producer ID for this test is `95b9aca00d322047048950d19cc5aece6fa757edd9104a5521446a168792b298`. The expected encryption recipient fingerprint is `SHA256:ZsrOVCtcb1bouzun0GIHz5vL5oCjVhVIQ3jfIBIgZ8g` (the clear header has no recipient).

| Domain-separated audit hash | Clear | Encrypted (frozen) |
| --- | --- | --- |
| First record | `4abff565227d1caa4dd8024573ccb9e913d9c4bd9c5c436ea365e10f2e2b0e0c` | `948219b4682315c7c2630691cd0d37da1f68f4610e821d55f6b7ddc1635b11b1` |
| Second record / signed head tip | `0411421b5a07a742ea3bcea32f41fc2d962eb061b8cbbda88d94484d42a67d2f` | `597d1df3c659c5de7a183d2e1c8b5f7829d27b52fd5bdb6f1659b17560e88749` |
| Content (magic through final record) | `5fb0c20d9d91de7b9a4835e4ecc878978931d87a73a5f7b6730a28967866463a` | `1ad8504fc41e89811d0236e6b17cc2fc34920d3ab58dd8e9ffb3c213b7ce8f8f` |
| Segment (entire sealed file) | `fe793ee92c2547663fbd50dec41971378d3d837bb2e6237fe06d6009d0ce9bc5` | `917fba80141b65171aa763ee878d45e67c9852aaa227fad87d89eb9451c3ff57` |

These record, content, and segment hashes use the **audit-specific domain prefixes** defined by the writer. They are not raw SHA-256 file digests: for example, `baudit-v1.baudit` is 1021 bytes with raw SHA-256 `9e996c9f05ba029cd9c9767d5227ce85d5638d464ced4b6d9854c82f6e6e7111`; `beaudit-v1.beaudit` is 1500 bytes with raw SHA-256 `6e2405618accc2392ef8740e543416e2ee51174ea9eaf7e30857d91bf5f6d2ed`. The manifest lists exact lengths and raw SHA-256 for **every** download. The head is an independent signed checkpoint bound to the second record hash; it is not included in either segment hash.

## Verification and reproduction

`mise exec -- go test ./pkg/audit -count=1` checks the exact asset list and manifest schema, metadata, lengths and hashes against actual bytes; regenerates the **clear** header, records, seal and head using production encoders and compares every byte; decodes and compares the framed `.unit` excerpts; and independently regenerates the signed mode-1 header without encrypting. It uses `VerifyJournalIntegrity`, `VerifyJournals` and `ExportJSONLines` on a temporary `<journal>/<producer-id>/segment-<sequence>-<hash>` plus `head.cbor` tree. It checks both redacted and full exports. For encrypted bytes it verifies signatures and hashes without a key, verifies and exports the private fields with the published test key, and rejects missing and wrong keys in full mode. The normal tests never rewrite fixtures.

Age encryption consumes fresh randomness. Consequently the encrypted `.beaudit`, its head (which signs its ciphertext-dependent chain tip), both JSONL exports, and the encrypted record and seal units have `reproducible: false`: they are **frozen decoder vectors**, not bytewise regeneration targets. Only `beaudit-header.unit` is independently reproducible (`reproducible: true`).

To update clear vectors and re-extract encrypted units **without changing the four frozen Age files**, run `mise exec -- go test ./pkg/audit -run '^TestGenerateNativeAuditFormatVectors$' -count=1 -args -audit-generate-vectors`. This first checks the existing `.beaudit`, its head, and both JSONL exports against the **old manifest's actual SHA-256 and size**, then verifies the frozen journal and writes the excerpts and updated manifest. Only a deliberate replacement of the age ciphertext uses **both** flags: `mise exec -- go test ./pkg/audit -run '^TestGenerateNativeAuditFormatVectors$' -count=1 -args -audit-generate-vectors -audit-generate-age-vector`. The age flag alone is rejected. Review all resulting binary and manifest changes before publishing. Never compare a freshly encrypted segment byte-for-byte with the frozen one. A valid self-signature does not establish trust by itself: pin the expected producer ID and, for encrypted journals, the expected recipient fingerprint from a trusted source.

The opt-in generator writes multiple files and is not transactional. If it fails, resolve the cause, regenerate and pass the complete vector test suite before publishing anything.
