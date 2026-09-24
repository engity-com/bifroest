---
description: Shared version 1 framing, canonical CBOR, compression, and recovery rules.
---

# Native container rules

Native audit segments and session recordings use the same framing and CBOR
codec. Their **maps, signatures, and hash chains are different**. Read this
page first, then follow the [audit](audit.md) or [recording](recording.md)
byte contract. A signed [standalone Cast](cast.md) is an export, not a native
container.

## Recognize a container

| Family | Clear suffix | Encrypted suffix | Magic at offset 0 | Version |
| --- | --- | --- | --- | --- |
| Audit segment | `.baudit` | `.beaudit` | `\x89BAUDIT\n` (8 bytes) | 1 |
| Recording | `.bcast` | `.becast` | `\x89BCAST\n` (7 bytes) | 1 |

Both suffixes in a family share its magic and CBOR maps. The header signs
encryption mode `0` (clear) or `1` (age SSH). Determine family, version,
and mode from the **content**, not the suffix. A managed repository also
requires the suffix to agree with the signed mode. Reject unknown versions,
modes, or suffix/mode combinations. Encryption does not replace the
producer's Ed25519 signature.

Audit files live below `<journal>/<producer-id>/`:

- `active.baudit` or `active.beaudit` while writing;
- `head.cbor` for the signed journal checkpoint;
- `segment-<20-digit-sequence>-<64-hex-segment-hash>.baudit` or
  `.beaudit` when sealed.

Recording work and active files use `recording.bcast` or
`recording.becast` in per-recording directories, with a signed `head.cbor`.
Published files use `sealed/<canonical-uuid-v4>.bcast` or `.becast`.
Remote targets copy sealed files byte for byte under
`<producer-id>/<sealed-file-name>`.

The producer ID is `SHA256(ssh-key)`, where `ssh-key` is the canonical
binary SSH Ed25519 signing public-key blob. In paths it is 64 lowercase
hex characters; in CBOR it is 32 bytes. Recording IDs use canonical
UUIDv4 text in file names. Neither a file suffix nor an embedded key or
producer ID provides an external trust anchor.

## Read a unit

After the magic, read consecutive framed units:

```text
type:u8 | payload-length:u32-big-endian | commit-state:u8
deterministic-CBOR-payload | crc32c:u32-big-endian | "BFCOMMIT"
```

`BFCOMMIT` is eight ASCII bytes. CRC32C uses Castagnoli and covers the
type, length, and **exact payload bytes**, but not the commit-state byte.
A complete unit occupies `payload-length + 18` bytes. Unit types `1`,
`2`, and `3` mean header, audit record/recording chunk, and seal.

A sealed file has a header first, then at least one record or chunk, and
finally one seal. Reject other types and trailing bytes. Audit requires
at least one record before its seal. Physical hashes use the complete
**state-1 frame**, never a reconstructed state-0 frame.

### Commit and crash boundaries

The writer first writes a whole unit with state `0` and syncs its body and
trailer. It then overwrites that byte with `1` and syncs again. It needs
a serialized writer and a writable, non-append-only handle. An append or
sync failure poisons the writer until recovery reconciles the file with
its signed checkpoint.

- State `1` requires the complete length, marker, CRC, and canonical CBOR.
  Any other committed content is invalid.
- State `0` or a partial header is an uncommitted tail **only past** the
  signed checkpoint. An interrupted new audit header after an already
  verified journal head has a specific recovery rule.
- Commit-state values other than `0` and `1` are invalid.
- Even a physically complete state-0 unit needs valid framing, CRC, and
  canonical CBOR, with no bytes after its declared boundary.
- Before truncating a short state-0 unit, recovery searches its bounded
  declared footprint for a plausible committed unit, **even if that
  candidate's CRC is damaged**. Ambiguous overlaps fail closed.
- `BFCOMMIT` bytes inside a payload do not identify a committed unit.

The [audit](audit.md#checkpoints-and-recovery) and
[recording](recording.md#storage-and-recovery-boundaries) pages describe
their respective signed checkpoint and writer requirements.

## Decode canonical CBOR

Each payload is **one** Core Deterministic CBOR map with unsigned-integer
field keys. Use definite lengths, minimal integer widths, ordered keys,
UTF-8 text, and byte strings for binary data (never integer arrays).
Text is not Unicode-normalized or JSON-escaped by the CBOR codec.
Semantic constraints on events and Cast metadata still apply.

| Name in the wire tables | Exact CBOR value |
| --- | --- |
| `u8`, `u32`, `u64` | Unsigned integer in range, encoded in its shortest CBOR form, not a fixed width. |
| `i64` | Signed integer; negative values use CBOR's negative-integer major type. |
| `timestamp` | Exactly `[i64 Unix seconds, u32 nanoseconds]`; nanoseconds are `0..999999999`. Nonnegative seconds use unsigned CBOR. |
| `uuid16` | 16-byte RFC 4122 UUIDv4 byte string, not UUID text. |
| `hash32`, `sig64` | 32- or 64-byte byte string. |
| `ssh-key` | Canonical binary SSH Ed25519 public-key blob, not `authorized_keys` text. |
| `recipient` | `SHA256:` plus unpadded standard Base64 of a 32-byte SSH recipient fingerprint. |

In the format-specific tables, `R` means present even when zero or false.
`O` means omit the key when absent. **No field permits CBOR null**. Optional
empty strings are omitted; optional pointer values preserve present
`false` and `0`. An empty private audit event is an encoded empty map,
not a missing payload.

Reject duplicate or unknown keys, floats, tags, indefinite lengths,
invalid UTF-8, unsupported values, and trailing CBOR values. Re-encode
every typed value and reject it unless the bytes match exactly. Before
decoding or allocating, enforce the input-size limit, plus at most 4096
array elements, 128 map pairs, and 16 nesting levels.

`head.cbor` contains **one raw signed canonical CBOR map**, not a unit:
no magic, framing, Zstd, or age. Native containers contain no JSON or
Cast lines. Zstd and age transform CBOR byte strings within them.

## Store a private payload

Audit records compress one private event map each. Recording chunks
compress one complete event-group map each. The pipeline is:

```text
canonical CBOR -> one Zstd frame -> (mode 1 only) one independent age SSH message -> stored CBOR byte string
```

The signed header binds mode and recipient. Record or chunk signatures bind
the stored bytes; there is no separate codec field or raw-CBOR fallback.
Zstd may use **raw blocks inside a valid frame**.

Each stored value contains exactly one Zstd frame with a content checksum,
declared decoded size, no dictionary, a window of at most 2 MiB, and at
most 32 blocks. Reject skippable or concatenated frames, trailing bytes,
and stored or decoded data beyond their limits. Header and seal are small,
uncompressed CBOR units.

Each encrypted unit uses its own age message. Check the signed recipient
fingerprint and authenticate the message through EOF before accepting
decoded CBOR. Wrong recipients, truncated ciphertext, and trailing age
data are invalid. Never compress ciphertext. The server must hold only
the age **public** recipient key, not its private decryption identity.
Keep that identity separate from signing, host, static SSH environment,
and SFTP target keys whose private part is on the server. Operators must
also keep dynamically rendered key paths disjoint. Only offline full
verification and explicit sensitive export use the private identity.

## Verify and recover

The decision depends on what remains **after the last signed checkpoint**:

### Head missing while history exists

- **Audit:** Fail closed. Only a genuinely empty new journal may create a
  zero-hash head.
- **Recording:** Seal only an otherwise complete, verified chain ending in
  a committed final chunk, with no uncommitted tail. A continuation or
  uncommitted tail without a head fails closed.

### Head does not match the committed chain

- **Audit:** Fail closed if head key 4 is absent from or ahead of the
  validated record chain.
- **Recording:** Fail closed unless head keys 4..8 match the exact committed
  continuation prefix, not merely a hash elsewhere.

### Valid committed units follow the head

- **Audit:** Verify the chain and advance the signed head to the durable tip.
- **Recording:** Verify every successor. A committed final chunk provides
  the signed status, Cast digest, signature, and end time for a missing
  seal. An unfinished continuation may be finalized as incomplete.

### Uncommitted unit follows the checkpoint

- **Complete state-0 unit:** Audit checks framing, CRC, canonical CBOR,
  and the absence of following bytes before discarding it. An interrupted
  audit header may instead be committed after full signature and chain
  validation. Recording discards it only after verifying the checkpoint
  and all committed successors.
- **Physically short state-0 unit:** Both formats truncate only when the
  bounded overlap check rules out a plausible committed unit.

### Invalid or ambiguous state

A state-0 tail **before** the checkpoint, an invalid committed unit, an
overlapping committed candidate, or bytes after a state-0 unit fail closed.
Never skip committed audit evidence or truncate recording data behind its
signed head.

### Complete sealed container

- **Audit:** Check seal, physical hash, predecessor chain, and canonical
  published file name.
- **Recording:** Check the outer seal and entire physical chain. A head
  supplied during recovery must still match its committed prefix.

Audit head key 4 is a *record hash* found by following validated records.
Recording head keys 4..8 identify a byte-exact continuation prefix in one
recording; a final chunk is not a checkpoint. Neither head prevents an
attacker from rolling back **both** the head and its artifacts. A separately
trusted producer ID anchors either verification mode. Detecting removal of
a valid suffix of an audit history also needs an independently saved chain
tip.

**Outer verification** checks signed framing, identity, hashes, stored-byte
commitments, and seal without age keys. It also decompresses clear payloads
and checks their canonical CBOR; recovery checks clear recording event maps.
It cannot validate encrypted event semantics without decryption.

**Full verification** authenticates and decrypts when needed. It validates
private audit events or recording events and Cast checkpoints, then checks
the Cast digest and standalone signature. For the exact checks and offline
export limits, see [audit verification](audit.md#checkpoints-and-recovery)
or [recording verification](recording.md#what-verification-establishes).
