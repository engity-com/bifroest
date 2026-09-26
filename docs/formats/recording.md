---
description: Version 1 native session recording maps, chain, checkpoints, and recovery.
---

# Native recording format

Native `.bcast` and `.becast` are signed session-recording containers. Start with the
shared [container rules](container.md) for framing and CBOR. This page specifies
recording-specific wire maps and commitments.
[Canonical standalone Cast](cast.md#canonical-standalone-cast)
defines the exact plaintext export, with byte-exact [native vectors](recording-vectors.md).

For configuration, retention, and operator commands, see
[session recording](../reference/auditlog/recording.md). The
[audit format](audit.md) uses different maps and hash domains.

## Files and identity

Both native suffixes start with `\x89BCAST\n` (seven bytes). The signed header selects
encryption mode `0` (clear `.bcast`) or `1` (age SSH `.becast`). The suffix is not the
authority, though managed repositories require the canonical suffix for the signed mode.

Recording work and active files use `recording.bcast` or `recording.becast` in
per-recording directories, with a signed `head.cbor`. Published files are
`sealed/<canonical-uuid-v4>.bcast` or `.becast`. Remote targets copy those files byte
for byte under `<producer-id>/<sealed-file-name>`.

The producer ID is `SHA256(ssh-key)`, where `ssh-key` is the canonical binary SSH
Ed25519 public-key blob. It is 32 raw bytes in the maps and 64 lowercase hex characters
in paths. Recording IDs are UUIDv4 bytes in CBOR and canonical UUID text in file names.

A suffix, embedded signing key, or embedded producer ID is not an external trust anchor.
Encryption does not replace Ed25519 signatures.

## Recording wire maps

All tables below are **version 1**. Each key is an unsigned-integer CBOR map key.
`R` means required, even for zero or false. `O` means omit when absent, never CBOR null.
Types, canonical encoding, and `head.cbor` (a separately signed canonical map, not a
container frame) follow the [shared container rules](container.md).

`timestamp` is `[i64 Unix seconds, u32 nanoseconds]`, with nanoseconds in
`0..999999999`. `uuid16`, `hash32`, and `sig64` are byte strings of 16, 32, and 64 bytes.
`recipient` is `SHA256:` plus unpadded standard Base64 of the 32-byte SSH recipient
fingerprint.

### Header and chunk

| Header (type 1) key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | version (`1`) | u8 | R |
| 2 | encryption (`0` none, `1` age SSH) | u8 | R |
| 3 | recording ID | uuid16 | R |
| 4 | producer ID | hash32 | R |
| 5 | signing public key | ssh-key | R |
| 6 | start time | timestamp | R |
| 7 | recipient fingerprint (only for mode 1) | recipient | O |
| 8 | signature | sig64 | R |

| Chunk (type 2) key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | sequence (starts at 1) | u64 | R |
| 2 | previous unit hash (header or preceding chunk frame) | hash32 | R |
| 3 | decoded CBOR event-group length | u32 (positive) | R |
| 4 | stored event group (Zstd frame or age message) | nonempty bytes | R |
| 5 | stored-byte hash | hash32 | R |
| 6 | Cast SHA-256 chaining state or final digest | hash32 | R |
| 7 | Cast SHA-256 processed byte count (`0` for final) | u64 | R |
| 8 | signature | sig64 | R |
| 9 | final status (`1` completed, `2` failed, `3` incomplete) | u8 | final only |
| 10 | final Cast digest (equals key 6) | hash32 | final only |
| 11 | standalone Cast signature | sig64 | final only |
| 12 | complete Cast export byte count (positive) | u64 | final only |
| 13 | end time | timestamp | final only |
| 14 | last actual event elapsed nanoseconds | u64 | continuation only |

On a final chunk, keys `9`..`13` are **all present** and key `14` is absent. On a
continuation, keys `9`..`13` are **all absent** and key `14` is present even when zero.

A continuation has nonzero, strictly increasing key `7` divisible by 64. A final chunk
has key `7 = 0`, and the hash in key `6` equals the Cast digest in key `10`. The signed
final chunk binds status, digest, Cast signature, complete Cast byte count and end time
before a seal exists.

### Decoded event group

The decoded chunk is exactly `{1: 1, 2: [event maps...]}`. Key `1` is the event-group
version; key `2` is a nonempty array of at most 4096 events. Each event has required key
`1` (`u8` kind) and only the fields below.

`elapsed` is an absolute, nonnegative nanosecond count (at most 10 * 365 * 24 hours),
not a relative Cast line interval. A setup occurs exactly once first; a result occurs
exactly once last. Nonfinal groups end in a padding event.

| Event kind | Required keys beyond 1 | Optional keys | Meaning |
| --- | --- | --- | --- |
| 1 setup | `2` Cast header map, `3` Cast metadata map | none | Initial Cast identity and terminal |
| 2 output | `2` elapsed u64, `3` stream u8 (`1` terminal, `2` stdout, `3` stderr), `4` raw bytes (1..65536) | none | One output event |
| 3 resize | `2` elapsed u64, `3` columns u32, `4` rows u32 | none | Positive dimensions, at most 65535, PTY only |
| 4 marker | `2` elapsed u64, `3` label text | none | UTF-8 label, at most 4096 bytes |
| 5 padding checkpoint | none | none | Regenerates the Cast SHA-256 alignment comment |
| 6 result | `2` elapsed u64, `3` result map | `4` exit status u32 | Last event; exit status may be 0, at most 2147483647 |

| Setup Cast header key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | Asciicast version (`3`) | u8 | R |
| 2 | terminal columns (1..65535) | u32 | R |
| 3 | terminal rows (1..65535) | u32 | R |
| 4 | terminal type (1..255 UTF-8 bytes) | text | O |
| 5 | Unix timestamp seconds (positive, equals metadata start seconds) | u64 | R |

| Setup Cast metadata key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | recording ID (equals recording header) | uuid16 | R |
| 2 | connection ID | 16-byte UUID bytes | R |
| 3 | session ID | 16-byte UUID bytes | R |
| 4 | operation ID | uuid16 | R |
| 5 | flow | text | R |
| 6 | task (`shell` or `exec`) | text | R |
| 7 | PTY (including false) | boolean | R |
| 8 | producer ID (equals recording header) | hash32 | R |
| 9 | start time (equals recording header) | timestamp | R |

| Result map key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | status (`1` completed, `2` failed, `3` incomplete) | u8 | R |
| 2 | end time | timestamp | R |
| 3 | reason (1..255 UTF-8 bytes) | text | O |

A completed result requires an exit status. Its end time must agree with the start plus
elapsed time. All CastWriter stream, event-order, time and text validations apply across
group boundaries.

Native groups contain no JSON or Asciicast lines;
[Cast rendering](cast.md#canonical-standalone-cast) produces those only at export.

### Seal and recovery head

| Seal (type 3) key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | final status | u8 (`1`..`3`) | R |
| 2 | chunk count (positive) | u64 | R |
| 3 | last chunk unit hash | hash32 | R |
| 4 | content hash | hash32 | R |
| 5 | Cast digest | hash32 | R |
| 6 | standalone Cast signature | sig64 | R |
| 7 | complete Cast export bytes (positive) | u64 | R |
| 8 | end time | timestamp | R |
| 9 | signature | sig64 | R |

| Recording head key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | version (`1`) | u8 | R |
| 2 | recording ID | uuid16 | R |
| 3 | producer ID | hash32 | R |
| 4 | durable prefix length (magic + header + committed continuation chunks) | u64 | R |
| 5 | continuation chunk count (positive) | u64 | R |
| 6 | last unit hash | hash32 | R |
| 7 | Cast SHA-256 chaining state | hash32 | R |
| 8 | Cast SHA-256 processed bytes (positive, divisible by 64) | u64 | R |
| 9 | signature | sig64 | R |

The seal must exactly match the final chunk. The head records an exact durable
continuation prefix, not a final chunk or an alternative source of events.

## Recording identity and chain

The recording header binds version, mode, recording ID, producer ID, public key, start
time, and any recipient fingerprint. Signed outer chunk descriptors bind sequence,
previous unit hash, stored payload hash, decoded byte count, and the continuation
information required by encrypted offline recovery. The seal binds status, counts, the
last unit hash, the content hash, and the pre-established signature of the exact
canonical `.cast` export.

### Sign each map

Recording header, chunk, seal and head signatures each equal
`Ed25519.sign(D_signature || C(map without signature key))` (key 8, 8, 9 and 9
respectively). `C` is exact canonical CBOR; `||` denotes byte concatenation. Optional
keys are included only if present.

These literal ASCII domains include the terminal NUL (`\x00`) and are distinct from the
[audit domains](audit.md):

```text
BIFROEST-BCAST-HEADER-SIGNATURE/v1\x00
BIFROEST-BCAST-CHUNK-SIGNATURE/v1\x00
BIFROEST-BCAST-SEAL-SIGNATURE/v1\x00
BIFROEST-BCAST-HEAD-SIGNATURE/v1\x00
BIFROEST-BCAST-UNIT-HASH/v1\x00
BIFROEST-BCAST-CONTENT-HASH/v1\x00
```

### Hash committed frames

For recording magic `R` (seven bytes), with `F` the exact complete committed state-1
frame (including CRC and marker), calculate:

```text
stored_hash       = SHA256(chunk[4])              # plain SHA-256, NO domain
header_unit_hash  = SHA256(D_recording_unit_hash || F(header))
chunk_i_unit_hash = SHA256(D_recording_unit_hash || F(chunk_i))
content_hash      = SHA256(D_recording_content_hash || R || F(header) || F(chunk_1) || ... || F(chunk_n))
```

Chunk 1 key 2 equals `header_unit_hash`; each later key 2 equals the prior
`chunk_i_unit_hash`. The seal key 3 equals the last chunk unit hash. Its key 4 hashes
from offset zero through the byte immediately before the seal: magic, header and all
committed chunks, but not the seal.

Neither chain hash includes the magic; the content hash does. There is no recording
equivalent of the audit sealed-segment hash. The recording head key 4 is the exact
physical prefix length at the end of a committed continuation frame. Keys 5..8 must
match that prefix's chunk count, last unit hash and last Cast checkpoint.

### Cast checkpoint and signature

For a nonfinal chunk, Cast key 6 is the 32 raw SHA-256 internal chaining-state bytes
at a 64-byte block boundary, **not** a digest. These are the eight state words `H0`
through `H7` in that order, each encoded as a big-endian 32-bit integer, before
SHA-256 final padding.

Key 7 is the total number of bytes fed to SHA-256. It includes the literal
`BIFROEST-ASCIICAST-CONTENT-HASH/v1\x00` prefix and all rendered Cast content through
that chunk's padding line and LF. It is positive, increasing and divisible by 64.

The padding line has prefix `# becast-checkpoint-padding:v1 `, followed by the unique
0..63 ASCII zeros needed so
`(processed_bytes + len(padding_prefix) + zeros + 1 LF) % 64 == 0`.
No SHA-256 partial block is retained in the signed checkpoint.

On a final chunk key 7 is zero and key 6 is the completed Cast digest (key 10),
**not** a resumable state. Key 12 and seal key 7 count complete `.cast` bytes including
the final signature comment and its LF; unlike Cast key 7 they exclude the hash domain.
The Cast digest instead covers the domain plus exact Cast lines through the result line
and LF, excluding the signature comment.

The standalone Cast uses schema `bifroest.asciicast-signature/v1` and domains
`BIFROEST-ASCIICAST-CONTENT-HASH/v1\x00` and
`BIFROEST-ASCIICAST-SIGNATURE/v1\x00`. Its Ed25519 signature covers the signature
domain plus canonical JSON signature content (`schema`, `recordingId`, `producerId`,
lowercase hex `digest`, and binary SSH `publicKey` as Base64).

The native seal stores that signature and digest. No JSON or Cast line is stored inside
the native recording. Offline export must reproduce and verify the same bytes without
the server's signing key. See [Canonical standalone Cast](cast.md#canonical-standalone-cast)
for rendering rules.

## Storage and recovery boundaries

### Encode and bound each group

Each recording event-group is canonical CBOR, encoded as
`canonical CBOR -> one Zstd frame -> (mode 1 only) one independent age SSH message -> stored CBOR byte string`.
The header binds mode and recipient; chunk signatures bind stored bytes. There is no
raw-CBOR fallback.

Each Zstd frame has a checksum, declared decoded size, no dictionary, a maximum 2 MiB
window and at most 32 blocks. Reject skippable/concatenated frames and trailing bytes.
Authenticate each age message through EOF before accepting the decoded group. Header
and seal are uncompressed CBOR units.

- A decoded group is at most 2 MiB. The complete stored chunk CBOR payload is at most
  4 MiB excluding its 18 framing bytes. The stored byte string is at most
  `4 MiB - 256` bytes. The default decoded-group target is 256 KiB.
- Recording container, Cast, and chunk-count defaults are 32 GiB, 16 GiB, and 262144
  chunks. Configured lower limits still apply. Readers enforce encoded and decoded
  limits before publishing data.

### Resume from the signed prefix

The signed `head.cbor` keys 4..8 must match the exact committed continuation prefix.
Verify each committed successor before advancing recovery. A committed final chunk
supplies its signed status, digest, signature and end time when writing a missing seal.

Otherwise recovery resumes the last signed, block-aligned Cast SHA-256 state, appending
a clear or encrypted incomplete-result chunk with no exit event. It uses the last signed
event elapsed time, without inventing output or timing.

A continuation without a persisted head fails closed. With no head, seal only
an otherwise complete, verified chain ending in a committed final chunk
with no uncommitted tail.

Only uncommitted tails **after** the checkpoint may be truncated. A physically complete
state-0 unit needs valid framing, CRC and canonical CBOR and no bytes after its declared
boundary. For a physically short state-0 tail, a bounded overlap search must rule out
any plausible committed state-1 unit even with damaged CRC.

An invalid committed unit, overlapping candidate, state-0 tail before the checkpoint,
or extra bytes fails closed.

### Persist committed units

Recovery requires an exclusively locked, writable `WriteAt` file. Its core performs
body-Sync and commit-byte-Sync; the caller syncs the directory after publication.

`NativeDurableRecordingOutput` accepts an empty regular read/write file without
`O_APPEND`. It syncs magic, then writes each signed unit with state 0, syncs, sets
state 1 with `WriteAt` and syncs again. Physical byte counts and content hashes use
state-1 frames.

A failed append poisons the sink until recovery. Passing a bare `*os.File` to the writer
is rejected, and the in-memory `io.Writer` path is not durable. The repository adapter
supplies locking, quota, signed-head replacement and directory sync. Neither a local
head nor an artifact stored beside it prevents rollback of both without an external
anchor.

## What verification establishes

### Choose the verification level

Outer verification checks signed frames, CRC, identities, hashes, stored-byte
commitments and seal without age keys. For clear payloads it also decompresses and
checks canonical CBOR; recovery checks clear event maps.

For encrypted payloads, outer verification **cannot** attest decrypted events or Cast
semantics: status and Cast digest are signed outer claims. Full verification
decrypts/authenticates when needed, validates all events, renders the exact Cast,
verifies its digest and standalone signature, and checks every Cast checkpoint.

Both modes require an independently trusted expected producer ID; a content-supplied
key is not that trust anchor.

### Verify before export

Offline FullVerify/Export requires the same immutable `io.ReaderAt` snapshot across
passes. It verifies the outer container, then streams independently
authenticated/decompressed groups (at most 2 MiB decoded each) through the renderer to
the Cast verifier. It checks signed continuations, final digest/signature, result and
exact byte count **before** exporting bytes.

Export rereads the same snapshot in a second bounded pass, without buffering the full
Cast or writing sensitive temporary plaintext. A mid-write destination failure can
leave a partial *verified* Cast; atomic publication belongs to the caller.

`RenderNativeRecordingCast` returning `[]byte` is an in-memory helper, not the
large-artifact export path. Never automatically generate a `.cast` or `.jsonl` on disk
or at remote targets; [operator export](../reference/auditlog/recording.md#export-and-playback)
requires explicit `--with-sensitive`.
