---
description: Native audit and recording container format contract.
---

# Native format contract

Version 1 defines four native containers: `.baudit` and `.beaudit` for audit
segments, `.bcast` and `.becast` for session recordings. This page specifies
their bytes independently of their file-name extensions. It does not describe
the older binary BECast container.

## Families and names

| Stored data | Clear | Encrypted | File magic | Version |
| --- | --- | --- | --- | --- |
| Audit segment | `.baudit` | `.beaudit` | `\x89BAUDIT\n` (8 bytes) | 1 |
| Session recording | `.bcast` | `.becast` | `\x89BCAST\n` (7 bytes) | 1 |

The header contains a signed encryption mode: `0` (none) or `1` (age SSH).
Both suffixes in a family use the same magic and CBOR schemas. Readers identify
the family, version, and encryption mode from the content, not from the suffix.
Managed repositories additionally require the canonical suffix matching the
signed mode. Unsupported versions, modes, or suffix/mode combinations fail
closed. Encryption does not replace the producer's Ed25519 signature.

Audit files live below `<journal>/<producer-id>/`: `active.baudit` or
`active.beaudit`, `head.cbor`, and
`segment-<20-digit-sequence>-<64-hex-segment-hash>.baudit` or `.beaudit`.
Recording work and active files use `recording.bcast` or `recording.becast`
inside their existing per-recording directories, with a signed `head.cbor`;
published files are `sealed/<canonical-uuid-v4>.bcast` or `.becast`.
Remote targets copy sealed files byte for byte under
`<producer-id>/<sealed-file-name>`. The producer ID remains the 32-byte SHA-256
of the SSH signing public-key blob, rendered as 64 lowercase hex characters.
Recording IDs remain UUIDv4 values, rendered canonically in file names. A
suffix, embedded key, or embedded producer ID is not an external trust anchor.

## Envelope and bounds

After the magic, each unit has the following framing, in order:

```text
type:u8 | payload-length:u32-big-endian | commit-state:u8
deterministic-CBOR-payload | crc32c:u32-big-endian | "BFCOMMIT" (8 ASCII bytes)
```

CRC32C (Castagnoli) covers the type, length, and exact CBOR payload bytes,
excluding the commit-state byte. That byte is `0` until the complete body and
trailer have been durably synced; then it is overwritten with `1` and synced
again. A partial unit header or state `0` is an uncommitted tail only beyond
the signed checkpoint (apart from recovery of a new audit active header after
an already verified journal head). A physically complete state-0 unit must
still have valid framing, CRC, and canonical CBOR; bytes after its declared boundary
make it invalid. Before truncating a physically incomplete state-0 unit,
recovery also rejects a plausible complete committed unit within its bounded
declared footprint, even if that unit's CRC is damaged. Such overlapping
binary data is ambiguous and fails closed. State `1` requires the complete
declared length, marker, CRC, and canonical payload. Other state values are
invalid. Bytes inside a payload that happen to spell `BFCOMMIT` alone are
never evidence of a committed unit. This in-place commit requires a writable
non-append-only file handle and a single serialized writer. An append or sync
failure poisons that writer: another append is forbidden until recovery has
reconciled the file against the signed checkpoint. The format-specific writers
and their failure-injection tests enforce this protocol; the shared decoder
distinguishes the resulting physical states.

Types `1`, `2`, and `3` are header, audit record/recording chunk, and seal.
Only a header first, zero or more audit records (at least one before an audit
seal) or one or more recording chunks, and a terminal seal are valid in a
sealed file. Other types or trailing bytes are invalid. The total frame size
is `6 + payload-length + 12 = payload-length + 18` bytes. Its state-1 bytes,
not a reconstructed state-0 frame, are used in physical hashes.

Each payload is exactly one deterministic CBOR map with unsigned integer
field keys. Use Core Deterministic CBOR: definite lengths, minimal integer
encodings, deterministically ordered map keys, UTF-8 text, and byte strings
(never integer arrays for binary data). A `u8`, `u32`, or `u64` below denotes
the permitted nonnegative numeric range, **not** a fixed CBOR integer width;
encode the value in its shortest CBOR form. `i64` permits negative values.
`timestamp` is exactly `[i64 Unix seconds, u32 nanoseconds]`, with the second
element in `0..999999999`; nonnegative seconds use the unsigned CBOR major
type, negative seconds the negative-integer major type. `uuid16` is a 16-byte
CBOR byte string containing RFC 4122 UUIDv4 bytes, not UUID text; `hash32`
is a 32-byte CBOR byte string; `sig64` is a 64-byte Ed25519 signature byte
string. `ssh-key` is the canonical binary SSH Ed25519 public-key blob, not
authorized_keys text; `producer32 = SHA256(ssh-key)`. `recipient` is the
canonical text `SHA256:` followed by unpadded standard Base64 of the 32-byte
SSH recipient fingerprint. Text values are UTF-8 CBOR text strings, with no
Unicode normalization or JSON escaping applied by the CBOR codec. Their
semantic constraints (such as valid event names or Cast metadata) still
apply. No field admits CBOR null: `R` means required even when its value is
zero or false; `O` means omit the key when absent, not encode null or an empty
placeholder. In the typed schemas, optional empty strings are omitted;
optional pointer values preserve present `false` and `0`. An empty private
audit event is the encoded empty map, not an absent record payload.

Reject duplicate or unknown keys, floats, tags, indefinite lengths, invalid
UTF-8, unsupported values, trailing CBOR values, and any input that does not
re-encode to identical typed canonical bytes. The decoder limits input size
before decoding and allocation: at most 4096 array elements, 128 map pairs,
and 16 nested levels. CBOR is the only structured encoding in the native
containers; Zstd and age transform CBOR byte strings, not JSON or embedded
Cast lines.

## CBOR wire keys (version 1)

All following tables are version 1; each key is a CBOR unsigned-integer map
key. The `head.cbor` files contain a single canonical signed CBOR map **without
file magic, unit framing, or Zstd/age**. They are not container units.

### Audit maps

| Header (type 1) key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | version (`1`) | u8 | R |
| 2 | encryption (`0` none, `1` age SSH) | u8 | R |
| 3 | producer ID | hash32 | R |
| 4 | signing public key | ssh-key | R |
| 5 | segment sequence (starts at 1) | u64 | R |
| 6 | previous sealed segment hash (zero for first) | hash32 | R |
| 7 | previous audit record hash (zero for first) | hash32 | R |
| 8 | creation time | timestamp | R |
| 9 | recipient fingerprint (only for mode 1) | recipient | O |
| 10 | signature | sig64 | R |

| Record (type 2) key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | record ID | uuid16 | R |
| 2 | recorded time | timestamp | R |
| 3 | previous record hash | hash32 | R |
| 4 | public event | public event map | R |
| 5 | stored private event (Zstd frame or age message) | nonempty bytes | R |
| 6 | signature | sig64 | R |

| Public event key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | name (nonempty) | text | R |
| 2 | domain | nonempty text | O |
| 3 | outcome | nonempty text | O |

The private event is itself a canonical CBOR map **before** compression. Its
IDs and recording digest are text in the established audit Event schema, not
`uuid16` or `hash32` CBOR byte strings. All keys below are optional.

| Private event key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | flow | nonempty text | O |
| 2 | connection ID | nonempty text | O |
| 3 | session ID | nonempty text | O |
| 4 | operation ID | nonempty text | O |
| 5 | recording ID | nonempty text | O |
| 6 | recording digest | nonempty text | O |
| 7 | target | nonempty text | O |
| 8 | authentication method | nonempty text | O |
| 9 | authentication phase | nonempty text | O |
| 10 | authorization kind | nonempty text | O |
| 11 | session task | nonempty text | O |
| 12 | reason | nonempty text | O |
| 13 | error category | nonempty text | O |
| 14 | exit code | i64 (nonnegative) | O |
| 15 | bytes read | i64 (nonnegative) | O |
| 16 | bytes written | i64 (nonnegative) | O |
| 17 | duration in milliseconds | i64 (nonnegative) | O |
| 18 | count | u64 (positive) | O |
| 19 | PTY | boolean | O |
| 20 | agent forwarding | boolean | O |
| 21 | forced command | boolean | O |

| Seal (type 3) key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | segment sequence | u64 | R |
| 2 | record count (positive) | u64 | R |
| 3 | content byte count | u64 | R |
| 4 | content hash | hash32 | R |
| 5 | last record hash | hash32 | R |
| 6 | seal time | timestamp | R |
| 7 | signature | sig64 | R |

| Audit head key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | version (`1`) | u8 | R |
| 2 | producer ID | hash32 | R |
| 3 | signing public key | ssh-key | R |
| 4 | last accepted record hash (zero for empty history) | hash32 | R |
| 5 | signature | sig64 | R |

### Recording maps

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

Keys `9`..`13` are **all present** on a final chunk and **all absent** on a
continuation. Key `14` has the reverse presence rule: it is present even when
zero on a continuation, absent on a final chunk. A continuation has nonzero,
strictly increasing key `7` divisible by 64; a final chunk has key `7 = 0`
and the hash in key `6` equals the Cast digest in key `10`. The signed final
chunk binds status, digest, Cast signature,
complete Cast byte count and end time before a seal exists.

The decoded chunk is exactly `{1: 1, 2: [event maps...]}`: key `1` is the
event-group version, key `2` is a nonempty array of at most 4096 events.
Each event has required key `1` (`u8` kind) and only the fields below.
`elapsed` is an absolute, nonnegative nanosecond count (at most 10 * 365 * 24
hours), not a relative Cast line interval. A setup occurs exactly once first;
a result occurs exactly once last. Nonfinal groups end in a padding event.

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

A completed result requires an exit status and its end time must agree with
the start plus elapsed time. All CastWriter stream, event-order, time and
text validations apply across group boundaries. Native groups contain no JSON
or Asciicast lines.

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

The seal must exactly match its final chunk. The signed recording `head.cbor`
recovery state requires an exact durable-prefix comparison. The standalone
recovery core verifies this checkpoint
and every committed successor without a private decryption key. It reuses a
committed final chunk's signed end time when writing a missing seal. Otherwise
it appends a new encrypted or clear CBOR incomplete-result chunk by resuming
the last signed, block-aligned Cast SHA-256 state; the result has no exit event
and uses the last signed event elapsed time rather than inventing terminal
output or timing. Only uncommitted tails after the checkpoint
may be truncated. Recovery requires an exclusively locked, writable `WriteAt`
file; its core performs body-Sync and commit-byte-Sync, while the caller must
sync the directory after publication. An empty regular read/write file opened
without `O_APPEND` can use `NativeDurableRecordingOutput`: it writes and syncs
the magic, then writes each complete signed unit with commit-state 0, syncs,
sets state 1 with `WriteAt`, and syncs again. Its byte counts and content hashes
cover the final state-1 frames. Failure poisons the sink; a caller must not
retry an append without recovery. Passing a bare `*os.File` to the writer is
rejected. The ordinary in-memory `io.Writer` path is NOT a durable recording
writer. The local repository adapter supplies the lock, quota, signed-head
replacement, and directory sync. No external rollback anchor is provided.
If the head was not yet persisted, recovery may only seal an otherwise
complete chain ending in a committed signed final chunk with no uncommitted
tail; a continuation without head fails closed rather than dropping events.

### Verification and crash decisions

| Observed state | Audit journal | Recording work file |
| --- | --- | --- |
| No head with existing history | Fail closed; only a genuinely empty new journal may create an initial zero-hash head. | A committed final chunk with no tail may be sealed; a continuation or uncommitted tail without head fails closed. |
| Signed head absent from or ahead of committed chain | Fail closed; audit head key 4 must occur in the validated record chain. | Fail closed; recording head keys 4..8 must equal the exact committed continuation prefix, never just a matching hash elsewhere. |
| Committed valid units after head | Verify chain and advance signed audit head to the durable tip. | Verify each successor; reuse a committed final chunk's signed status, Cast digest, signature and end time to add a missing seal, or finalize an unfinished continuation as incomplete. |
| Physically complete state-0 unit after checkpoint | Accept only valid framing, CRC and canonical CBOR with no following bytes; discard the uncommitted tail, except an interrupted audit header may be committed after full signature/chain validation. | Discard only after verifying the signed checkpoint and all committed successors. |
| Physically short state-0 tail after checkpoint | Truncate only when bounded overlap search finds no plausible committed state-1 unit. | Same bounded overlap check; truncate only after checkpoint validation. |
| State-0 tail before checkpoint, invalid committed unit, overlapping committed candidate, or extra bytes after state-0 unit | Fail closed; never silently skip or repair committed evidence. | Fail closed; no truncation behind head and no reinterpretation of signed units. |
| Complete sealed container | Check seal, physical hash, predecessor chain and canonical published name. | Verify outer seal and entire physical chain; head, if supplied during recovery, still has to match its committed prefix. |

Audit head key 4 is a *record hash*, not a byte offset or a Cast checkpoint;
record hashes locate its position by verifying the chain across segments.
Recording head keys 4..8 instead identify a byte-exact continuation prefix
within one recording; a final chunk cannot be its checkpoint. Neither local
head protects against an attacker rolling back the head and artifact together.
Outer verification checks signed frames, CRC, identities, hashes, stored-byte
commitments and seal without age keys. For clear payloads it also decompresses
and checks canonical CBOR (and recovery checks clear event maps); for encrypted
payloads it cannot attest to the decrypted event semantics. Full verification
decrypts/authenticates if necessary, validates the private audit event or all
recording events, renders the exact Cast, verifies its digest and standalone
signature, and checks every Cast checkpoint. Only a trusted expected producer
ID anchors either verification mode; content-supplied keys are not trust
anchors.

The offline FullVerify/Export API requires the **same immutable** `io.ReaderAt`
snapshot across all passes. It verifies the outer container, then streams
independently authenticated/decompressed CBOR groups (at most 2 MiB decoded
each) through a stateful renderer into a pipe consumed by the Cast verifier.
It checks every signed Cast continuation, final digest/signature, result, and
exact Cast byte count before writing any export bytes. Export re-reads the
same immutable snapshot in a second bounded pass; no full Cast or aggregate
group history is buffered and no sensitive temporary plaintext file is made.
Configured container, chunk and Cast limits (up to 16 GiB Cast) still apply.
If the destination fails mid-write, it may contain a partial *verified* Cast;
atomic export-file publication is the caller's responsibility. The standalone
`RenderNativeRecordingCast` returning `[]byte` remains an in-memory helper,
not the large-artifact export path.

An audit record commits independently: write and sync its framed body, then
set and sync its commit-state byte, then atomically replace and sync the signed
head. Header, seal, and public audit-event CBOR maps are limited to 4 KiB each.
The private audit-event CBOR map is limited to 64 KiB before
compression/encryption, and the complete stored record CBOR payload to 128 KiB
(excluding the 18 framing bytes).
Audit segments target approximately 16 MiB
and have a 17 MiB verification limit. A recording chunk contains at most 2 MiB
of decoded CBOR and its complete stored CBOR payload is at most 4 MiB (including
the map and signature, but excluding framing); the stored byte string itself
is limited to `4 MiB - 256` bytes. The default decoded-group target is
256 KiB. Recording container, Cast and chunk-count defaults are respectively
32 GiB, 16 GiB and 262144 chunks; configured lower limits still apply.
Readers enforce encoded and decoded limits before publishing data. Zstd may
use raw blocks inside its frames, never an unwrapped raw-CBOR record variant.

Audit records compress one private event map each; recording chunks compress
complete native event-group maps. The exact pipeline per record/chunk is
`canonical CBOR -> one Zstd frame -> (mode 1 only) one independent age SSH
message -> stored CBOR byte string`. The signed header binds encryption mode
and recipient; the signed record/chunk binds the stored bytes, not a separately
encoded codec field. There is no raw-CBOR fallback. Each stored value contains
exactly one independently decodable Zstd frame with a content
checksum, declared decoded size, no dictionary, and a maximum 2 MiB window.
The decoder accepts at most 32 blocks; it rejects skippable or concatenated
frames and trailing bytes and limits both
the stored and decoded lengths. The Zstd encoder may choose a raw block for
small inputs; this still carries a valid frame header and checksum. Each
encrypted unit is its own age message. The reader must authenticate the
message through EOF before accepting the decoded CBOR; a mismatched recipient
fingerprint, truncated ciphertext, or trailing age data is invalid. Do not
attempt to compress ciphertext. Header and seal are small, uncompressed
CBOR units. A signed, separately persisted head is recovery state, not an
alternative source of event data. Only uncommitted tails beyond
the last accepted checkpoint may be truncated; a committed invalid unit fails
verification.

Each encrypted audit log has exactly one dedicated age SSH recipient. The
server has its public key but must not have the matching private key. Reject
reuse of any signing, host, static SSH environment, or SFTP target key whose
private key is available to the server, across all configured audit logs and
recordings. Dynamically rendered key paths must be kept disjoint by the
operator. Only offline verification and explicit sensitive export use the
private decryption identity. Do not weaken this separation when unifying the
four container formats.

## Audit identity and chain

The audit header binds format version, encryption mode, producer ID, signing
public key, segment sequence, previous segment hash, previous record hash,
creation time, and (for age) recipient fingerprint. Each record binds a new
UUIDv4, timestamp, previous record hash, public event fields, and the stored
private event bytes. The seal binds sequence, record count, content byte count,
content hash, last record hash, and seal time. All three carry Ed25519
signatures over domain-separated, deterministic CBOR excluding their own
signature field.

Let `C(M)` be the exact canonical CBOR encoding of map `M`; `P` is the full
record payload **including** its signature; `F(X)` is the entire committed
state-1 frame of unit `X` (type, length, state 1, payload, CRC32C, marker).
`A` is the eight-byte audit magic. `||` denotes byte concatenation and
`SHA256` returns 32 raw bytes. Each signature in the audit tables is
`Ed25519.sign(D_signature || C(map without its signature key))`, with the
domain `D_signature` selected from the corresponding list below. The
unsigned map retains all optional keys actually present. Do not sign a framed
unit, a hash, JSON, or CBOR containing the signature field.

```text
record_hash   = SHA256(D_audit_record_hash || P)
content_bytes = len(A || F(header) || F(record_1) || ... || F(record_n))
content_hash  = SHA256(D_audit_content_hash || A || F(header) || F(record_1) || ... || F(record_n))
segment_hash  = SHA256(D_audit_segment_hash || A || F(header) || F(record_1) || ... || F(record_n) || F(seal))
```

The predecessor of record 1 comes from the header; later records chain to
the previous `record_hash`, also across segment boundaries. The seal's
`content_bytes` is the byte offset at which its frame starts. `segment_hash`
is bound by the canonical file name and next segment header. The signed audit
head binds the last accepted record hash. All domains are literal ASCII bytes
including the terminal NUL (`\x00`), distinct from recording and JSON journal
domains:

```text
BIFROEST-BAUDIT-HEADER-SIGNATURE/v1\x00
BIFROEST-BAUDIT-RECORD-SIGNATURE/v1\x00
BIFROEST-BAUDIT-SEAL-SIGNATURE/v1\x00
BIFROEST-BAUDIT-HEAD-SIGNATURE/v1\x00
BIFROEST-BAUDIT-RECORD-HASH/v1\x00
BIFROEST-BAUDIT-CONTENT-HASH/v1\x00
BIFROEST-BAUDIT-SEGMENT-HASH/v1\x00
```

Signatures and hashes verify the public metadata and committed private bytes
without a decryption key. Full semantic validation of encrypted private data
also requires the matching private age key. Producer identity needs an
independently trusted expected producer ID. Detecting deletion of a valid
suffix of a remote history additionally requires an independently retained
expected chain tip; a signed head stored beside a mutable journal cannot by
itself rule out rollback of both.

## Public and confidential audit fields

The public part of every event contains `name` and, when present, `domain` and
`outcome`. The signed record contains the timestamp, record ID, predecessor
hash, and signature; its signed enclosing header contains producer identity,
segment sequence, encryption mode, and recipient fingerprint where applicable.
The record and segment hashes are calculated from those signed bytes. Record IDs
identify only that record; they are not connection/session correlation IDs.
The default JSONL event contains only `name`, `domain`, and `outcome` when
present. Its separate export envelope contains `auditlog`, `producerId`,
`segmentSequence`, `segmentRecordIndex`, `id`, `recordedAt`, `previousHash`,
and `hash`. Signing key, signature, encryption mode, and recipient fingerprint
remain inspectable in the native artifact but MUST NOT appear in default JSONL
lines. Do not treat a redacted JSONL line as an independently signed record.

The confidential part contains **every other** current `Event` field:
`flow`, `connectionId`, `sessionId`, `operationId`, `recordingId`,
`recordingDigest`, `target`, `authenticationMethod`, `authenticationPhase`,
`authorizationKind`, `sessionTask`, `reason`, `errorCategory`, `exitCode`,
`bytesRead`, `bytesWritten`, `durationMillis`, `count`, `pty`,
`agentForwarding`, and `forcedCommand`. New fields default to confidential
until explicitly classified and documented. Audit event values still follow
their established type and validation rules; do not infer a closed set of
names or reasons merely from the current lists of constants.

The confidential event map is CBOR-encoded and Zstd-compressed for every
record, including an empty map. In `.beaudit` it is also age-encrypted per
record; in `.baudit` the compressed map is unencrypted. The visible and stored
parts are jointly signed, so a redacted export can never be substituted for
the signed original. `audit export` and `audit merge` omit the confidential
fields by default **even for `.baudit`**; `--with-sensitive` includes them
only after full verification and, for `.beaudit`, decryption. Redaction is not
access control: `.baudit` contains the private map in plaintext after
decompression. Even public metadata such as exact times and outcomes may be
correlated and must not be published to an unprotected destination.

## Recording identity and chain

The recording header binds version, mode, recording ID, producer ID, public
key, start time, and any recipient fingerprint. Signed outer chunk descriptors
bind sequence, previous unit hash, stored payload hash, decoded byte count,
and the continuation information required by encrypted offline recovery.
The seal binds status, counts, the last unit hash, the content hash, and the
pre-established signature of the exact canonical `.cast` export. Recording
header, chunk, seal and head signatures each sign the literal matching domain
prefix plus `C(map without signature key)` (key 8, 8, 9 and 9 respectively).
Optional keys are included only if present. Distinct domains also apply to
hashes; do not reuse the audit domains:

```text
BIFROEST-BCAST-HEADER-SIGNATURE/v1\x00
BIFROEST-BCAST-CHUNK-SIGNATURE/v1\x00
BIFROEST-BCAST-SEAL-SIGNATURE/v1\x00
BIFROEST-BCAST-HEAD-SIGNATURE/v1\x00
BIFROEST-BCAST-UNIT-HASH/v1\x00
BIFROEST-BCAST-CONTENT-HASH/v1\x00
```

For recording magic `R` (seven bytes), with `F` the exact complete committed
state-1 frame (including CRC and marker), calculate:

```text
stored_hash       = SHA256(chunk[4])              # plain SHA-256, NO domain
header_unit_hash  = SHA256(D_recording_unit_hash || F(header))
chunk_i_unit_hash = SHA256(D_recording_unit_hash || F(chunk_i))
content_hash      = SHA256(D_recording_content_hash || R || F(header) || F(chunk_1) || ... || F(chunk_n))
```

Chunk 1 key 2 equals `header_unit_hash`; each later key 2 equals the prior
`chunk_i_unit_hash`. The seal key 3 equals the last chunk unit hash; its key 4
hashes from offset zero through the byte immediately before the seal (including
magic, header, all committed chunks; excluding the seal). Neither chain hash
includes the magic; the content hash does. There is no recording equivalent of
the audit sealed-segment hash. The recording head key 4 is the exact physical
prefix length at the end of a committed continuation frame; keys 5..8 must
match that prefix's chunk count, last unit hash and last Cast checkpoint.

For a nonfinal chunk, Cast key 6 is the 32 raw SHA-256 internal chaining-state
bytes at a 64-byte block boundary, **not** a digest: the eight state words
`H0` through `H7` in that order, each encoded as a big-endian 32-bit integer,
before SHA-256 final padding. Key 7 is the total number
of bytes fed to SHA-256, including the literal
`BIFROEST-ASCIICAST-CONTENT-HASH/v1\x00` prefix and all rendered Cast content
through that chunk's padding line and LF. It is positive, increasing and
divisible by 64. The padding line has prefix
`# becast-checkpoint-padding:v1 `, followed by the unique 0..63 ASCII zeros
needed so `(processed_bytes + len(padding_prefix) + zeros + 1 LF) % 64 == 0`.
No SHA-256 partial block is retained in the signed checkpoint. On a final
chunk key 7 is zero and key 6 is the completed Cast digest (key 10), **not** a
resumable state. Key 12 and seal key 7 count complete `.cast` bytes including
the final signature comment and its LF; unlike Cast key 7 they exclude the
hash domain. The Cast digest instead covers the domain plus exact Cast lines
through the result line and LF, excluding the signature comment.

The standalone Cast keeps its existing `bifroest.asciicast-signature/v1`
schema and the domains `BIFROEST-ASCIICAST-CONTENT-HASH/v1\x00` and
`BIFROEST-ASCIICAST-SIGNATURE/v1\x00`. Its digest hashes the exact canonical
Asciicast v3 bytes, including LF, through the result line but excluding the
final signature comment. Its Ed25519 signature covers the domain plus the
canonical JSON signature content (`schema`, `recordingId`, `producerId`,
lowercase hex `digest`, and binary SSH `publicKey` as Base64). The native seal
stores that signature and digest; no JSON or Cast line is stored inside the
native recording. Offline export must reproduce and verify those same bytes
without access to the server's signing key.

### Canonical standalone Cast

The native writer and offline exporter use the same asciicast v3 rendering
rules. Every line ends in one LF byte (`0a`); there is no BOM, CRLF, extra
whitespace, or automatic plaintext file. The first line is compact JSON with
fields in this order: `version` (3), `term` (`cols`, `rows`, optional `type`),
and `timestamp` (Unix seconds). The second line starts with the literal
`# bifroest:metadata:v1 ` and compact JSON with `schema`, `recordingId`,
`connectionId`, `sessionId`, `operationId`, `flow`, `task`, `pty`, `producerId`,
and `startedAt`, in that order. Timestamps in these comments use Go's JSON
encoding of UTC `time.Time` (RFC 3339 with the necessary fractional digits).
UUIDs and the producer ID use canonical lowercase text. Comment objects use
the established Go JSON encoding of the fixed-field structs, including JSON
escaping of HTML characters, U+2028, and U+2029.

Output is divided into events of at most 65,536 raw bytes; a split does not
divide a valid multibyte UTF-8 rune when a complete rune fits within the
limit. For stderr, or for an event containing invalid UTF-8, immediately
before its `o` event emit `# bifroest:event:v1 ` followed by compact JSON
fields `schema`, `sequence`, `stream` and, only for invalid UTF-8, `raw`.
`raw` is the original bytes encoded as JSON Base64; the displayed event string
replaces each maximal contiguous run of invalid UTF-8 bytes with one U+FFFD
(the `strings.ToValidUTF8` rule). The sequence counts all events, not only
output events. The event line has the exact shape
`[seconds.mmm,"code",json-string]`, without spaces. Codes `o`, `r`, `m`, and
`x` denote output, resize (`colsxrows`), marker, and decimal exit status.
Absolute event time is rounded to the nearest millisecond, with half a
millisecond rounded up; the line contains the difference from the previously
rounded event. Strings escape quotes, backslashes, standard JSON controls,
non-printing Unicode and U+2028/U+2029, using lowercase hex in `\u` escapes
and UTF-16 surrogate pairs where necessary. They do not use comment JSON's
HTML escaping.

Every nonfinal native chunk ends with a logical padding event. Only the Cast
renderer emits its line: `# becast-checkpoint-padding:v1 `, zero or more ASCII
`0` bytes, then LF. Choose the number of zeros from `0..63` so that the Cast
SHA-256 input byte count, including its domain prefix, becomes divisible by
64. The native chunk stores no Cast or JSON line. An optional `x` exit event
precedes `# bifroest:result:v1 ` plus compact JSON fields `schema`, `status`,
`endedAt`, and optional `reason`. The domain-separated SHA-256 digest includes
all lines from the header through this result line, with each LF, but not the
signature line. The final line is `# bifroest:signature:v1 ` followed by
compact JSON fields `schema`, `recordingId`, `producerId`, `digest`,
`publicKey`, and `signature`, then LF. `digest` is lowercase hex; `publicKey`
is the Base64-encoded binary SSH public key, and `signature` is Base64 of the
Ed25519 signature over the specified domain and the compact JSON of the
preceding five fields. The signed native final chunk and seal already bind
this digest and signature. `VerifyCast` accepts some non-canonical standalone
Cast header/event spellings, but native export **always** produces the bytes
defined here; parser tolerance does not alter the signed native export.

Terminal bytes, stdout/stderr identity, resize dimensions, markers, and
other Cast event content remain inside native CBOR chunks. `.becast` encrypts
these chunks; `.bcast` stores them unencrypted after Zstd compression. The
outer metadata necessarily reveals at least recording identity, timing,
status, sizes, and recipient identity. Outer verification without decryption
does not claim that encrypted inner Cast content is semantically valid.
Offline recovery of `.becast` must remain possible without the recipient's
private key by using signed continuation state, without inventing terminal
output or overriding a final chunk's completed status. A valid `.cast` export
is reconstructed deterministically, checked
against the sealed digest and signature, and never emitted without explicit
`--with-sensitive`. It is the only Asciicast representation; no `.cast` or
`.jsonl` is generated automatically on disk or at remote targets.
