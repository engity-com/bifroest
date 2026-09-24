---
description: Native audit and recording container format contract.
---

# Native format contract

The server emits `.baudit` and `.beaudit` audit containers and `.bcast` and
CBOR-based `.becast` recording containers. Published byte-level recording
vectors will follow in a later milestone.

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
again. A partial header or state `0` is an uncommitted tail only beyond the
signed head checkpoint. A physically complete state-0 unit must still have
valid framing, CRC, and canonical CBOR; bytes after its declared boundary
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
Other types are invalid. Each payload is exactly
one deterministic CBOR map with unsigned integer field keys. Integer widths,
timestamp representation (`[signed Unix seconds, unsigned nanoseconds]`),
byte-string lengths, and the meaning of absent versus null fields must be
fixed in the byte-level specification. Reject duplicate/unknown keys, tags or
indefinite lengths not defined by that specification, trailing CBOR values,
and any decoded value that does not re-encode to identical canonical bytes.
CBOR is the only structured encoding in the native containers; Zstd and age
transform CBOR byte strings, not JSON or embedded Cast lines.

## CBOR wire keys (version 1)

All top-level units are maps with the following unsigned integer keys. Only
explicitly optional fields may be absent; a CBOR `null` is not an alternative
to absence. Timestamps are two-element arrays `[signed Unix seconds,
nanoseconds (0..999999999)]` with nanosecond precision. UUIDs, 32-byte hashes,
and signatures are CBOR byte strings, not integer arrays or tagged values.
The signing public key uses its binary SSH wire encoding. Integer keys and
types are implemented by the separate `pkg/audit/native-wire.go` and
`pkg/recording/native-wire.go` schemas and the strict `pkg/nativeformat`
codec. These key assignments must be kept stable when the code is integrated.

| Audit unit | Keys |
| --- | --- |
| Header | `1` version, `2` encryption, `3` producer ID, `4` public key, `5` sequence, `6` previous segment hash, `7` previous record hash, `8` creation time, `9` optional recipient fingerprint, `10` signature |
| Record | `1` UUIDv4, `2` recorded time, `3` previous record hash, `4` public event map, `5` stored private bytes, `6` signature |
| Public event | `1` name, `2` optional domain, `3` optional outcome |
| Seal | `1` sequence, `2` record count, `3` content bytes, `4` content hash, `5` last record hash, `6` seal time, `7` signature |

The confidential audit event map uses keys `1` flow, `2` connection ID,
`3` session ID, `4` operation ID, `5` recording ID, `6` recording digest,
`7` target, `8` authentication method, `9` authentication phase,
`10` authorization kind, `11` session task, `12` reason, `13` error category,
`14` exit code, `15` bytes read, `16` bytes written, `17` duration in
milliseconds, `18` count, `19` PTY, `20` agent forwarding, and
`21` forced command. All fields in this map are optional; an empty event
still has a complete, encoded empty map.

| Recording unit | Keys |
| --- | --- |
| Header | `1` version, `2` encryption, `3` recording ID, `4` producer ID, `5` public key, `6` start time, `7` optional recipient fingerprint, `8` signature |
| Chunk | `1` sequence, `2` previous unit hash, `3` decoded length, `4` stored bytes, `5` stored-byte hash, `6` Cast hash state, `7` Cast hash byte count, `8` signature, `9` optional final status, `10` optional final Cast digest, `11` optional final Cast signature, `12` optional final Cast byte count, `13` optional final end time, `14` optional continuation last event elapsed nanoseconds |
| Seal | `1` status, `2` chunk count, `3` last unit hash, `4` content hash, `5` Cast digest, `6` Cast signature, `7` Cast bytes, `8` end time, `9` signature |

Decoded recording chunks are canonical CBOR maps `{1: 1, 2: [event maps...]}`.
The event array is nonempty (at most 4096 events). Every event has unsigned
integer key `1` for its kind. Kind `1` (setup) has key `2` Cast header map
(`1` version=3, `2` columns, `3` rows, optional `4` terminal type, `5` Unix
timestamp seconds) and key `3` Cast metadata map (`1` recording UUID bytes,
`2` connection UUID bytes, `3` session UUID bytes, `4` operation UUID bytes,
`5` flow, `6` task, `7` PTY boolean, `8` producer hash bytes, `9` start
timestamp). Kind `2` (output) has `2` absolute elapsed nanoseconds, `3`
stream (`1` terminal, `2` stdout, `3` stderr), `4` raw bytes (1..65536).
Kind `3` (resize) has `2` elapsed nanoseconds, `3` columns, `4` rows. Kind
`4` (marker) has `2` elapsed nanoseconds and `3` label. Kind `5` (padding
checkpoint) has no other keys; it regenerates exactly the CastWriter SHA-256
alignment comment, never an embedded Cast line. Kind `6` (result) has `2`
elapsed nanoseconds, `3` result map (`1` status: completed=1, failed=2,
incomplete=3; `2` end timestamp, optional `3` reason), and optional `4`
exit code. Timestamps use the standard native timestamp array. Optional
empty text fields are omitted; null, unknown keys, and JSON/Asciicast lines
as event encodings are forbidden. Setup occurs once first, result once last;
the same CastWriter validations and byte rendering apply across chunks.

Continuation chunks have no keys `9`..`13`; they require key `14` for the
last actual event's absolute elapsed nanoseconds (zero is allowed). Keys `6`
and `7` contain a real, block-aligned SHA-256 state and byte count of the
reconstructed Cast content including its hash domain. Final chunks omit key
`14` and instead set `7` to zero and `6` to
the final Cast digest; they include **all** keys `9`..`13`. The signed final
chunk thus binds status, digest, standalone Cast signature, exact Cast byte
count, and end time even if the seal has not yet been committed. A seal must
match its final chunk. The signed `head.cbor` recovery state requires an exact
durable-prefix comparison. The standalone recovery core verifies this checkpoint
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
the map and signature, but excluding framing). The default target remains
256 KiB. Existing configured total-artifact and decoded-Cast quotas continue
to apply separately. Readers enforce both encoded and decoded limits before
allocating or publishing data. Zstd may use raw blocks inside its frames; the
format does not define an unwrapped raw-CBOR record variant.

Audit records compress one event each; recording chunks compress complete
groups of native recording events. For encrypted files, compression precedes
independent age encryption of the confidential CBOR bytes. Public CBOR fields
and private bytes are signed together, including codec and recipient identity.
Each unit has exactly one independently decodable Zstd frame with a content
checksum, declared decoded size, no dictionary, and a maximum 2 MiB window.
The decoder rejects concatenated frames and trailing bytes and limits both
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

The record hash is SHA-256 over domain plus the exact signed CBOR record. The
seal's content hash covers the exact physical file bytes from the magic
through the last committed record, excluding the seal. The segment hash covers
the entire sealed physical file, including its seal, and is bound by its
canonical file name and the next header. The signed audit head binds the last
accepted record hash. These are distinct domains, also distinct from the
recording and current JSON-journal domains:

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
The seal binds status, counts, the last unit hash, the content digest, and the
pre-established signature of the exact canonical `.cast` export. Use distinct
Ed25519 domains and hashes for header, chunk, seal, head, and unit chaining;
do not reuse the audit domains:

```text
BIFROEST-BCAST-HEADER-SIGNATURE/v1\x00
BIFROEST-BCAST-CHUNK-SIGNATURE/v1\x00
BIFROEST-BCAST-SEAL-SIGNATURE/v1\x00
BIFROEST-BCAST-HEAD-SIGNATURE/v1\x00
BIFROEST-BCAST-UNIT-HASH/v1\x00
BIFROEST-BCAST-CONTENT-HASH/v1\x00
```

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
