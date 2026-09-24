---
description: Native audit segment fields, privacy boundary, and signed hash chain.
---

# Native audit format

This is the version 1 byte contract for signed audit segments: clear `.baudit`
and age-encrypted `.beaudit`. Start with the shared [container framing and CBOR
rules](container.md); this page covers the audit-specific maps, confidentiality,
and chain. See [recording](recording.md) for session recordings,
[audit vectors](audit-vectors.md) for downloadable examples, and the
[audit log reference](../reference/auditlog/index.md) for operation and CLI use.

## Audit maps

All keys below are unsigned-integer CBOR map keys in version 1. `R` means
required; `O` means omit the key when absent, not encode null or an empty
placeholder. The types, deterministic encoding, validation, and unit framing
follow the [container rules](container.md). A signed `head.cbor` is one raw
canonical CBOR map, **not** a framed, compressed, or encrypted unit.

### Header (type 1)

| Key | Field | Type | Presence |
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

### Record (type 2)

| Key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | record ID | uuid16 | R |
| 2 | recorded time | timestamp | R |
| 3 | previous record hash | hash32 | R |
| 4 | public event | public event map | R |
| 5 | stored private event (Zstd frame or age message) | nonempty bytes | R |
| 6 | signature | sig64 | R |

The public event map has these keys:

| Key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | name (nonempty) | text | R |
| 2 | domain | nonempty text | O |
| 3 | outcome | nonempty text | O |

The private event is itself a canonical CBOR map **before** compression. Its
IDs and recording digest are text in the established audit Event schema, not
`uuid16` or `hash32` CBOR byte strings. Every key below is optional.

| Key | Private event field | Type | Presence |
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

### Seal (type 3)

| Key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | segment sequence | u64 | R |
| 2 | record count (positive) | u64 | R |
| 3 | content byte count | u64 | R |
| 4 | content hash | hash32 | R |
| 5 | last record hash | hash32 | R |
| 6 | seal time | timestamp | R |
| 7 | signature | sig64 | R |

### Signed audit head

| Key | Field | Type | Presence |
| --- | --- | --- | --- |
| 1 | version (`1`) | u8 | R |
| 2 | producer ID | hash32 | R |
| 3 | signing public key | ssh-key | R |
| 4 | last accepted record hash (zero for empty history) | hash32 | R |
| 5 | signature | sig64 | R |

## Public and confidential audit fields

Every public event contains `name` and, when present, `domain` and `outcome`.
The signed record also contains timestamp, record ID, predecessor hash, and
signature. Its signed header contains producer identity, segment sequence,
encryption mode, and the recipient fingerprint when applicable. Record and
segment hashes are calculated from these signed bytes. Record IDs identify
individual records, **not** connections or sessions.

Default JSONL event data contains only `name`, `domain`, and `outcome` when
present. The separate export envelope contains `auditlog`, `producerId`,
`segmentSequence`, `segmentRecordIndex`, `id`, `recordedAt`, `previousHash`,
and `hash`. Signing key, signature, encryption mode, and recipient fingerprint
are inspectable in the native artifact but **MUST NOT** appear in default
JSONL lines. A redacted JSONL line is not an independently signed record.

The confidential part contains **every other** current `Event` field:
`flow`, `connectionId`, `sessionId`, `operationId`, `recordingId`,
`recordingDigest`, `target`, `authenticationMethod`, `authenticationPhase`,
`authorizationKind`, `sessionTask`, `reason`, `errorCategory`, `exitCode`,
`bytesRead`, `bytesWritten`, `durationMillis`, `count`, `pty`,
`agentForwarding`, and `forcedCommand`. New fields default to confidential
until explicitly classified and documented. Event values still obey their
established type and validation rules; the current name and reason constants
do not imply a closed set.

Every record encodes and Zstd-compresses its private event map, even when the
map is empty. `.beaudit` also encrypts it with age **per record**; `.baudit`
leaves the compressed map unencrypted. Public and stored private parts are
jointly signed: redacted output cannot replace the signed original.

`audit export` and `audit merge` omit private fields by default **even for
`.baudit`**. `--with-sensitive` includes them only after full verification
and, for `.beaudit`, decryption. Redaction is not access control: `.baudit`
reveals the private map after decompression. Even public times and outcomes
can be correlated; do not publish them to an unprotected destination.

## Audit payload limits

An audit record commits independently: write and sync its framed body; set
and sync its commit-state byte; then atomically replace and sync the signed
head. The [container rules](container.md#store-a-private-payload) describe
the shared CBOR, Zstd, and optional age pipeline.

The following limits exclude the 18 framing bytes where specified:

| Item | Limit |
| --- | --- |
| Audit header, seal, or public event CBOR map | 4 KiB each |
| Private audit-event CBOR map before compression/encryption | 64 KiB |
| Complete stored audit-record CBOR payload | 128 KiB, excluding framing |
| Audit segment | Approximately 16 MiB target; 17 MiB verification limit |

Readers enforce both encoded and decoded limits before publishing data.
Each encrypted audit log has one dedicated age SSH recipient: the server
holds its public key, **never** its private key. Do not reuse a signing, host,
static SSH environment, or SFTP target key whose private part is available
to the server. This rule applies across all configured audit logs and
recordings; operators must also keep dynamically rendered key paths disjoint.

## Audit identity and chain

The audit header binds version, encryption mode, producer ID, signing public
key, segment sequence, previous segment hash, previous record hash, creation
time, and (for age) recipient fingerprint. Each record binds a new UUIDv4,
timestamp, previous record hash, public event fields, and stored private
bytes. The seal binds sequence, record count, content byte count, content
hash, last record hash, and seal time. Header, record, and seal have Ed25519
signatures over domain-separated deterministic CBOR excluding their own
signature field. The signed head binds the last accepted record hash.

Let `C(M)` be the exact canonical CBOR encoding of map `M`; `P` is the full
record payload **including** its signature; `F(X)` is the entire committed
state-1 frame of unit `X` (type, length, state 1, payload, CRC32C, marker).
`A` is the eight-byte audit magic (`\x89BAUDIT\n`); `||` concatenates bytes;
`SHA256` returns 32 raw bytes. Each audit-table signature is
`Ed25519.sign(D_signature || C(map without its signature key))`, using its
corresponding domain below. The unsigned map retains every optional key
actually present. Do **not** sign a framed unit, a hash, JSON, or CBOR that
contains the signature key.

```text
record_hash   = SHA256(D_audit_record_hash || P)
content_bytes = len(A || F(header) || F(record_1) || ... || F(record_n))
content_hash  = SHA256(D_audit_content_hash || A || F(header) || F(record_1) || ... || F(record_n))
segment_hash  = SHA256(D_audit_segment_hash || A || F(header) || F(record_1) || ... || F(record_n) || F(seal))
```

Record 1 takes its predecessor from the header; later records chain to the
previous `record_hash`, including across segment boundaries. Seal
`content_bytes` is the byte offset where the seal frame begins. The canonical
file name and next segment header bind `segment_hash`.

These domains are **literal ASCII bytes including the terminal NUL** (`\x00`),
distinct from recording and JSON journal domains:

```text
BIFROEST-BAUDIT-HEADER-SIGNATURE/v1\x00
BIFROEST-BAUDIT-RECORD-SIGNATURE/v1\x00
BIFROEST-BAUDIT-SEAL-SIGNATURE/v1\x00
BIFROEST-BAUDIT-HEAD-SIGNATURE/v1\x00
BIFROEST-BAUDIT-RECORD-HASH/v1\x00
BIFROEST-BAUDIT-CONTENT-HASH/v1\x00
BIFROEST-BAUDIT-SEGMENT-HASH/v1\x00
```

Signatures and hashes verify public metadata and committed private bytes
without a decryption key. Full semantic validation of encrypted private
events also needs the matching private age key. Verification needs an
independently trusted expected producer ID; the embedded key is not a trust
anchor. Detecting deletion of a valid remote suffix also needs an
independently retained expected chain tip: a signed head beside a mutable
journal does not prevent rollback of both.

## Checkpoints and recovery

The audit head's key 4 is a **record hash**, not a byte offset or Cast
checkpoint. Find it by validating the record chain across segments. With
existing history, a missing head fails closed; only a genuinely empty new
journal may start with a zero-hash head. The signed head must point to a
record in the validated chain. Committed valid units after the head can be
verified and the signed head advanced to the durable tip.

Recovery accepts only valid framing, CRC, and canonical CBOR for a physically
complete uncommitted state-0 unit with no following bytes; it discards that
uncommitted tail, except an interrupted audit header may be committed after
full signature and chain validation. A physically short state-0 tail may be
truncated only if bounded overlap search finds no plausible committed state-1
unit. A state-0 tail before the checkpoint, an invalid committed unit, an
overlapping committed candidate, or extra bytes after a state-0 unit fails
closed. Never silently skip or repair committed evidence.

For a complete sealed segment, check the seal, physical hash, predecessor
chain, and canonical published name. Outer verification checks signed frames,
CRC, identities, hashes, stored-byte commitments, and the seal without age
keys. For clear payloads it also decompresses and checks canonical CBOR; for
encrypted payloads it cannot attest to decrypted event semantics. Full
verification decrypts/authenticates if needed and validates the private audit
event. The [operational audit documentation](../reference/auditlog/index.md)
explains verification and export of a complete journal.
