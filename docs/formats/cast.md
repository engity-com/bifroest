---
description: Byte-exact standalone Cast rendering and signatures for native recordings.
---

# Standalone Cast format

A native [recording](recording.md) stores CBOR events, not Asciicast lines. Offline export
reconstructs one signed asciicast v3 `.cast` for playback and full verification. Consult
the [native vectors](recording-vectors.md) for real bytes and the
[operator guide](../reference/auditlog/recording.md#export-and-playback) before exporting
sensitive content.

See the byte-exact [signed Cast example](../assets/recording-format-vectors/cast-v3.cast)
or the Cast exports in the [native recording vectors](recording-vectors.md).
Shared container framing belongs to [container.md](container.md);
[audit.md](audit.md) describes the other native family.

## Canonical standalone Cast

The native writer and offline exporter use the same asciicast v3 rendering rules. Every
line ends in one LF byte (`0a`); there is no BOM, CRLF, extra whitespace, or automatic
plaintext file.

### Header and metadata

The first line is compact JSON with fields in this order: `version` (3), `term`
(`cols`, `rows`, optional `type`), and `timestamp` (Unix seconds).

The second line starts with the literal `# bifroest:metadata:v1 ` and compact JSON.
Its fields are `schema`, `recordingId`, `connectionId`, `sessionId`, `operationId`,
`flow`, `task`, `pty`, `producerId`, and `startedAt`, in that order.

Timestamps in these comments use Go's JSON encoding of UTC `time.Time` (RFC 3339 with
the necessary fractional digits). UUIDs and the producer ID use canonical lowercase
text. Comment objects use the established Go JSON encoding of the fixed-field structs,
including JSON escaping of HTML characters, U+2028, and U+2029.

### Split and annotate output

Output is divided into events of at most 65,536 raw bytes. A split does not divide a
valid multibyte UTF-8 rune when a complete rune fits within the limit.

For stderr, or for an event containing invalid UTF-8, immediately before its `o` event
emit `# bifroest:event:v1 ` followed by compact JSON fields `schema`, `sequence`,
`stream` and, only for invalid UTF-8, `raw`. `raw` is the original bytes encoded as
JSON Base64. The displayed event string replaces each maximal contiguous run of
invalid UTF-8 bytes with one U+FFFD (the `strings.ToValidUTF8` rule). The sequence
counts all events, not only output events.

### Render event lines

The event line has the exact shape `[seconds.mmm,"code",json-string]`, without spaces.
Codes `o`, `r`, `m`, and `x` denote output, resize (`colsxrows`), marker, and decimal
exit status. Absolute event time is rounded to the nearest millisecond, with half a
millisecond rounded up. The line contains the difference from the previously rounded
event.

Strings escape quotes, backslashes, standard JSON controls, non-printing Unicode and
U+2028/U+2029. They use lowercase hex in `\u` escapes and UTF-16 surrogate pairs where
necessary. They do not use comment JSON's HTML escaping.

### Align each checkpoint

Every nonfinal native chunk ends with a logical padding event. Only the Cast renderer
emits its line: `# becast-checkpoint-padding:v1 `, zero or more ASCII `0` bytes, then LF.
Choose the number of zeros from `0..63` so that the Cast SHA-256 input byte count,
including its domain prefix, becomes divisible by 64.

The native chunk stores no Cast or JSON line. See
[recording checkpoints](recording.md#cast-checkpoint-and-signature) for the signed
chaining state.

### Finish and sign the Cast

An optional `x` exit event precedes `# bifroest:result:v1 ` plus compact JSON fields
`schema`, `status`, `endedAt`, and optional `reason`. The domain-separated SHA-256
digest includes all lines from the header through this result line, with each LF, but
not the signature line.

The final line is `# bifroest:signature:v1 ` followed by compact JSON fields `schema`,
`recordingId`, `producerId`, `digest`, `publicKey`, and `signature`, then LF. `digest` is
lowercase hex; `publicKey` is the Base64-encoded binary SSH public key. `signature` is
Base64 of the Ed25519 signature over the specified domain and the compact JSON of the
preceding five fields.

The standalone Cast keeps schema `bifroest.asciicast-signature/v1` and domains
`BIFROEST-ASCIICAST-CONTENT-HASH/v1\x00` and
`BIFROEST-ASCIICAST-SIGNATURE/v1\x00`. The signed native final chunk and seal already
bind this digest and signature.

`VerifyCast` accepts some non-canonical standalone Cast header/event spellings, but
native export **always** produces the bytes defined here. Parser tolerance does not
alter the signed native export.

### Keep export explicit

Terminal bytes, stdout/stderr identity, resize dimensions, markers, and other Cast event
content remain inside native CBOR chunks. `.becast` encrypts these chunks; `.bcast`
stores them unencrypted after Zstd compression. Outer metadata necessarily reveals at
least recording identity, timing, status, sizes, and recipient identity.

[Outer verification](recording.md#what-verification-establishes) without decryption does
not claim encrypted inner Cast content is semantically valid.

Offline recovery of `.becast` remains possible without the recipient private key by
using signed continuation state. It does not invent terminal output or override a final
chunk's completed status.

A valid `.cast` export is reconstructed deterministically and checked against the sealed
digest and signature. It is never emitted without explicit `--with-sensitive`. It is the
only Asciicast representation; no `.cast` or `.jsonl` is generated automatically on disk
or at remote targets.
