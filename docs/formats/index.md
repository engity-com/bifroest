---
description: File formats for Bifröst audit evidence and session recordings.
---

# File formats

This section describes the bytes Bifröst writes and the signed evidence it
exports. It is for people building readers, checking interoperability, or
examining test fixtures. For configuration and day-to-day use, start with
the [audit log](../reference/auditlog/index.md) or
[session recording](../reference/auditlog/recording.md) guides instead.

## Find your format

| Artifact | What it contains | Read next |
| --- | --- | --- |
| `.baudit`, `.beaudit` | Signed audit segments; the latter encrypts private event fields. | [Native audit format](audit.md) and [audit vectors](audit-vectors.md) |
| `.bcast`, `.becast` | Signed recordings; the latter encrypts event groups. | [Native recording format](recording.md) and [recording vectors](recording-vectors.md) |
| Exported `.cast` | Signed, readable asciicast v3, reconstructed from a recording. | [Standalone Cast](cast.md) |

Start with [shared container rules](container.md) if you need to parse or
produce native bytes. They define framing, CBOR, compression, encryption,
and commit boundaries. The audit and recording pages then define their
**different** map keys and signature/hash chains. A signed `.cast` is a
verified export, not another native container.

## Before trusting a file

A valid signature alone does not identify a trusted producer. Obtain the
expected producer ID independently of the file. To detect a missing suffix
of an audit history, also preserve an expected chain tip independently.
An encrypted recording can pass **outer** verification without a private
key; that does not verify its decrypted Cast content.

The [operational audit workflow](../reference/auditlog/index.md#examples)
and [recording export workflow](../reference/auditlog/recording.md#export-and-playback)
explain how to verify and handle artifacts without implementing a decoder.
