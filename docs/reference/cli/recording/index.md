---
description: Inspect, verify, and export Bifröst session Recording artifacts.
---

# `bifroest recording`

Recording commands verify sealed session Recording artifacts without changing them. On the Bifröst host, `recording export` and `recording verify` select `<auditlogName> <recording-uuid>` from a configured Recording repository and trust its signing identity. For offline use, copy the original `.bcast` or `.becast` bytes from `sealed/<recording-uuid>.<suffix>` or download them from a remote target under `<producer-id>/<recording-uuid>.<suffix>`. Bifröst does not list or download artifacts and does not automatically create plaintext `.cast` or `.jsonl` copies. See the [end-to-end workflow](../../auditlog/recording.md#export-and-playback), [native recording format](../../../formats/recording.md), and [native vectors](../../../formats/recording-vectors.md).

An embedded signing key proves that an artifact is internally consistent, not who produced it. Supply the positional `.bcast` or `.becast` file with `--expectedProducerId ID` for offline export or verification; obtain the 64-hex ID independently, for example from [`audit producer-id`](../audit/producer-id.md) on the host. `inspect` emits metadata only; encrypted `.becast` receives outer verification without a key. `verify` reports outer or full verification without outputting Cast content. `export --with-sensitive` produces the complete, **never redacted** signed asciicast v3 stream. It needs the offline age SSH decryption identity for `.becast`, but not for clear `.bcast`. Protect the plaintext export and the public metadata in the original artifact even if an unrelated audit JSONL export is redacted.

## Commands

* [`bifroest recording inspect`](inspect.md) verifies one Recording artifact and emits its metadata as JSON.
* [`bifroest recording verify`](verify.md) checks a Recording against a trusted producer without exporting the Cast.
* [`bifroest recording export`](export.md) verifies, decompresses, and when necessary decrypts one Recording artifact as asciicast v3.
