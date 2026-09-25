---
description: Inspect and export Bifröst session Recording artifacts.
---

# `bifroest recording`

Recording commands verify sealed session Recording artifacts without changing them. Copy the original `.bcast` or `.becast` bytes from the local repository's `sealed/<recording-uuid>.<suffix>` or download them from a remote target under `<producer-id>/<recording-uuid>.<suffix>`. Bifröst does not list or download artifacts and does not automatically create plaintext `.cast` or `.jsonl` copies. See the [end-to-end workflow](../../auditlog/recording.md#export-and-playback), [native recording format](../../../formats/recording.md), and [native vectors](../../../formats/recording-vectors.md).

An embedded signing key proves that an artifact is internally consistent, not who produced it. Supply an independently obtained 64-hex producer ID with `--expectedProducerId` for copied or downloaded artifacts; on the Bifröst host, `recording export --auditlog <name>` can instead trust the configured local signing identity for a file in that log's `sealed/` directory. [`audit producer-id`](../audit/producer-id.md) prints the ID from that identity for independently trusted offline use. `inspect` emits metadata only; encrypted `.becast` receives outer verification without a key. `export --with-sensitive` produces the complete, **never redacted** signed asciicast v3 stream. It needs the offline age SSH decryption identity for `.becast`, but not for clear `.bcast`. Protect the plaintext export and the public metadata in the original artifact even if an unrelated audit JSONL export is redacted.

## Commands

* [`bifroest recording inspect`](inspect.md) verifies one Recording artifact and emits its metadata as JSON.
* [`bifroest recording export`](export.md) verifies, decompresses, and when necessary decrypts one Recording artifact as asciicast v3.
