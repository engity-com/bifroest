---
description: Inspect, verify, and export Bifröst session Recording artifacts.
---

# `bifroest recording`

Recording commands verify sealed session Recording artifacts without changing them. On the Bifröst host, `recording export` and `recording verify` select `<auditlogName> <recording-uuid>` from a configured Recording repository and trust its signing identity. For offline use, copy the original `.bcast` or `.becast` bytes from `sealed/<recording-uuid>.<suffix>` or download them from a remote target under `<producer-id>/<recording-uuid>.<suffix>`. The [SSH management client](../management.md) can list metadata and download signed artifacts for local verification, export and playback. Bifröst does not automatically create plaintext `.cast` or `.jsonl` copies. See the [end-to-end workflow](../../auditlog/recording.md#export-and-playback), [native recording format](../../../formats/recording.md), and [native vectors](../../../formats/recording-vectors.md).

An embedded signing key proves that an artifact is internally consistent, not who produced it. Supply the positional `.bcast` or `.becast` file with `--expectedProducerId ID` for offline export or verification; obtain the 64-hex ID independently, for example from [`audit producer-id`](../audit/producer-id.md) on the host. `inspect` emits metadata only; encrypted `.becast` receives outer verification without a key. `verify` reports outer or full verification without outputting Cast content. `export --with-sensitive` produces the complete, **never redacted** signed asciicast v3 stream. It needs the offline age SSH decryption identity for `.becast`, but not for clear `.bcast`. Protect the plaintext export and the public metadata in the original artifact even if an unrelated audit JSONL export is redacted.

## Commands

* `bifroest recording ls <auditlogName>` lists one bounded page of verified Recording metadata.
* `bifroest recording show <auditlogName> <recording-uuid>` shows verified metadata for one Recording.
* [`bifroest recording inspect`](inspect.md) verifies one Recording artifact and emits its metadata as JSON.
* [`bifroest recording verify`](verify.md) checks a Recording against a trusted producer without exporting the Cast.
* [`bifroest recording export`](export.md) verifies, decompresses, and when necessary decrypts one Recording artifact as asciicast v3.

## Listing pages

`recording ls` returns up to **100** entries by default, in ascending canonical Recording-ID order. This order is independent of the Recording start time. `--limit` accepts **1 through 1,000**; `0` does not request an unlimited list. Use the last returned ID as the exclusive `--after` cursor for the next page:

```shell
bifroest recording ls default --limit=100 --format=json
bifroest recording ls default --limit=100 --after=LAST_RECORDING_UUID --format=json
bifroest @bifroest-admin recording ls default --limit=100 --after=LAST_RECORDING_UUID
```

These flags apply locally, through `@host`, and over direct SSH. Only the selected artifacts are opened and cryptographically verified for metadata output; encrypted Recordings report outer verification without a decryption key. Each verified entry is streamed immediately. An invalid selected artifact aborts the request; entries already emitted remain partial output.

The directory inventory is still scanned, using fixed-size batches and memory bounded by the page size. A live repository can change between pages; newly created IDs before the current cursor appear when starting a fresh listing. Retention can remove an artifact during a request, in which case retry the page.

## Streaming a page

Streaming is the default for `recording ls`, including requests with `--limit`. The limit controls only the number of entries. Each entry is emitted as soon as that artifact has been verified. Paging, ID order and the maximum page size still apply. Tables are flushed per entry; JSON, YAML and CBOR are emitted incrementally as a single result array or sequence:

```shell
bifroest recording ls default --format=json
bifroest @bifroest-admin recording ls default --limit=100 --after=LAST_RECORDING_UUID
```

If verification, transport or output fails, streaming stops with a nonzero exit status. Entries already emitted remain partial output; JSON or CBOR can be unfinished. Management-server failures are logged on the server and reported to SSH stderr where possible. The integrated client also checks an explicit completion frame and reports a missing or failed completion as an error. Check the command's exit status before treating its output as a complete page.

Streaming uses the same SSH authentication, host-key checking and metadata permissions as normal listing. The integrated client uses a separately versioned streaming exchange; ordinary management requests keep their single-response encoding.
