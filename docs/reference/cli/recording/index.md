---
description: Find, inspect, verify, export and play signed Bifröst session recordings.
---

# `bifroest recording`

Work with sealed session recordings from a configured repository or a copied artifact. [Session recording configuration](../../auditlog/recording.md) controls capture, storage, encryption and delivery.

## Commands

| Command | Purpose |
| --- | --- |
| [`ls`](ls.md) | List one bounded page of verified repository metadata. |
| [`show`](show.md) | Show verified metadata for one repository Recording ID. |
| [`inspect`](inspect.md) | Inspect a local artifact and emit JSON metadata. |
| [`verify`](verify.md) | Verify evidence against a trusted producer, without replaying content. |
| [`export`](export.md) | Verify and export the signed asciicast v3 stream. |
| [`play`](play.md) | Verify and replay captured terminal output. |

Repository commands select an auditlog name and Recording UUID. File commands accept `.bcast`, `.becast` or signed `.cast` as documented. Remote verification, export and playback download the signed original and run on the CLI machine; see [Remote access](../management.md).

<span id="listing-pages"></span>
<span id="streaming-a-page"></span>

Paging, ID order and streaming behavior are documented on [`recording ls`](ls.md). Producer trust, decryption and protected output paths are described in [Trust and verification](../verification.md).

## Examples

* [Record, find and replay a session](../../../guides/recording.md) on the Bifröst host.
* [Verify encrypted evidence on a workstation](../../../guides/evidence.md) using a trusted producer ID and a local recipient key.
