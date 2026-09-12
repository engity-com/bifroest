---
description: Replicate sealed Bifröst audit-log segments to remote storage.
---

# Remote targets

Remote targets copy complete, sealed audit-log segments to external storage. The local journal remains the authoritative, crash-safe source; remote targets provide additional independent retention and never receive the active segment.

Bifröst delivers segments in sequence with one independent worker per target. A failed target does not block recording or another target. Failed attempts use exponential backoff with jitter and resume automatically when the target becomes available again.

After a target confirms a segment, Bifröst stores a signed cursor below `<journal-directory>/.delivery/<producer-id>/<target-id>/cursor.json`. The target ID is a SHA-256 hash of the exact target name, avoiding filesystem aliases between distinct names. Normal delivery never publishes a segment at or before that cursor again. If a process stops after the remote write succeeds but before the cursor is durable, the next attempt safely verifies the same immutable remote object through the target's idempotent publication protocol.

The target name is its durable delivery identity. Changing an endpoint or credentials under the same name continues at the existing cursor; use a new target name when a replacement destination must receive all locally available segments.

Local sealed segments are retained even after every configured target confirms them. Bifröst does not currently prune the authoritative chain, because removing its prefix without a signed retention checkpoint would prevent complete startup and offline verification. Remote failures therefore never cause local segment deletion.

During an orderly shutdown, Bifröst seals the current non-empty segment and allows remote targets up to five seconds to confirm the resulting journal tail. If that bounded flush cannot finish, shutdown continues and the retained segments are delivered after the next start.

Each target has a unique `name` within its audit log and selects one of the following implementations with `type`:

* [S3](s3.md) stores segments in AWS S3 or a compatible object store.
* [SFTP](sftp.md) stores segments on an SSH-authenticated SFTP server.
* [WebDAV](webdav.md) stores segments in an HTTPS WebDAV collection.
