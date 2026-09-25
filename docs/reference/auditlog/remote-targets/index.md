---
description: Replicate sealed Bifröst audit-log segments to remote storage.
---

# Remote targets

Remote targets copy **sealed originals**, not exports:

* Audit segments: `.baudit` or `.beaudit` under `<producer-id>/<segment-file-name>`.
* Selected session recordings: `.bcast` or `.becast` under `<producer-id>/<recording-uuid>.<suffix>`.

When the audit journal is enabled, it remains authoritative and retains its segments. Remote targets never receive `head.cbor`, the active segment, JSONL or a decrypted Cast. A downloaded segment alone is **not** a complete journal for the [audit CLI](../../cli/audit/index.md). Keep the complete local journal for verification and an independently trusted chain tip to detect missing remote history. [Recording-only](../recording.md#recording-only) delivers sealed Recordings without creating journal segments.

Clear originals contain confidential content after decompression; encrypted originals expose signed public metadata. Protect every destination and configure its retention independently.

## Available targets

Each target needs a unique `name` within its audit log and selects an implementation with `type`:

* [S3](s3.md) stores segments in AWS S3 or a compatible object store.
* [SFTP](sftp.md) stores segments on an SSH-authenticated SFTP server.
* [WebDAV](webdav.md) stores segments in an HTTPS WebDAV collection.

## Delivery behavior

* Each target has an independent worker. Segments are delivered in order; failures retry with backoff and a fresh timeout without blocking local audit writes or other targets.
* Filesystem notifications trigger delivery, backed by a periodic scan. If notifications fail, polling continues with a warning.
* On shutdown, Bifröst seals a non-empty active segment and allows up to five seconds for delivery. Undelivered segments remain local for the next start.

## Delivery identity

A signed cursor under `<auditlog-directory>/.delivery/` binds the last confirmed segment to its target name and effective destination:

* Credentials and timeouts can rotate without resetting it. Changing the endpoint, namespace, bucket, prefix, directory, destination user or SFTP host-key trust under the same name fails closed. Use a new target name to deliver the full history to a replacement destination.
* For SFTP, host-key trust depends on the `knownHosts` entries or **contents** of `knownHostsFile`, not its path. Switching to `acceptAllHostKeys` also changes the destination identity.
* Before the next delivery and again after restart, Bifröst reconstructs and verifies the predecessor chain against the cursor. Removing a confirmed local segment fails closed: a cursor alone cannot reconstruct the chain or prove a remote copy still exists.

## Recording receipts

Before publishing a sealed recording locally, Bifröst stores a signed receipt under its repository's `.delivery/`. It permanently binds the artifact's digest and size to the **selected targets and destination fingerprints at sealing time**. Later target changes cannot redirect that artifact.

At startup:

* A sealed artifact without its matching receipt fails closed.
* A receipt without its artifact fails closed, unless durable retention deletion already began.
* If both receipt and artifact disappear, detection requires an independent inventory.

With an enabled audit journal, receipts also hold the outbox for [`session.recording.delivery.failed` and `session.recording.delivery.succeeded`](../events.md#sessionrecordingdeliveryfailed). Recording-only receipts have **no audit outbox**. All receipts count toward `maximumSpoolBytes`; temporary copies left by atomic replacement are recovered before admitting more spool growth.

## Recording delivery

* One sequential worker per selected target retries asynchronously with backoff and jitter; notifications have a periodic safety scan.
* With audit enabled, the first failure in an episode is durably recorded and audited **before another attempt**. A successful publication needs both a signed acknowledgement and success audit event. Startup replays a pending success event **without republishing**.
* Recording-only has no delivery audit events: failures retry with backoff, and a **durable signed acknowledgement** completes delivery. If acknowledgement persistence fails, the running worker does not immediately republish; restart can repeat publication in either mode. Targets must reject conflicting bytes and support idempotent retries.
* Changing or removing a target with outstanding delivery (or an enabled audit obligation) fails at startup. Completed historical targets do not block changes.
* Shutdown allows up to five seconds for acknowledgements and, when audit is enabled, audit events. Unfinished work remains in the local spool for restart.

## Recording retention

`recording.retainFor` defaults to 30 days. It starts at sealing without targets, or at the **latest durable target acknowledgement** with targets. With audit enabled, each selected target's success event must also be durably marked before deletion.

Housekeeping verifies the signed receipt and artifact, marks deletion durably, deletes the local artifact **before** the receipt, and retries later if verification, deletion or (when enabled) audit-start fails. `retainFor: 0s` stops new deletions, not one already begun. Remote copies and local audit-log segments are never deleted by Recording retention.

## Example

An S3 target with bucket `company-bifroest-audit` and prefix `bifroest-auditlog` stores a sealed segment at:

```text
s3://company-bifroest-audit/bifroest-auditlog/<producer-id>/segment-00000000000000000001-<segment-hash>.beaudit
```

The placeholders are not trust anchors. Preserve the exact bytes; the remote file name alone cannot establish producer identity.
