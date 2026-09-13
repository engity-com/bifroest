---
description: Replicate sealed Bifröst audit-log segments to remote storage.
---

# Remote targets

Remote targets copy sealed audit-log segments to external storage. The local journal remains the authoritative source and keeps all segments after successful delivery.

## Available targets

Each target needs a unique `name` within its audit log and selects an implementation with `type`:

* [S3](s3.md) stores segments in AWS S3 or a compatible object store.
* [SFTP](sftp.md) stores segments on an SSH-authenticated SFTP server.
* [WebDAV](webdav.md) stores segments in an HTTPS WebDAV collection.

## Delivery behavior

Bifröst delivers segments in sequence with one independent worker per target. Failures do not block audit recording or other targets; they are retried with exponential backoff and a fresh timeout.

New segments are discovered through filesystem notifications and a periodic safety scan. If notifications are unavailable, Bifröst continues with bounded polling and logs a warning.

During shutdown, Bifröst seals a non-empty active segment and gives targets up to five seconds to catch up. Undelivered segments remain local and continue after the next start.

## Delivery identity

A signed cursor below `<journal-directory>/.delivery/` records the last confirmed segment and binds it to the target name and effective destination. Credential and timeout rotation keeps the cursor, while changing the endpoint, namespace, bucket, prefix, directory, or destination user under the same name fails closed. Use a new target name when a replacement destination must receive the complete local history.

## Custom targets

Custom Go targets return `RemoteTargetSettings` with a stable, non-secret `DestinationIdentity` and a positive `PublishAttemptTimeout`. Their `Publish` method must honor context cancellation, and `Close` must unblock an active publication during shutdown.
