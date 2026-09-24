---
description: Replicate sealed Bifröst audit-log segments to remote storage.
---

# Remote targets

Remote targets copy sealed `.baudit` or `.beaudit` audit-log segments byte for byte to external storage under `<producer-id>/<segment-file-name>`. The local journal remains the authoritative source and keeps all segments after successful delivery. Neither a JSONL export nor a decrypted recording is created remotely.

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

A signed cursor below `<journal-directory>/.delivery/` records the last confirmed segment and binds it to the target name and effective destination. Credential and timeout rotation keeps the cursor, while changing the endpoint, namespace, bucket, prefix, directory, destination user, or SFTP host-key trust under the same name fails closed. For SFTP, trust is bound to the inline entries and file contents, not the known-hosts file path; switching to `acceptAllHostKeys` also changes the destination identity. Use a new target name when a replacement destination must receive the complete local history.

Before delivering the next segment, Bifröst verifies its signed predecessor segment and record hashes against the confirmed chain. On restart it reconstructs that chain from locally retained segments, verifies the cursor against its tip, and checks a signed temporary cursor before promoting it. Removing a confirmed local segment makes delivery fail closed; the cursor alone cannot reconstruct the missing last-record hash or prove that a remote copy still exists.

## Custom targets

Custom Go targets normally register through `audit.RegisterRemoteTarget`, which binds their configuration codec and runtime factory together. `configuration.RegisterAuditlogTargetCodec` is only the low-level entry point for configuration codecs without runtime delivery support.

Factories return `RemoteTargetSettings` with a stable, non-secret `DestinationIdentity` and a positive `PublishAttemptTimeout`. A factory can be invoked separately for audit-log and inherited recording delivery, so every invocation must return an independently owned target. The target's `Publish` method must honor context cancellation, and `Close` must unblock an active publication during shutdown.

Targets can additionally implement `audit.RemoteArtifactTarget` to accept byte-exact artifacts such as sealed session recordings. `PublishArtifact` must verify the supplied `ArtifactDigest`, preserve the same atomic and idempotent publication semantics as journal segments, and reject conflicting content at the same producer-relative file name. Existing custom targets that only implement `audit.RemoteTarget` remain journal-only.

The delivery worker checks the local artifact bytes against their signed receipt before calling `PublishArtifact`; custom targets remain responsible for the integrity of the bytes they actually store and for rejecting a different remote object at the same path.

Before a sealed session recording is published locally, Bifröst stores a signed delivery receipt below the Recording repository's `.delivery` directory. The receipt binds the exact artifact digest and size to the selected target names and effective destination fingerprints. This snapshot remains authoritative for that artifact when targets are later added, removed, reordered, or reconfigured; an existing sealed artifact without its matching receipt is rejected fail-closed during service startup. The receipt also contains the persistent outbox state for [`session.recording.delivery.failed` and `session.recording.delivery.succeeded`](../events.md#sessionrecordingdeliveryfailed). Receipt files count toward the Recording repository's `maximumSpoolBytes` limit. Every state transition atomically replaces its receipt, so the old and temporary copies can coexist briefly; quota admission accounts for the durable replacement size, while a temporary copy left by a crash is fully inventoried and recovered before further spool growth is admitted.

Sealed recordings are delivered asynchronously by one sequential worker per selected target. Workers use filesystem notifications with a periodic safety scan, retry failures with exponential backoff and jitter, and persist a signed acknowledgement only after successful publication. The first failure in one Recording-target episode is persisted and audited before another publication attempt; retries do not flood the audit journal. A successful publication whose acknowledgement could not yet be persisted is not repeated by the running process. After the acknowledgement becomes durable, its pending success event is recovered and written before delivery is considered complete. During restart, publication remains at-least-once and targets must therefore preserve their idempotent conflict-detection contract.

An incomplete receipt whose target was removed or whose effective destination changed makes service preparation fail closed. Historical targets with both a durable acknowledgement and success-audit marker do not block later configuration changes. During shutdown, Bifröst gives Recording delivery up to five seconds to finish the acknowledgement and audit outbox for artifacts visible at the start of the flush; incomplete artifacts stay in the local spool and resume after restart.

Local Recording cleanup is controlled by `recording.retainFor`, which defaults to `720h`. A value of `0s` prevents new automatic deletions; cleanup that was already durably marked as started still completes after restart or reconfiguration. For an artifact with selected targets, the retention period starts at the latest durable target acknowledgement; every selected target must also have its success event durably marked before the artifact is eligible. If no target was selected, retention starts when the artifact was sealed. Housekeeping verifies the signed receipt and artifact identity, durably marks the deletion, deletes the artifact first, and removes its receipt state only afterwards. Any verification, deletion, or audit-start failure preserves the remaining local state for a later retry. Audit-log journal segments are not affected by Recording retention and remain local.
