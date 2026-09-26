---
description: Bifröst must carry out some clean-up tasks periodically to ensure no sessions and connections are dangling.
---

# Housekeeping

Bifröst periodically removes expired sessions and resources that are no longer needed. Cleanup remains conservative when persisted state cannot be restored safely.

## Cleanup guarantees

Session storage is deleted only after the session, environment, and authorization were disposed successfully. Transient or unknown errors retain the session for a later retry. Permanently unusable local authorization tokens can be removed during an audited disposal.

For an OIDC flow whose session retention period has already elapsed, disposal means removing the locally stored token. Bifröst does not need to revalidate that token with the provider before deletion; a temporary provider outage cannot indefinitely retain an otherwise expired session. A session with a known `ValidUntil` remains stored until that time plus `keepExpiredFor`, even if already disposed. Storage failures still prevent deletion. Audit failures prevent it under `failurePolicy: strict`; `bestEffort` may instead disable the audit log and continue. OIDC disposal does not revoke tokens at the provider.

Sealed session Recordings become eligible only after their retention period and every selected target's durable acknowledgement and success-audit marker. Housekeeping verifies and marks the signed receipt before deleting the artifact, then removes the receipt state. An interruption resumes this order without recreating deleted content. See [Recording remote delivery and retention](auditlog/remote-targets/index.md#delivery-behavior) and the [`housekeeping.recording.delete.*` events](auditlog/events.md#housekeepingrecordingdeletestarted).

## Removed flows

Sessions whose flow no longer exists are preserved because Bifröst can no longer interpret their environment and authorization tokens safely. Their resources are excluded from automatic orphan cleanup, and the skip is logged as [`housekeeping.orphaned-session.cleanup.skipped`](auditlog/events.md#housekeeping-orphaned-session-cleanup-skipped).

## Corrupt sessions

Without automatic repair, corrupt entries are preserved and reported individually. Automatic repair is limited to configured flows; one corrupt entry does not block other sessions or environment cleanup.

## Properties

<<property("every", "Duration", "data-type.md#duration", default="10m")>>
How often the housekeeping should run.

<<property("initialDelay", "Duration", "data-type.md#duration", default=0)>>
How long should be waited upon start of the application before the first run. If `0` it is also blocking, even before the first connection will be accepted.

<<property("autoRepair", "bool", default=True)>>
If `true` the service will try to repair potentially corrupt or broken states by itself, as long as this is safely possible.

<<property("keepExpiredFor", "Duration", "data-type.md#duration", default="336h")>>
For how long a disposed session will be kept. The session will no longer be usable, but it might be helpful for audit reasons.

!!! note
    `336h` = 14 days
