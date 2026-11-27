---
description: Bifröst must carry out some clean-up tasks periodically to ensure no sessions and connections are dangling.
---

# Housekeeping

Bifröst periodically removes expired sessions and resources that are no longer needed, and renews due [ACME certificates](transports/tls/index.md#acme). Cleanup remains conservative when persisted state cannot be restored safely.

## Cleanup guarantees

Cleanup requires a known runtime owner. Session storage is deleted only after the session, environment, and authorization were disposed successfully through that owner. Transient or unknown errors retain the session for a later retry. Permanently unusable local authorization tokens can be removed during an audited disposal.

Unscoped orphan scans are disabled because flow labels, missing session IDs and terminal Pod state do not prove ownership. `cleanOrphan` does not override this boundary. Unassigned, mismatched and v0.7.8 sessions remain preserved for operator review; see the [restart and upgrade contract](../setup/upgrade.md#existing-sessions-no-import).

Disposal is idempotent. An already disposed entry may be inspected again while
retained, and pending resource cleanup is still attempted, but an unchanged
disposal is not reported as a new successful change. Disposal does not itself
delete the retained session entry or shorten `keepExpiredFor`.

For an OIDC flow, lost access can dispose a session before its retention period ends. Disposal removes the locally stored token after successful cleanup; Bifröst does not need to revalidate that token with the provider before deletion. A temporary provider outage cannot indefinitely retain an otherwise expired session. A session with a known `ValidUntil` remains stored until that time plus `keepExpiredFor`, even if already disposed. Storage failures still prevent deletion. Audit failures prevent it under `failurePolicy: strict`; `bestEffort` may instead disable the audit log and continue. OIDC disposal does not revoke tokens at the provider.

Sealed session Recordings become eligible only after their retention period and every selected target's durable acknowledgement and success-audit marker. Housekeeping verifies and marks the signed receipt before deleting the artifact, then removes the receipt state. An interruption resumes this order without recreating deleted content. See [Recording remote delivery and retention](auditlog/remote-targets/index.md#delivery-behavior) and the [`housekeeping.recording.delete.*` events](auditlog/events.md#housekeepingrecordingdeletestarted).

## Removed flows

Removing a flow during a live configuration change revokes its access across generations. While the old runtime owner remains available, housekeeping uses its retained providers and cleanup rules. A missing flow after process restart does not reconstruct that owner: its sessions and resources are preserved, and the skip is logged as [`housekeeping.orphaned-session.cleanup.skipped`](auditlog/events.md#housekeeping-orphaned-session-cleanup-skipped).

A changed environment does not transfer old sessions to its new provider. Live sessions retain their original owner; after restart, only an exact supported ownership proof permits reconstruction. Unknown or mismatched sessions remain stored even after the retention period. Inspect ownership and backend resources before removing anything manually. Restoring an earlier configuration does not revive an older session revision.

## Corrupt sessions

Corrupt entries are preserved and reported individually. The persistent runtime disables destructive session-metadata auto-repair, including when `autoRepair` is enabled: damaged evidence must not become permission to erase an unknown resource owner. One corrupt session does not block inspection of other sessions. Damaged process-wide runtime state or an unfinished runtime write instead blocks startup.

## Properties

<<property("every", "Duration", "data-type.md#duration", default="10m")>>
Interval between housekeeping runs, including ACME renewal checks after TLS startup.

<<property("initialDelay", "Duration", "data-type.md#duration", default=0)>>
How long should be waited upon start of the application before the first run. If `0` it is also blocking, even before the first connection will be accepted.

<<property("autoRepair", "bool", default=True)>>
If `true` the service will try to repair potentially corrupt or broken states by itself, as long as this is safely possible.

<<property("keepExpiredFor", "Duration", "data-type.md#duration", default="336h")>>
For how long a disposed session will be kept. The session will no longer be usable, but it might be helpful for audit reasons.

!!! note
    `336h` = 14 days
