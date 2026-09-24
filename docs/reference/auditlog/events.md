---
description: Reference for Bifröst audit events and their privacy and failure semantics.
---

# Audit events

For each enabled audit log, Bifröst writes structured events for security-relevant SSH transitions selected by the active [flow](../flow.md). Disabled audit logs discard events without journal side effects. Events contain controlled classifications and technical correlation IDs rather than request contents.

## Event model

Every event has a `name`. All other fields are optional and are present only when they apply to that event.

| Field | Description |
| --- | --- |
| `name` | Stable event type documented in the [event catalog](#event-catalog). |
| `domain` | Event category: `authentication`, `connection`, `housekeeping`, `port-forwarding`, or `session`. |
| `outcome` | Result: `success`, `denied`, `failure`, or `canceled`. Start events omit this field. |
| `flow` | Configured flow that selected the audit log. |
| `connectionId` | UUID correlating events from one SSH connection. |
| `sessionId` | UUID of the persistent Bifröst session, when one is available. |
| `operationId` | UUID correlating the events belonging to one task, forwarding operation, or housekeeping action. |
| `recordingId` | Canonical UUIDv4 identifying one session recording. |
| `recordingDigest` | Lowercase SHA-256 digest of the canonical signed Cast content, cryptographically bound by the recording seal. It is not a hash of the outer native `.bcast` or `.becast` container file. |
| `target` | Configured audit-log target name for a Recording delivery transition. It contains no destination address, credentials, or remote path. |
| `authenticationMethod` | `public-key`, `password`, or `keyboard-interactive`. |
| `authenticationPhase` | `candidate` before public-key possession is proven or `verified` after certificate-signature verification. |
| `authorizationKind` | Authorization implementation that produced the result, for example `simple` or `local`. |
| `sessionTask` | `shell`, `exec`, or `sftp`. |
| `reason` | Stable machine-readable reason code whose values are documented for each event. |
| `errorCategory` | Controlled error class: `unknown`, `system`, `config`, `network`, `user`, `permission`, or `expired`. |
| `exitCode` | Non-negative task exit code, including zero. |
| `bytesRead`, `bytesWritten` | Aggregate transport byte counts in the direction documented for the event. |
| `durationMillis` | Completed operation duration in milliseconds. |
| `count` | Positive number of security-relevant occurrences represented by an aggregate event. |
| `pty`, `agentForwarding`, `forcedCommand` | Boolean task properties without their request contents. |

This table describes the complete logical event, **not** the public fields of a native container. Only `name` and optional `domain` and `outcome` appear in the public event map. The record ID and time remain visible in its signed envelope; `flow`, `reason`, `target`, correlation IDs, and all other event fields belong to the compressed private map, encrypted only in `.beaudit`. The default JSONL export omits that map even for clear `.baudit`; its separate provenance envelope still contains identifying metadata. JSONL is an unsigned derived view. Protect the original container and even a redacted export from unnecessary access.

Events with the same `connectionId` belong to one SSH transport. Events with the same `sessionId` can span multiple SSH connections to one persistent Bifröst session. An `operationId` has meaning within the event lifecycle that created it and must be interpreted together with `name`.

## Event catalog

### Authentication

Authentication is evaluated flow by flow. A flow that does not match the request requirements or does not support the requested authentication method is skipped and produces no event. Evaluation stops after the first flow accepts the request.

#### `authentication.flow.evaluated`

Written after one flow has actually evaluated an authentication request.

Fields: `domain` is `authentication`; `outcome`, `flow`, `connectionId`, and `authenticationMethod` identify the evaluation. `authorizationKind` and `sessionId` are present when the authorization result supplies them. `authenticationPhase` is present for public-key authentication. `errorCategory` is present when evaluation failed with an error.

Outcomes:

* `success`: the flow accepted the authentication request.
* `denied`: the flow rejected the request, including user-classified authorization errors.
* `failure`: evaluation failed for another reason.

For public keys, `candidate` means that the key or certificate was evaluated before proof of private-key possession. User certificates are evaluated again with `verified` after their signature has been verified. An accepted candidate does not by itself mean that authentication succeeded.

Unauthenticated evaluation details are subject to the bounded [SSH audit limits](../connection/ssh.md#unauthenticated-audit). This includes every public-key `candidate`, including accepted candidates, and denied or failed password and keyboard-interactive evaluations. Accepted password and keyboard-interactive results and every public-key `verified` result bypass these limits.

#### `authentication.flow.evaluations-suppressed`

A signed aggregate written when detailed unauthenticated `authentication.flow.evaluated` records are suppressed. It never changes the authentication result.

Fields: `domain` is `authentication`; `reason`, `count`, and `durationMillis` describe the suppressed batch. For `rate-limit`, `outcome` identifies the common outcome represented by the batch. Aggregation can span flows that reference the same audit log, so `flow`, authentication method, connection IDs, and remote addresses are intentionally omitted. For `journal-reserve`, `outcome` is omitted because the batch can contain mixed outcomes.

Reasons:

* `rate-limit`: the per-source or service-wide token bucket had no detail token available.
* `journal-reserve`: the configured minimum free filesystem space would have been crossed by a suppressible write.

The first suppression in a rate-limited episode is written immediately with `count: 1`. Further suppressions are counted in memory and written at a bounded cadence or during orderly shutdown. If the reserve is reached while a `rate-limit` aggregate is pending, that aggregate retains its `rate-limit` reason and outcome and is written once using the emergency reserve; only later evaluations are counted as `journal-reserve`. A hard crash can lose only the not-yet-flushed count; the first signed event still proves that detail suppression began. While the journal reserve is active, Bifröst does not repeatedly consume the reserve for markers and periodically probes for recovery only when further unauthenticated evaluations arrive.

During orderly shutdown, pending aggregate counts are final audit records and bypass `minimumFreeBytes`. These bounded emergency writes can consume the configured reserve. If any final aggregate cannot be recorded, shutdown still attempts every other audit log and resource cleanup but returns an error instead of reporting a complete audit flush.

#### `authentication.completed`

Written when an authorization accepted by a flow either completes successfully or is denied because its session is incompatible with the selected environment. For public keys, `success` is written only after the SSH signature has been verified.

This event is not a summary of every failed authentication attempt. It is omitted when no flow accepts the request, public-key possession cannot be proven, or an error prevents Bifröst from reaching one of the final results described above. Evaluated flows are still represented by their `authentication.flow.evaluated` events where applicable.

Fields: `domain` is `authentication`; `outcome`, `flow`, `connectionId`, `authenticationMethod`, and `authorizationKind` identify the final result. `sessionId` is present when the authorization has a session.

Outcomes and reasons:

* `success`: authentication completed successfully; `reason` is omitted.
* `denied`: the credentials were accepted by the flow, but its session was incompatible with the selected environment; `reason` is `session-incompatible`.

### Sessions

#### `session.pty.decided`

Written before Bifröst answers a PTY allocation request.

Fields: `domain` is `session`; `outcome`, `flow`, `connectionId`, `sessionId`, and `authorizationKind` identify the decision. `reason` and `errorCategory` are present when applicable.

Outcomes and reasons:

* `success`: both authorized-key and environment policies permit the request.
* `denied` with `authorized-key-policy`: the active authorized-key policy forbids PTY allocation.
* `denied` with `environment-policy`: the environment does not support or permit the requested PTY.
* `denied` with `invalid-request`: session recording cannot represent the requested terminal type or dimensions.
* `failure` with `environment-policy`: evaluation of the environment policy failed; `errorCategory` classifies the failure.

The event does not contain the terminal type, terminal dimensions, or terminal modes.

#### `session.agent-forwarding.decided`

Written before Bifröst answers an SSH agent-forwarding request.

Fields: `domain` is `session`; `outcome`, `flow`, `connectionId`, `sessionId`, and `authorizationKind` identify the decision.

Outcomes and reasons:

* `success`: the active authorization permits agent forwarding.
* `denied` with `authorized-key-policy`: the active authorized-key policy forbids agent forwarding.

The event does not contain agent messages, keys, or socket paths.

#### `session.recording.started`

Written after the initial recording content and recovery head are durable, but before Bifröst writes the recording notice, environment banner, or target output. SFTP and direct forwarding never produce recording lifecycle events. If this audit event reports an error, target execution does not start, Bifröst finalizes the recording as failed, and best-effort writes `session.recording.failed` with reason `audit-write`. Because an audit backend can report an error after committing a record, both events can be present.

Fields: `domain` is `session`; `flow`, `connectionId`, `sessionId`, `operationId`, `recordingId`, and `sessionTask` correlate the recording with its shell or exec task. `pty` records whether the session has a PTY. `outcome` is omitted.

#### `session.recording.completed`

Written only after a completed recording has been sealed, synchronized, verified, and atomically published. The correlation fields match `session.recording.started`. `outcome` is `success`; `durationMillis`, `exitCode`, and `recordingDigest` describe the immutable result. A signed local outbox binds the event to both the canonical Cast digest in `recordingDigest` and the outer artifact digest in a non-replayable prepared state before publication. Atomic publication and verification promote the event to pending; only pending events are replayed at startup. A failure to write this event does not alter the already published completed artifact, but the SSH operation still fails closed.

#### `session.recording.incomplete`

Written only after an incomplete recording has been sealed, synchronized, verified, and atomically published. The correlation fields are the same as for `session.recording.started`; `durationMillis` and `recordingDigest` describe the immutable result.

Outcomes and reasons:

* `canceled` with `context-canceled`: the SSH task context was canceled.
* `canceled` with `deadline-exceeded`: the SSH task deadline expired.
* `failure` with `invalid-exit-code`: execution returned no valid exit code.
* `failure` with `session-error`: another task error prevented normal completion; `errorCategory` classifies it.
* `failure` with `startup-recovery`: startup recovered an active recording that had not completed sealing before the previous process stopped.

If the Bifröst process terminates with an unsealed active recording, startup recovery seals and publishes that artifact as incomplete. Correlation data persisted in the signed lifecycle intent allows recovery to finalize this event without decrypting BECast content. If sealing had already made a terminal event and receipt durable, recovery preserves that event instead of replacing it. A prepared event is not replayable until recovery has published and verified its artifact. Pending terminal events are replayed at least once during startup: a crash or ambiguous error after the audit journal commits but before outbox completion can produce an identical duplicate, but cannot silently lose the transition.

#### `session.recording.failed`

Written when recording creation, capture, checkpointing, final publication, or the required start audit write fails. The correlation fields are the same as for `session.recording.started`. `outcome` is `failure`; `reason` is `recording-create`, `recording-capture`, `recording-seal`, or `audit-write`, and `errorCategory` classifies the error. `recordingDigest` is present only when a failed artifact was nevertheless sealed and published successfully. A create failure has no preceding `session.recording.started` event.

#### `session.recording.delivery.failed`

Written after the first failed remote-delivery attempt for one Recording and target. `domain` is `session`; `outcome` is `failure`; `recordingId`, `target`, and `operationId` identify the delivery episode; and `errorCategory` classifies the failure. Flow, Connection, Session, file-name, path, endpoint, and digest fields are intentionally omitted because they cannot all be reconstructed safely after restart and are not required to identify the retained artifact.

The failure intent and operation ID are stored in the signed delivery receipt before the event is attempted. Further publication attempts are blocked until the event has been recorded and its durable receipt marker has been written. Later failures in the same delivery episode do not produce more events, including after restart.

#### `session.recording.delivery.succeeded`

Written after a target has accepted the exact artifact and its signed local acknowledgement is durable. `domain` is `session`; `outcome` is `success`; and `recordingId`, `target`, and `operationId` match the delivery episode and its optional `session.recording.delivery.failed` event. A direct success has no preceding failure event.

The signed receipt retains an outbox marker until this event is recorded. Startup resumes a pending success event without publishing the artifact again. Flush and retention eligibility require the durable success-audit marker in addition to the target acknowledgement. A crash after an audit record commits but before its receipt marker commits can produce an at-least-once duplicate after restart; it cannot silently discard the pending transition.

#### `session.task.started`

Written immediately before Bifröst begins service execution of a shell, exec, or SFTP task. If this event cannot be recorded, the task does not start.

Fields: `domain` is `session`; `flow`, `connectionId`, `sessionId`, `authorizationKind`, `operationId`, and `sessionTask` identify the task. `pty`, `agentForwarding`, and `forcedCommand` describe Boolean task properties. `outcome` is omitted.

The event records the requested task category. Applying an authorized-key forced command does not expose that command or change `sessionTask`; only `forcedCommand: true` indicates that the policy was applied.

#### `session.task.completed`

Written when a previously started shell, exec, or SFTP task finishes. Its `operationId`, `flow`, `connectionId`, `sessionId`, `authorizationKind`, and `sessionTask` match the corresponding `session.task.started` event.

Fields: `domain` is `session`; `outcome` and `durationMillis` describe completion. `exitCode`, `reason`, and `errorCategory` are present when applicable.

Outcomes and reasons:

* `success`: execution completed and `exitCode` contains the process result. A non-zero exit code is still a successfully completed task.
* `canceled` with `context-canceled`: the task context was canceled.
* `canceled` with `deadline-exceeded`: the task deadline expired.
* `failure` with `invalid-exit-code`: execution returned neither an error nor a valid exit code.
* `failure`: task execution failed; `errorCategory` classifies the failure.

### Port forwarding

#### `port-forwarding.direct.decided`

Written when direct-forwarding request processing reaches a policy decision or rejects an invalid request. A successful decision follows request parsing and both policy checks; malformed requests and earlier policy denials are recorded at the point where processing stops. The event is always recorded before Bifröst attempts to open the destination connection.

Fields: `domain` is `port-forwarding`; `outcome`, `flow`, `connectionId`, `sessionId`, `authorizationKind`, and `operationId` identify the decision. `reason` and `errorCategory` are present when applicable.

Outcomes and reasons:

* `success`: policy permits the request; this does not mean that the destination or SSH channel was opened successfully.
* `denied` with `authorized-key-policy`: the active authorized-key policy forbids the destination.
* `denied` with `environment-policy`: the environment policy forbids forwarding.
* `failure` with `invalid-request`: the SSH request payload or destination was invalid.
* `failure` with `environment`: the target environment could not be prepared.
* `failure` with `environment-policy`: evaluation of the environment policy failed.

#### `port-forwarding.direct.open-failed`

Written after a successful `port-forwarding.direct.decided` event when Bifröst cannot establish the destination connection or accept the SSH channel. No `port-forwarding.direct.started` or `port-forwarding.direct.completed` event follows for that operation.

Fields: `domain` is `port-forwarding`; `outcome`, `flow`, `connectionId`, `sessionId`, `authorizationKind`, and `operationId` correlate the failed open with its decision. `reason` identifies the result. `errorCategory` is present for failed open attempts, but omitted when the environment explicitly denies the destination.

Outcomes and reasons:

* `denied` with `destination-rejected`: the environment explicitly rejected the destination connection.
* `failure` with `destination-connect`: opening the destination connection failed.
* `failure` with `channel-accept`: accepting the SSH channel failed.

#### `port-forwarding.direct.started`

Written after both the destination connection and SSH channel have been established, immediately before Bifröst starts bidirectional streaming. If this event cannot be recorded, streaming does not start.

Fields: `domain` is `port-forwarding`; `flow`, `connectionId`, `sessionId`, `authorizationKind`, and `operationId` correlate the start with the preceding decision. `outcome` is omitted.

#### `port-forwarding.direct.completed`

Written when a previously started direct-forwarding stream ends.

Fields: `domain` is `port-forwarding`; `outcome`, `flow`, `connectionId`, `sessionId`, `authorizationKind`, and `operationId` correlate completion with the decision and start events. `bytesRead` counts source-to-destination bytes, `bytesWritten` counts destination-to-source bytes, and `durationMillis` measures the streaming duration. `reason` and `errorCategory` are present when applicable.

Outcomes and reasons:

* `success`: bidirectional streaming ended without an error.
* `canceled` with `context-canceled`: the forwarding context was canceled.
* `canceled` with `deadline-exceeded`: the forwarding deadline expired.
* `failure`: streaming failed; `errorCategory` classifies the failure.

#### `port-forwarding.reverse.decided`

Written after Bifröst evaluates a reverse-forwarding request.

Fields: `domain` is `port-forwarding`; `outcome`, `flow`, `connectionId`, `sessionId`, `authorizationKind`, and `operationId` identify the decision. `reason` and `errorCategory` are present when applicable.

Outcomes and reasons:

* `success`: policy permits the request.
* `denied` with `authorized-key-policy`: the active authorized-key policy forbids the bind address.
* `denied` with `invalid-bind`: the requested bind address or port is invalid.
* `denied` with `environment-policy`: the environment policy forbids reverse forwarding.
* `failure` with `environment`: the target environment could not be prepared.
* `failure` with `environment-policy`: evaluation of the environment policy failed.

Reverse listener creation and individual reverse-forwarded streams are managed by the SSH server library after the policy callback. Consequently, this event records only the policy decision and does not claim that a listener was successfully created.

### Connections

#### `connection.closed`

Written when an authenticated SSH connection ends. A pre-authentication connection cannot be assigned to one flow audit log and therefore produces no `connection.closed` event.

Fields: `domain` is `connection`; `flow`, `connectionId`, `sessionId`, and `authorizationKind` identify the connection. `reason` is `disconnected`. On the wrapped SSH transport, `bytesRead` counts bytes from the SSH client to Bifröst and `bytesWritten` counts bytes from Bifröst to the SSH client. `durationMillis` measures the complete connection lifetime. `outcome` is omitted because the available disconnect callback does not provide a reliable success or failure result.

### Housekeeping

Housekeeping events are not associated with an active SSH connection. They therefore contain no `connectionId` or `authorizationKind`.

#### `housekeeping.session.dispose.started`

Written before housekeeping disposes the session state, environment, and authorization resources of an expired session. If this event cannot be recorded, disposal is not attempted.

Fields: `domain` is `housekeeping`; `flow`, `sessionId`, and `operationId` identify the disposal attempt. `reason` is `expired` for the initial expiry path when the session is not yet selected for deletion. `reason` is `retention-elapsed` when housekeeping has selected the deletion path, either because the retention threshold elapsed or because the session was already marked as disposed. `outcome` is omitted.

#### `housekeeping.session.dispose.completed`

Written after the disposal attempt returns. Its `flow`, `sessionId`, `operationId`, and `reason` match the corresponding `housekeeping.session.dispose.started` event.

Fields: `domain` is `housekeeping`; `durationMillis` measures the complete disposal attempt. `outcome` is `success` when all disposal operations completed, even if no remaining resource required a change. This can include removing a persisted authorization token that its configured authorizer safely classified as permanently unusable because of malformed local token data, removed local configuration, or a removed local user. On `failure`, `errorCategory` classifies the error. Transient, network, system, and unclassified restore failures are not converted into token removal.

#### `housekeeping.session.delete.started`

Written before housekeeping deletes an expired or already disposed session from persistent session storage. If this event cannot be recorded, deletion is not attempted.

Fields: `domain` is `housekeeping`; `flow`, `sessionId`, and `operationId` identify the deletion attempt. `reason` is `retention-elapsed`, which identifies the deletion path but does not by itself prove that the full configured retention duration elapsed: an already disposed session also enters this path. `outcome` is omitted.

#### `housekeeping.session.delete.completed`

Written after the persistent session deletion returns. Its `flow`, `sessionId`, `operationId`, and `reason` match the corresponding `housekeeping.session.delete.started` event.

Fields: `domain` is `housekeeping`; `durationMillis` measures the deletion attempt. `outcome` is `success` only when deletion completed without an error. On `failure`, `errorCategory` classifies the error.

#### `housekeeping.recording.delete.started`

Written before housekeeping deletes a sealed session Recording whose configured retention period has elapsed. If this event cannot be recorded, deletion is not attempted.

Fields: `domain` is `housekeeping`; `recordingId` and `operationId` identify the logical deletion operation. The operation ID is stable across crash recovery, so this event may be repeated before the durable completion marker exists. `reason` is `retention-elapsed`. `outcome` is omitted. The event contains no Recording file name, path, digest, or content.

#### `housekeeping.recording.delete.completed`

Written after the Recording artifact has been removed and its signed delivery receipt has entered a durable completion-pending state. The receipt is removed only after this event succeeds. If the recorder reports an ambiguous failure, or final receipt cleanup fails while the completion marker remains, housekeeping retries the same completion event without repeating the destructive action. Its `recordingId`, `operationId`, and `reason` match the corresponding `housekeeping.recording.delete.started` event.

Fields: `domain` is `housekeeping`; `durationMillis` is `0` so the durably reconstructable event remains identical across retries. `outcome` is `success` when the artifact was removed and the receipt reached completion-pending state. On `failure`, `durationMillis` measures the failed deletion attempt, `errorCategory` classifies the error, and housekeeping preserves the receipt for retry.

#### `housekeeping.orphaned-session.cleanup.skipped` {: #housekeeping-orphaned-session-cleanup-skipped }

Written when housekeeping encounters a persisted session whose flow is no longer present in the running configuration. The implementations needed to interpret and safely dispose its environment and authorization tokens are unavailable. Housekeeping therefore preserves the complete session, including expired or already disposed sessions beyond their retention period, for operator recovery. It does not read or modify either token, dispose the session or environment, or delete session storage.

The original flow-to-audit-log assignment cannot be reconstructed safely, so the same event is written deterministically to every enabled audit log instead of being attributed to one replacement log. If no audit log is enabled, the safe skip is logged but no audit event can be written.

Fields: `domain` is `housekeeping`; `flow` is the persisted, now-unknown flow name and does not assert ownership by any receiving audit log. `sessionId` identifies the preserved session, `reason` is `missing-flow`, and `outcome` is `denied` because destructive cleanup was not allowed. No `operationId`, token contents, environment details, or retention timestamps are included.

## Privacy

Bifröst's built-in audit events never contain:

* Passwords, keyboard-interactive answers, access or persisted authorization tokens, private keys, or public-key material.
* Commands, arguments, original or forced command text, or environment values.
* SFTP paths, file names, protocol payloads, or file contents.
* Terminal types, dimensions, or modes.
* Agent messages, keys, or socket paths.
* Raw errors, wrapped causes, or formatted error messages.
* Direct-forwarding destinations, reverse bind addresses, or client-claimed origin addresses.

Error events use only the documented reason codes and broad `errorCategory` values. With `.beaudit`, Bifröst encrypts the confidential event fields at rest; event name, domain, outcome, timestamp, and verification metadata remain visible and signed. With `.baudit`, confidential fields are stored unencrypted but are still omitted from the default JSONL export. Operators must protect both original containers and any sensitive exports. See the [native format contract](native-format-contract.md#public-and-confidential-audit-fields) for the exact field boundary.

## Audit-event persistence failures

With `failurePolicy: strict`, local audit-event persistence is synchronous and fail-closed. If Bifröst cannot durably record an event before an allowed SSH action, the action is denied and only the causing SSH connection is closed. Bifröst does not retry the event in the service layer or shut down the complete service. With `failurePolicy: bestEffort`, the first local failure instead disables the complete audit log, including session recording, until restart; the affected SSH operation may continue without further recording. A disabled audit log uses a no-op recorder. See [failure policy](index.md#property-failurePolicy) and [session-recording failures](recording.md#captured-data-and-privacy) for the distinct consequences.

Bucket exhaustion and an intentionally preserved journal reserve are not local persistence failures: they replace only suppressible pre-authentication details with bounded signed aggregates. They never deny a successful authentication. Under `strict`, failure to inspect free space or to durably write a selected detail, suppression marker, or aggregate remains fail-closed for the causing connection.

If persisting a completion event fails after an action has already happened, the action cannot be rolled back. Under `strict`, the handler reports the audit failure and closes the causing connection; under `bestEffort`, the audit log is disabled for the rest of the process. A failed housekeeping start-event write prevents the associated session action under `strict`. Under `bestEffort`, the failure is logged and disables that audit log, but session housekeeping can continue without its start and completion events. A failed orphaned-session skip-event write is reported if the recorder returns an error; `bestEffort` can instead absorb that error after logging and disabling its audit log. The orphaned session remains untouched, and housekeeping continues with later sessions. Housekeeping failures do not close unrelated SSH connections or stop the service.

Remote-target delivery remains asynchronous. A remote outage does not change the result of local recording or an SSH action because the sealed artifact remains in the local spool for later delivery. Delivery-transition audit failures block further work for that Recording and target but do not close unrelated SSH connections or stop independent targets.
