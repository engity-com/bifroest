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

The table describes the **complete logical event**, not what an observer can read from its native container:

* Public event fields: `name`, optional `domain` and `outcome`. Record ID and time remain visible in the signed envelope.
* Private map: `flow`, `reason`, `target`, correlation IDs and all other event fields. It is compressed in `.baudit` and additionally encrypted in `.beaudit`.
* Default JSONL omits the private map even for `.baudit`, but still exposes identifying provenance. JSONL is **unsigned**; protect it and the original evidence.

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

* The first rate-limited suppression is signed immediately with `count: 1`. Later counts are aggregated in memory and flushed periodically or at orderly shutdown. A hard crash can lose **only unflushed counts**, not the first signed marker.
* If the journal reserve is reached while a `rate-limit` aggregate is pending, that aggregate keeps its reason and outcome and uses the emergency reserve. Only later suppressed evaluations count as `journal-reserve`. While the reserve is active, recovery is probed when new unauthenticated evaluations arrive; markers do not repeatedly consume it.
* Final aggregates during orderly shutdown bypass `minimumFreeBytes` as bounded emergency writes. If one fails, Bifröst still closes other resources but reports an incomplete audit flush.

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

Written after the first recording content and recovery head are durable, **before** notice, banner or target output. SFTP and direct forwarding do not produce recording lifecycle events.

If the audit write reports an error, target execution does not start. Bifröst finalizes the recording as failed and attempts `session.recording.failed` with reason `audit-write`. Both events can exist if the backend committed before reporting an error.

Fields: `domain` is `session`; `flow`, `connectionId`, `sessionId`, `operationId`, `recordingId`, and `sessionTask` correlate the recording with its shell or exec task. `pty` records whether the session has a PTY. `outcome` is omitted.

#### `session.recording.completed`

Written only after a completed recording is sealed, synchronized, verified and atomically published. Correlation fields match `session.recording.started`; `outcome: success`, `durationMillis`, `exitCode` and `recordingDigest` describe the immutable result.

The signed outbox binds the Cast and outer artifact digests **before** publication in a non-replayable `prepared` state. Verified publication promotes it to `pending`; only then can startup replay the event. An audit-write failure leaves the sealed artifact intact but fails the SSH operation closed.

#### `session.recording.incomplete`

Written only after an incomplete recording has been sealed, synchronized, verified, and atomically published. The correlation fields are the same as for `session.recording.started`; `durationMillis` and `recordingDigest` describe the immutable result.

Outcomes and reasons:

* `canceled` with `context-canceled`: the SSH task context was canceled.
* `canceled` with `deadline-exceeded`: the SSH task deadline expired.
* `failure` with `invalid-exit-code`: execution returned no valid exit code.
* `failure` with `session-error`: another task error prevented normal completion; `errorCategory` classifies it.
* `failure` with `startup-recovery`: startup recovered an active recording that had not completed sealing before the previous process stopped.

Startup recovery seals unfinished recordings as incomplete. The signed lifecycle intent holds correlation data needed to finish BECast **without** its private decryption key.

* Already durable terminal events and receipts are preserved, not replaced.
* `prepared` is not replayable until its artifact is published and verified.
* `pending` is replayed at least once. A crash after audit commit can duplicate the **same** event, but cannot silently lose it.

#### `session.recording.failed`

Written when recording creation, capture, checkpointing, publication or the required start audit write fails. Correlation fields match `session.recording.started`; `outcome: failure` and `errorCategory` classify the result.

* `reason`: `recording-create`, `recording-capture`, `recording-seal` or `audit-write`.
* `recordingDigest` appears only if a failed artifact was still sealed and published. A create failure has no preceding `session.recording.started` event.

#### `session.recording.delivery.failed`

Written after the first failed attempt for a Recording and target. `domain: session`, `outcome: failure`, `recordingId`, `target` and `operationId` identify the episode; `errorCategory` classifies it. Flow, connection, session, paths, endpoint and digest are omitted: they are unnecessary here and not all safely recoverable after restart.

The failure intent and operation ID are stored in the signed delivery receipt before the event is attempted. Further publication attempts are blocked until the event has been recorded and its durable receipt marker has been written. Later failures in the same delivery episode do not produce more events, including after restart.

#### `session.recording.delivery.succeeded`

Written after a target has accepted the exact artifact and its signed local acknowledgement is durable. `domain` is `session`; `outcome` is `success`; and `recordingId`, `target`, and `operationId` match the delivery episode and its optional `session.recording.delivery.failed` event. A direct success has no preceding failure event.

The signed receipt keeps the success event pending until it is recorded. Startup replays it **without republishing** the artifact. Flush and retention require both the target acknowledgement and durable success-audit marker. A crash between audit and marker commits can replay an identical event, not silently discard it.

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

Fields: `domain: connection`; `flow`, `connectionId`, `sessionId`, `authorizationKind` and `reason: disconnected` identify the connection. `durationMillis` covers its full lifetime.

* `bytesRead`: SSH client to Bifröst; `bytesWritten`: Bifröst to SSH client, measured at the wrapped SSH transport.
* No `outcome`: the disconnect callback cannot reliably distinguish success from failure.

### Housekeeping

Housekeeping events are not associated with an active SSH connection. They therefore contain no `connectionId` or `authorizationKind`.

#### `housekeeping.session.dispose.started`

Written before housekeeping disposes the session state, environment, and authorization resources of an expired session. If this event cannot be recorded, disposal is not attempted.

Fields: `domain` is `housekeeping`; `flow`, `sessionId`, and `operationId` identify the disposal attempt. `reason` is `expired` for the initial expiry path when the session is not yet selected for deletion. `reason` is `retention-elapsed` when housekeeping has selected the deletion path, either because the retention threshold elapsed or because the session was already marked as disposed. `outcome` is omitted.

#### `housekeeping.session.dispose.completed`

Written after the disposal attempt returns. Its `flow`, `sessionId`, `operationId`, and `reason` match the corresponding `housekeeping.session.dispose.started` event.

Fields: `domain: housekeeping`; `durationMillis` measures the attempt. `outcome: success` means disposal completed, even if nothing needed changing. `failure` has an `errorCategory`.

A persisted token may be removed only when its authorizer safely classifies it as **permanently unusable** (malformed local data, removed configuration or user). Transient, network, system or unclassified restore failures do **not** authorize removal.

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

Written after the artifact is removed and its signed receipt reaches durable `completion-pending`. The receipt itself is removed **only after this event succeeds**. An ambiguous audit result or failed final cleanup retries the same event, not the deletion. `recordingId`, `operationId` and `reason` match the start event.

Fields: `domain: housekeeping`. On success, `durationMillis: 0` keeps retries identical. On failure, `durationMillis` measures the failed attempt, `errorCategory` classifies it and the receipt remains for retry.

#### `housekeeping.orphaned-session.cleanup.skipped` {: #housekeeping-orphaned-session-cleanup-skipped }

If a persisted session's flow is missing, housekeeping cannot safely interpret its environment or authorization tokens. It **preserves the whole session** for operator recovery, even past retention; it neither reads tokens nor disposes or deletes that session.

* The original audit-log assignment is unknown. The identical skip event goes to **every enabled audit log**, never a guessed replacement; without enabled logs, only a normal log entry is possible.
* Fields: `domain: housekeeping`; `flow` is the unknown original flow, `sessionId` the preserved session, `reason: missing-flow`, `outcome: denied`. No operation ID, token contents, environment details or retention timestamps are emitted.

## Privacy

Bifröst's built-in audit events never contain:

* Passwords, keyboard-interactive answers, access or persisted authorization tokens, private keys, or public-key material.
* Commands, arguments, original or forced command text, or environment values.
* SFTP paths, file names, protocol payloads, or file contents.
* Terminal types, dimensions, or modes.
* Agent messages, keys, or socket paths.
* Raw errors, wrapped causes, or formatted error messages.
* Direct-forwarding destinations, reverse bind addresses, or client-claimed origin addresses.

Error events expose only documented reason codes and broad `errorCategory` values:

* `.beaudit` encrypts private event fields in segments; name, domain, outcome, time and verification metadata remain visible and signed.
* `.baudit` stores private fields in clear form, but the default JSONL export still omits them.
* The [local Recording lifecycle outbox](recording.md#storage-and-recovery) can store private event fields as **signed, unencrypted JSON** until completion.

Protect local repositories, backups, containers and exports. See the [exact container boundary](../../formats/audit.md#public-and-confidential-audit-fields).

## Audit-event persistence failures

* **`strict`:** local writes are synchronous. A failed pre-action write denies that action and closes **only its SSH connection**; the service does not retry the event or shut down.
* **`bestEffort`:** the first local failure disables the whole audit log and its recording until restart. The SSH operation may continue without further audit writes.
* **Suppression is not a write failure:** token-bucket exhaustion or the journal reserve replaces only suppressible pre-authentication details with bounded signed aggregates. Successful authentication is not denied. Under `strict`, failure to inspect free space or write a chosen detail, marker or aggregate still closes the causing connection.
* **After-action failure:** a completed action cannot be undone. `strict` reports the failure and closes its connection; `bestEffort` disables the audit log.
* **Housekeeping:** a failed start-event write prevents its session action under `strict`. Under `bestEffort`, housekeeping may proceed without start/completion events. Failed missing-flow skip audits never cause the orphaned session to be modified; housekeeping continues with later sessions. Unrelated SSH connections and the service remain running.
* **Remote delivery:** outages leave sealed artifacts in the local spool for retry. Failed delivery-transition audits pause only that Recording and target, not other connections or targets.

See [failure policy](index.md#property-failurePolicy) and [session-recording failures](recording.md#captured-data-and-privacy).
