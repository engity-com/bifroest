package audit

import "github.com/engity-com/bifroest/pkg/configuration"

type EventName = string

const (
	EventNameAuthenticationFlowEvaluated               = "authentication.flow.evaluated"
	EventNameAuthenticationFlowEvaluationsSuppressed   = "authentication.flow.evaluations-suppressed"
	EventNameAuthenticationCompleted                   = "authentication.completed"
	EventNameSessionPtyDecided                         = "session.pty.decided"
	EventNameSessionAgentForwardingDecided             = "session.agent-forwarding.decided"
	EventNameSessionRecordingStarted                   = "session.recording.started"
	EventNameSessionRecordingCompleted                 = "session.recording.completed"
	EventNameSessionRecordingIncomplete                = "session.recording.incomplete"
	EventNameSessionRecordingFailed                    = "session.recording.failed"
	EventNameSessionRecordingDeliveryFailed            = "session.recording.delivery.failed"
	EventNameSessionRecordingDeliverySucceeded         = "session.recording.delivery.succeeded"
	EventNameSessionTaskStarted                        = "session.task.started"
	EventNameSessionTaskCompleted                      = "session.task.completed"
	EventNamePortForwardingDirectDecided               = "port-forwarding.direct.decided"
	EventNamePortForwardingDirectOpenFailed            = "port-forwarding.direct.open-failed"
	EventNamePortForwardingDirectStarted               = "port-forwarding.direct.started"
	EventNamePortForwardingDirectCompleted             = "port-forwarding.direct.completed"
	EventNamePortForwardingReverseDecided              = "port-forwarding.reverse.decided"
	EventNameConnectionClosed                          = "connection.closed"
	EventNameHousekeepingSessionDisposeStarted         = "housekeeping.session.dispose.started"
	EventNameHousekeepingSessionDisposeCompleted       = "housekeeping.session.dispose.completed"
	EventNameHousekeepingSessionDeleteStarted          = "housekeeping.session.delete.started"
	EventNameHousekeepingSessionDeleteCompleted        = "housekeeping.session.delete.completed"
	EventNameHousekeepingRecordingDeleteStarted        = "housekeeping.recording.delete.started"
	EventNameHousekeepingRecordingDeleteCompleted      = "housekeeping.recording.delete.completed"
	EventNameHousekeepingOrphanedSessionCleanupSkipped = "housekeeping.orphaned-session.cleanup.skipped"
)

var knownEventNames = [...]EventName{
	EventNameAuthenticationFlowEvaluated,
	EventNameAuthenticationFlowEvaluationsSuppressed,
	EventNameAuthenticationCompleted,
	EventNameSessionPtyDecided,
	EventNameSessionAgentForwardingDecided,
	EventNameSessionRecordingStarted,
	EventNameSessionRecordingCompleted,
	EventNameSessionRecordingIncomplete,
	EventNameSessionRecordingFailed,
	EventNameSessionRecordingDeliveryFailed,
	EventNameSessionRecordingDeliverySucceeded,
	EventNameSessionTaskStarted,
	EventNameSessionTaskCompleted,
	EventNamePortForwardingDirectDecided,
	EventNamePortForwardingDirectOpenFailed,
	EventNamePortForwardingDirectStarted,
	EventNamePortForwardingDirectCompleted,
	EventNamePortForwardingReverseDecided,
	EventNameConnectionClosed,
	EventNameHousekeepingSessionDisposeStarted,
	EventNameHousekeepingSessionDisposeCompleted,
	EventNameHousekeepingSessionDeleteStarted,
	EventNameHousekeepingSessionDeleteCompleted,
	EventNameHousekeepingRecordingDeleteStarted,
	EventNameHousekeepingRecordingDeleteCompleted,
	EventNameHousekeepingOrphanedSessionCleanupSkipped,
}

type EventReason = string

const (
	EventReasonRateLimit           = "rate-limit"
	EventReasonJournalReserve      = "journal-reserve"
	EventReasonSessionIncompatible = "session-incompatible"
	EventReasonAuthorizedKeyPolicy = "authorized-key-policy"
	EventReasonEnvironmentPolicy   = "environment-policy"
	EventReasonContextCanceled     = "context-canceled"
	EventReasonDeadlineExceeded    = "deadline-exceeded"
	EventReasonInvalidExitCode     = "invalid-exit-code"
	EventReasonInvalidRequest      = "invalid-request"
	EventReasonEnvironment         = "environment"
	EventReasonDestinationConnect  = "destination-connect"
	EventReasonDestinationRejected = "destination-rejected"
	EventReasonChannelAccept       = "channel-accept"
	EventReasonInvalidBind         = "invalid-bind"
	EventReasonDisconnected        = "disconnected"
	EventReasonMissingFlow         = "missing-flow"
	EventReasonRetentionElapsed    = "retention-elapsed"
	EventReasonExpired             = "expired"
	EventReasonRecordingCreate     = "recording-create"
	EventReasonRecordingCapture    = "recording-capture"
	EventReasonRecordingSeal       = "recording-seal"
	EventReasonAuditWrite          = "audit-write"
	EventReasonSessionError        = "session-error"
)

var knownEventReasons = [...]EventReason{
	EventReasonRateLimit,
	EventReasonJournalReserve,
	EventReasonSessionIncompatible,
	EventReasonAuthorizedKeyPolicy,
	EventReasonEnvironmentPolicy,
	EventReasonContextCanceled,
	EventReasonDeadlineExceeded,
	EventReasonInvalidExitCode,
	EventReasonInvalidRequest,
	EventReasonEnvironment,
	EventReasonDestinationConnect,
	EventReasonDestinationRejected,
	EventReasonChannelAccept,
	EventReasonInvalidBind,
	EventReasonDisconnected,
	EventReasonMissingFlow,
	EventReasonRetentionElapsed,
	EventReasonExpired,
	EventReasonRecordingCreate,
	EventReasonRecordingCapture,
	EventReasonRecordingSeal,
	EventReasonAuditWrite,
	EventReasonSessionError,
}

type EventDomain string

const (
	EventDomainAuthentication EventDomain = "authentication"
	EventDomainConnection     EventDomain = "connection"
	EventDomainHousekeeping   EventDomain = "housekeeping"
	EventDomainPortForwarding EventDomain = "port-forwarding"
	EventDomainSession        EventDomain = "session"
)

type EventOutcome string

const (
	EventOutcomeSuccess  EventOutcome = "success"
	EventOutcomeDenied   EventOutcome = "denied"
	EventOutcomeFailure  EventOutcome = "failure"
	EventOutcomeCanceled EventOutcome = "canceled"
)

type AuthenticationMethod string

const (
	AuthenticationMethodPublicKey           AuthenticationMethod = "public-key"
	AuthenticationMethodPassword            AuthenticationMethod = "password"
	AuthenticationMethodKeyboardInteractive AuthenticationMethod = "keyboard-interactive"
)

type AuthenticationPhase string

const (
	AuthenticationPhaseCandidate AuthenticationPhase = "candidate"
	AuthenticationPhaseVerified  AuthenticationPhase = "verified"
)

type SessionTask string

const (
	SessionTaskShell SessionTask = "shell"
	SessionTaskExec  SessionTask = "exec"
	SessionTaskSftp  SessionTask = "sftp"
)

type ErrorCategory string

const (
	ErrorCategoryUnknown    ErrorCategory = "unknown"
	ErrorCategorySystem     ErrorCategory = "system"
	ErrorCategoryConfig     ErrorCategory = "config"
	ErrorCategoryNetwork    ErrorCategory = "network"
	ErrorCategoryUser       ErrorCategory = "user"
	ErrorCategoryPermission ErrorCategory = "permission"
	ErrorCategoryExpired    ErrorCategory = "expired"
)

// Event is the domain payload accepted by a Recorder. The recorder adds common
// metadata and the journal adds its persistence envelope.
type Event struct {
	Name                 EventName                        `json:"name"`
	Domain               EventDomain                      `json:"domain,omitempty"`
	Outcome              EventOutcome                     `json:"outcome,omitempty"`
	Flow                 string                           `json:"flow,omitempty"`
	ConnectionId         string                           `json:"connectionId,omitempty"`
	SessionId            string                           `json:"sessionId,omitempty"`
	OperationId          string                           `json:"operationId,omitempty"`
	RecordingId          string                           `json:"recordingId,omitempty"`
	RecordingDigest      string                           `json:"recordingDigest,omitempty"`
	Target               configuration.AuditlogTargetName `json:"target,omitempty"`
	AuthenticationMethod AuthenticationMethod             `json:"authenticationMethod,omitempty"`
	AuthenticationPhase  AuthenticationPhase              `json:"authenticationPhase,omitempty"`
	AuthorizationKind    string                           `json:"authorizationKind,omitempty"`
	SessionTask          SessionTask                      `json:"sessionTask,omitempty"`
	Reason               EventReason                      `json:"reason,omitempty"`
	ErrorCategory        ErrorCategory                    `json:"errorCategory,omitempty"`
	ExitCode             *int                             `json:"exitCode,omitempty"`
	BytesRead            *int64                           `json:"bytesRead,omitempty"`
	BytesWritten         *int64                           `json:"bytesWritten,omitempty"`
	DurationMillis       *int64                           `json:"durationMillis,omitempty"`
	Count                *uint64                          `json:"count,omitempty"`
	Pty                  *bool                            `json:"pty,omitempty"`
	AgentForwarding      *bool                            `json:"agentForwarding,omitempty"`
	ForcedCommand        *bool                            `json:"forcedCommand,omitempty"`
}
