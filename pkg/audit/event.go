package audit

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
	Name                 string               `json:"name"`
	Domain               EventDomain          `json:"domain,omitempty"`
	Outcome              EventOutcome         `json:"outcome,omitempty"`
	Flow                 string               `json:"flow,omitempty"`
	ConnectionId         string               `json:"connectionId,omitempty"`
	SessionId            string               `json:"sessionId,omitempty"`
	OperationId          string               `json:"operationId,omitempty"`
	AuthenticationMethod AuthenticationMethod `json:"authenticationMethod,omitempty"`
	AuthenticationPhase  AuthenticationPhase  `json:"authenticationPhase,omitempty"`
	AuthorizationKind    string               `json:"authorizationKind,omitempty"`
	SessionTask          SessionTask          `json:"sessionTask,omitempty"`
	Reason               string               `json:"reason,omitempty"`
	ErrorCategory        ErrorCategory        `json:"errorCategory,omitempty"`
	ExitCode             *int                 `json:"exitCode,omitempty"`
	BytesRead            *int64               `json:"bytesRead,omitempty"`
	BytesWritten         *int64               `json:"bytesWritten,omitempty"`
	DurationMillis       *int64               `json:"durationMillis,omitempty"`
	Count                *uint64              `json:"count,omitempty"`
	Pty                  *bool                `json:"pty,omitempty"`
	AgentForwarding      *bool                `json:"agentForwarding,omitempty"`
	ForcedCommand        *bool                `json:"forcedCommand,omitempty"`
}
