package session

import (
	"context"
	"errors"
	"io"

	log "github.com/echocat/slf4g"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/net"
)

var (
	ErrNoSuchSession  = errors.New("no such session")
	ErrCorruptSession = errors.New("corrupt session")
)

type Repository interface {
	Create(ctx context.Context, flow configuration.FlowName, remote net.Remote, authToken []byte) (Session, error)

	FindBy(context.Context, configuration.FlowName, Id, *FindOpts) (Session, error)
	FindByPublicKey(context.Context, ssh.PublicKey, *FindOpts) (Session, error)
	FindByAccessToken(context.Context, []byte, *FindOpts) (Session, error)
	FindAll(context.Context, Consumer, *FindOpts) error

	DeleteBy(context.Context, configuration.FlowName, Id) error
	Delete(context.Context, Session) error
}

type CloseableRepository interface {
	Repository
	io.Closer
}

type Consumer func(context.Context, Session) (canContinue bool, err error)

// FindDiagnostic identifies one persisted session entry that could not be loaded.
type FindDiagnostic struct {
	Flow configuration.FlowName
	Id   Id
	Path string
	Err  error
}

func (this FindDiagnostic) Error() string {
	return "cannot load session " + this.Flow.String() + "/" + this.Id.String() + " at " + this.Path + ": " + this.Err.Error()
}

func (this FindDiagnostic) Unwrap() error {
	return this.Err
}

// FindDiagnosticConsumer handles one non-destructive session lookup diagnostic.
type FindDiagnosticConsumer func(context.Context, FindDiagnostic) error

// AutoCleanUpAllowedFor decides whether automatic cleanup is allowed for one
// persisted session entry. A zero Id denotes content belonging to the flow but
// not to a valid session directory.
type AutoCleanUpAllowedFor func(context.Context, configuration.FlowName, Id) bool

// FindOpts adds some more hints what should happen when find methods of
// Repository are executed.
type FindOpts struct {
	// Predicates are used to filter the returned sessions.
	Predicates Predicates

	// AutoCleanUpAllowed tells the repository to clean up everything
	// automatically while executing the search. The requester will never
	// see the requested result. This is false by default because it could
	// lead to quite performance impacts or other unwanted side effects.
	//
	// Therefore: Use with caution.
	AutoCleanUpAllowed *bool

	// AutoCleanUpAllowedFor optionally restricts AutoCleanUpAllowed for one
	// session entry. It cannot enable cleanup when AutoCleanUpAllowed is false.
	AutoCleanUpAllowedFor AutoCleanUpAllowedFor

	// Logger will be used (if any log is required) instead of the standard logger.
	Logger log.Logger

	// DiagnosticConsumer receives non-destructive per-entry diagnostics while
	// iterating all sessions. Without one, the first diagnostic remains fatal.
	DiagnosticConsumer FindDiagnosticConsumer
}

func (this *FindOpts) GetPredicates() Predicates {
	if this == nil {
		return nil
	}
	return this.Predicates
}

func (this *FindOpts) WithPredicate(predicates ...Predicate) *FindOpts {
	this.Predicates = predicates
	return this
}

func (this *FindOpts) IsAutoCleanUpAllowed() bool {
	if this != nil {
		if v := this.AutoCleanUpAllowed; v != nil {
			return *v
		}
	}
	return false
}

func (this *FindOpts) IsAutoCleanUpAllowedFor(ctx context.Context, flow configuration.FlowName, id Id) bool {
	if !this.IsAutoCleanUpAllowed() {
		return false
	}
	if this != nil && this.AutoCleanUpAllowedFor != nil {
		return this.AutoCleanUpAllowedFor(ctx, flow, id)
	}
	return true
}

func (this *FindOpts) GetLogger(or func() log.Logger) log.Logger {
	if this != nil {
		if v := this.Logger; v != nil {
			return v
		}
	}
	if or != nil {
		return or()
	}
	return log.GetRootLogger()
}

// ReportDiagnostic forwards a diagnostic or returns it when no consumer exists.
func (this *FindOpts) ReportDiagnostic(ctx context.Context, diagnostic FindDiagnostic) error {
	if this != nil && this.DiagnosticConsumer != nil {
		return this.DiagnosticConsumer(ctx, diagnostic)
	}
	return diagnostic
}
