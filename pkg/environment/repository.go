package environment

import (
	"context"
	"errors"
	"io"

	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/session"
)

var (
	ErrNoSuchEnvironment = errors.New("no such environment")
	ErrNotAcceptable     = errors.New("not acceptable")
)

type Repository interface {
	// WillBeAccepted returns true if it is possible to get an Environment for the
	// provided Request.
	WillBeAccepted(Request) (bool, error)

	// Ensure will create or return an environment that matches the given Request.
	// If it is not acceptable to do this action with the provided Request
	// ErrNotAcceptable is returned; you can call WillBeAccepted to prevent such
	// errors.
	Ensure(Request) (Environment, error)

	// FindBySession will find an existing environment for a given session.Session.
	// If there is no matching one ErrNoSuchEnvironment will be returned.
	FindBySession(context.Context, session.Session, *FindOpts) (Environment, error)
}

type CloseableRepository interface {
	Repository
	io.Closer
}

// FindOpts adds some more hints what should happen when find methods of
// Repository are executed.
type FindOpts struct {
	// AutoCleanUpAllowed tells the repository to clean up everything
	// automatically while executing the search. The requester will never
	// see the requested result. This is false by default because it could
	// lead to quite performance impacts or other unwanted side effects.
	//
	// Therefore: Use with caution.
	AutoCleanUpAllowed *bool

	// Logger will be used (if any log is required) instead of the standard logger.
	Logger log.Logger
}

func (this *FindOpts) IsAutoCleanUpAllowed() bool {
	if this != nil {
		if v := this.AutoCleanUpAllowed; v != nil {
			return *v
		}
	}
	return false
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
