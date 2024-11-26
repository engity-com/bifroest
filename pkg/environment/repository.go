package environment

import (
	"context"
	"errors"
	"io"

	log "github.com/echocat/slf4g"
	glssh "github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
)

var (
	ErrNoSuchEnvironment = errors.New("no such environment")
	ErrNotAcceptable     = errors.New("not acceptable")
)

type Repository interface {
	// WillBeAccepted returns true if it is possible to get an Environment for the
	// provided Request.
	WillBeAccepted(Context) (bool, error)

	// DoesSupportPty will return true if the resulting Environment will support
	// an PTY.
	DoesSupportPty(Context, glssh.Pty) (bool, error)

	// Ensure will create or return an environment that matches the given Request.
	// If it is not acceptable to do this action with the provided Request
	// ErrNotAcceptable is returned; you can call WillBeAccepted to prevent such
	// errors.
	Ensure(Request) (Environment, error)

	// FindBySession will find an existing environment for a given session.Session.
	// If there is no matching one ErrNoSuchEnvironment will be returned.
	FindBySession(context.Context, session.Session, *FindOpts) (Environment, error)

	// Cleanup can be called while housekeeping iteration. It will also forward
	// all otherFlows that are configured within Bifröst. This gives the Repository
	// to potentially cleanup orphan resources that where initially owned by another
	// flow.
	Cleanup(context.Context, *CleanupOpts) error
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

// CleanupOpts adds some more hints what should happen when Repository.Cleanup
// is executed.
type CleanupOpts struct {
	// FlowOfNamePredicate returns true if in the context of Bifröst
	// there exists another flow with this name.
	FlowOfNamePredicate func(configuration.FlowName) (bool, error)

	// SessionExists returns true if the given session (by its [session.Id]) does
	// exist within the whole Bifröst context.
	SessionExists func(context.Context, configuration.FlowName, session.Id) (bool, error)

	// Logger will be used (if any log is required) instead of the standard logger.
	Logger log.Logger
}

func (this *CleanupOpts) HasFlowOfName(name configuration.FlowName) (bool, error) {
	if this != nil {
		if v := this.FlowOfNamePredicate; v != nil {
			return v(name)
		}
	}
	return false, nil
}

// HasSession calls SessionExists and returns its values. If SessionExists or in case
// of errors the actual result will be nil.
func (this *CleanupOpts) HasSession(ctx context.Context, flow configuration.FlowName, id session.Id) (*bool, error) {
	if this != nil {
		if v := this.SessionExists; v != nil {
			result, err := v(ctx, flow, id)
			if err != nil {
				return nil, err
			}
			return &result, nil
		}
	}
	return nil, nil
}

func (this *CleanupOpts) GetLogger(or func() log.Logger) log.Logger {
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
