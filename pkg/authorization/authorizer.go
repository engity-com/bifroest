package authorization

import (
	"context"
	"errors"
	"fmt"
	"io"

	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/session"
)

var (
	ErrNoSuchAuthorization = errors.New("no such authorization")
	// ErrUnusableAuthorizationToken marks persisted local token data that cannot
	// become restorable without changing that token or the running configuration.
	ErrUnusableAuthorizationToken = errors.New("unusable persisted authorization token")
)

func unusableAuthorizationToken(ctx context.Context, sess session.Session, opts *RestoreOpts, cause error) error {
	if !opts.IsAutoCleanUpAllowed() {
		return fmt.Errorf("%w: %v", ErrUnusableAuthorizationToken, cause)
	}
	if err := sess.SetAuthorizationToken(ctx, nil); err != nil {
		return fmt.Errorf("cannot remove unusable persisted authorization token: %w", err)
	}
	opts.GetLogger(nil).With("session", sess).Info("removed unusable persisted authorization token")
	return ErrNoSuchAuthorization
}

type Authorizer interface {
	AuthorizePublicKey(PublicKeyRequest) (Authorization, error)
	AuthorizePassword(PasswordRequest) (Authorization, error)
	AuthorizeInteractive(InteractiveRequest) (Authorization, error)

	// RestoreFromSession tries to restore the existing authorization from the given
	// session.Session. If the given session does not contain enough information to restore
	// the Authorization ErrNoSuchAuthorization is returned.
	RestoreFromSession(context.Context, session.Session, *RestoreOpts) (Authorization, error)
}

type CloseableAuthorizer interface {
	Authorizer
	io.Closer
}

// RestoreOpts adds some more hints what should happen when find methods of
// Repository are executed.
type RestoreOpts struct {
	// AutoCleanUpAllowed tells the Authorizer to clean up everything
	// automatically while executing the search. The requester will never
	// see the requested result. This is false by default because it could
	// lead to quite performance impacts or other unwanted side effects.
	//
	// Therefore: Use with caution.
	AutoCleanUpAllowed *bool

	// Logger will be used (if any log is required) instead of the standard logger.
	Logger log.Logger
}

func (this *RestoreOpts) IsAutoCleanUpAllowed() bool {
	if this != nil {
		if v := this.AutoCleanUpAllowed; v != nil {
			return *v
		}
	}
	return false
}

func (this *RestoreOpts) GetLogger(or func() log.Logger) log.Logger {
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
