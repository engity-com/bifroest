package session

import (
	"context"
	"errors"
	"io"

	log "github.com/echocat/slf4g"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/net"
)

var (
	ErrNoSuchSession = errors.New("no such session")
)

type Repository interface {
	Create(ctx context.Context, flow configuration.FlowName, remote net.Remote, authToken []byte) (Session, error)

	FindBy(context.Context, configuration.FlowName, uuid.UUID, *FindOpts) (Session, error)
	FindByPublicKey(context.Context, ssh.PublicKey, *FindOpts) (Session, error)
	FindByAccessToken(context.Context, []byte, *FindOpts) (Session, error)
	FindAll(context.Context, Consumer, *FindOpts) error

	DeleteBy(context.Context, configuration.FlowName, uuid.UUID) error
	Delete(context.Context, Session) error
}

type CloseableRepository interface {
	Repository
	io.Closer
}

type Consumer func(context.Context, Session) (canContinue bool, err error)

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

	// Logger will be used (if any log is required) instead of the standard logger.
	Logger log.Logger
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
