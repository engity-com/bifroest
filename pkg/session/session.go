package session

import (
	"context"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
)

const (
	EnvName = "BIFROEST_SESSION_ID"
)

var (
	ErrMaxConnectionsPerSessionReached = errors.Newf(errors.User, "max connections per session reached")
)

type Session interface {
	Flow() configuration.FlowName
	Id() Id
	Info(context.Context) (Info, error)
	AuthorizationToken(context.Context) ([]byte, error)
	EnvironmentToken(context.Context) ([]byte, error)
	HasPublicKey(context.Context, ssh.PublicKey) (bool, error)

	// ConnectionInterceptor creates a new instance of ConnectionInterceptor to
	// watch net.Conn of each connection related to this Session.
	//
	// It can return ErrMaxConnectionsPerSessionReached to indicate that no more
	// net.Conn are allowed for this Session.
	ConnectionInterceptor(context.Context) (ConnectionInterceptor, error)

	SetAuthorizationToken(context.Context, []byte) error
	SetEnvironmentToken(context.Context, []byte) error
	AddPublicKey(context.Context, ssh.PublicKey) error
	DeletePublicKey(context.Context, ssh.PublicKey) error
	NotifyLastAccess(ctx context.Context, remote net.Remote, newState State) (oldState State, err error)
	Dispose(ctx context.Context) (bool, error)

	String() string
}
