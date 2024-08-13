package session

import (
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"golang.org/x/crypto/ssh"
)

var (
	ErrMaxConnectionsPerSessionReached = errors.Newf(errors.TypeUser, "max connections per session reached")
)

type Session interface {
	Info() (Info, error)
	AuthorizationToken() ([]byte, error)
	HasPublicKey(ssh.PublicKey) (bool, error)

	// ConnectionInterceptor creates a new instance of ConnectionInterceptor to
	// watch net.Conn of each connection related to this Session.
	//
	// It can return ErrMaxConnectionsPerSessionReached to indicate that no more
	// net.Conn are allowed for this Session.
	ConnectionInterceptor() (ConnectionInterceptor, error)

	SetAuthorizationToken([]byte) error
	AddPublicKey(key ssh.PublicKey) error
	DeletePublicKey(key ssh.PublicKey) error
	NotifyLastAccess(remote common.Remote, newState State) error
}
