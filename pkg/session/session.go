package session

import (
	"github.com/engity-com/bifroest/pkg/common"
	"golang.org/x/crypto/ssh"
)

type Session interface {
	Info() (Info, error)
	AuthorizationToken() ([]byte, error)
	HasPublicKey(ssh.PublicKey) (bool, error)
	IteratePublicKey(func(ssh.PublicKey) (canContinue bool, err error)) error

	SetAuthorizationToken([]byte) error
	AddPublicKey(key ssh.PublicKey) error
	DeletePublicKey(key ssh.PublicKey) error
	NotifyLastAccess(remote common.Remote, newState State) error
}
