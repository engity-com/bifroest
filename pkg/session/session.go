package session

import (
	"golang.org/x/crypto/ssh"
	"net"
)

type Session interface {
	Info() (Info, error)
	PublicKeys(func(key ssh.PublicKey) (canContinue bool, err error)) error

	AddPublicKey(key ssh.PublicKey) error
	NotifyLastAccess(remoteUser string, remoteAddr net.IP, newState State) error
}
