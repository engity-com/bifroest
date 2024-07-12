package authorization

import (
	"github.com/echocat/slf4g"
	"github.com/engity-com/yasshd/pkg/common"
	"github.com/gliderlabs/ssh"
	gssh "golang.org/x/crypto/ssh"
)

type Request interface {
	Context() ssh.Context
	Remote() common.Remote
	Logger() log.Logger
	Validate(Authorization) (bool, error)
}

type PublicKeyRequest interface {
	Request
	RemotePublicKey() gssh.PublicKey
}

type PasswordRequest interface {
	Request
	RemotePassword() string
}

type InteractiveRequest interface {
	Request
	SendInfo(string) error
}
