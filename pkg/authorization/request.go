package authorization

import (
	glssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/session"
)

type Request interface {
	Sessions() session.Repository
	Connection() connection.Connection
	Context() glssh.Context
	Validate(Authorization) (bool, error)
}

type PublicKeyRequest interface {
	Request
	RemotePublicKey() gossh.PublicKey
}

type PasswordRequest interface {
	Request
	RemotePassword() string
}

type InteractiveRequest interface {
	Request
	SendInfo(string) error
	SendError(string) error
	Prompt(msg string, echoOn bool) (string, error)
}
