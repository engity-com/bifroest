package authorization

import (
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/session"
)

type Request interface {
	connection.Context
	Sessions() session.Repository
	Validate(Authorization) (bool, error)
}

type PublicKeyRequest interface {
	Request
	RemotePublicKey() gossh.PublicKey
}

type verifiedPublicKeyRequest interface {
	PublicKeyVerified() bool
}

func isPublicKeyVerified(req PublicKeyRequest) bool {
	verified, ok := req.(verifiedPublicKeyRequest)
	return ok && verified.PublicKeyVerified()
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

type authorizationContextSetter interface {
	SetAuthorizationContext(Authorization)
}

func setAuthorizationContext(req Request, auth Authorization) {
	if setter, ok := req.(authorizationContextSetter); ok {
		setter.SetAuthorizationContext(auth)
	}
}
