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

// PublicKeyRequest may be an unsigned eligibility probe. Without an explicit
// verified assertion, an accepted response is provisional: it must not allocate
// persistent sessions, change credentials or register an authenticated connection.
type PublicKeyRequest interface {
	Request
	RemotePublicKey() gossh.PublicKey
}

// VerifiedPublicKeyRequest is implemented by trusted transport adapters only.
// True means the adapter has checked a fresh signature proving possession of
// this exact key for this attempt, not merely a certificate's CA signature.
// Never obtain this flag from an unverified client payload.
type VerifiedPublicKeyRequest interface {
	PublicKeyRequest
	PublicKeyVerified() bool
}

func isPublicKeyVerified(req PublicKeyRequest) bool {
	verified, ok := req.(VerifiedPublicKeyRequest)
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
