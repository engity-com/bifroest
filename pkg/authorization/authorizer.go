package authorization

import (
	"io"
)

type Authorizer interface {
	AuthorizePublicKey(PublicKeyRequest) (Authorization, error)
	AuthorizePassword(PasswordRequest) (Authorization, error)
	AuthorizeInteractive(InteractiveRequest) (Authorization, error)
	AuthorizeSession(SessionRequest) (Authorization, error)
}

type CloseableAuthorizer interface {
	Authorizer
	io.Closer
}
