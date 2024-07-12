package authorization

type Authorizer interface {
	AuthorizePublicKey(PublicKeyRequest) (Authorization, error)
	AuthorizePassword(PasswordRequest) (Authorization, error)
	AuthorizeInteractive(InteractiveRequest) (Authorization, error)
}
