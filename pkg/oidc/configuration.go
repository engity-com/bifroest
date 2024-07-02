package oidc

type Configuration interface {
	GetOidcIssuer() string
	GetOidcClientId() string
	GetOidcClientSecret() string
	GetOidcScopes() []string
}
