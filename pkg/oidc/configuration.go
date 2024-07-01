package oidc

type Configuration interface {
	GetIssuer() string
	GetClientId() string
	GetClientSecret() string
	GetScopes() []string
}
