package core

import (
	"github.com/coreos/go-oidc/v3/oidc"
)

type ConfigurationOidc struct {
	Issuer       string   `yaml:"issuer,omitempty"`
	ClientId     string   `yaml:"clientId,omitempty"`
	ClientSecret string   `yaml:"clientSecret,omitempty"`
	Scopes       []string `yaml:"scopes,omitempty"`
}

func NewConfigurationOidc() (*ConfigurationOidc, error) {
	return &ConfigurationOidc{
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}, nil
}
