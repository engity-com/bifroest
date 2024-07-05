package core

import (
	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/engity/pam-oidc/pkg/common"
	"github.com/engity/pam-oidc/pkg/errors"
)

type ConfigurationOidc struct {
	Issuer       string   `yaml:"issuer,omitempty"`
	ClientId     string   `yaml:"clientId,omitempty"`
	ClientSecret string   `yaml:"clientSecret,omitempty"`
	Scopes       []string `yaml:"scopes,omitempty"`

	RetrieveIdToken  bool `yaml:"retrieveIdToken,omitempty"`
	RetrieveUserInfo bool `yaml:"retrieveUserInfo,omitempty"`
}

func NewConfigurationOidc() (*ConfigurationOidc, error) {
	return &ConfigurationOidc{
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},

		RetrieveIdToken:  true,
		RetrieveUserInfo: false,
	}, nil
}

func (this ConfigurationOidc) Validate(key common.StructuredKey) error {
	fail := func(err error) error {
		return err
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.Newf(errors.TypeConfig, msg, args...))
	}

	if this.Issuer == "" {
		return failf("required option %v", key.Child("issuer"))
	}
	if this.ClientId == "" {
		return failf("required option %v", key.Child("clientId"))
	}
	if this.ClientSecret == "" {
		return failf("required option %v", key.Child("clientSecret"))
	}
	if len(this.Scopes) == 0 {
		return failf("required option %v", key.Child("scopes"))
	}

	return nil
}
