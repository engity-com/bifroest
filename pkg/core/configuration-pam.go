package core

import (
	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/engity/pam-oidc/pkg/common"
)

type ConfigurationPam struct {
	AllowedUserName   common.Regexp `yaml:"allowedUserName,omitempty"`
	ForbiddenUserName common.Regexp `yaml:"forbiddenUserName,omitempty"`
}

func NewConfigurationPam() (*ConfigurationOidc, error) {
	return &ConfigurationOidc{
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}, nil
}

func (this ConfigurationPam) Validate(common.StructuredKey) error {
	return nil
}
