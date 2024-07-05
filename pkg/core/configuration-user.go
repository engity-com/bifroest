package core

import (
	"github.com/engity/pam-oidc/pkg/common"
	"github.com/engity/pam-oidc/pkg/template"
	"github.com/engity/pam-oidc/pkg/user"
)

type ConfigurationUser struct {
	user.RequirementTemplate `yaml:",inline"`

	AllowedRequestingName   common.Regexp `yaml:"allowedRequestingName,omitempty"`
	ForbiddenRequestingName common.Regexp `yaml:"forbiddenRequestingName,omitempty"`

	LoginAllowed template.Bool `yaml:"loginAllowed,omitempty"`

	CreateIfAbsent    template.Bool `yaml:"createIfAbsent,omitempty"`
	UpdateIfDifferent template.Bool `yaml:"updateIfDifferent,omitempty"`
}

func NewConfigurationUser() (*ConfigurationUser, error) {
	return &ConfigurationUser{
		RequirementTemplate: user.RequirementTemplate{
			Name:        template.MustNewString("{{.Oidc.IdToken.Claims.email}}"),
			DisplayName: template.MustNewString("{{.Oidc.IdToken.Claims.name}}"),
			Group: user.GroupRequirementTemplate{
				Name: template.MustNewString("sso"),
			},
			HomeDir: template.MustNewString("/home/sso/{{.Oidc.IdToken.Claims.email}}"),
		},
		LoginAllowed:      template.MustNewBool("true"),
		CreateIfAbsent:    template.MustNewBool("true"),
		UpdateIfDifferent: template.MustNewBool("true"),
	}, nil
}

func (this ConfigurationUser) Validate(key common.StructuredKey) error {
	fail := func(err error) error {
		return err
	}

	if err := this.RequirementTemplate.Validate(key); err != nil {
		return fail(err)
	}

	return nil
}
