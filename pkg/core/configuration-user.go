package core

import (
	"github.com/engity/pam-oidc/pkg/common"
	"github.com/engity/pam-oidc/pkg/template"
	"github.com/engity/pam-oidc/pkg/user"
)

type ConfigurationUser struct {
	user.RequirementTemplate `yaml:",inline"`

	CreateIfAbsent    bool `yaml:"createIfAbsent,omitempty"`
	UpdateIfDifferent bool `yaml:"updateIfDifferent,omitempty"`
}

func NewConfigurationUser() (*ConfigurationUser, error) {
	return &ConfigurationUser{
		RequirementTemplate: user.RequirementTemplate{
			Name: template.MustNewString("{{.Oidc.UserInfo.Email}}"),
			//DisplayName: template.MustNewString("{{.Oidc.UserInfo.displayName}}"),
			Group: user.GroupRequirementTemplate{
				Name: template.MustNewString("sso"),
			},
			HomeDir: template.MustNewString("/home/sso/{{.Oidc.UserInfo.Email}}"),
		},
		CreateIfAbsent:    true,
		UpdateIfDifferent: true,
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
