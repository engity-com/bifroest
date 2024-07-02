package core

import (
	"github.com/engity/pam-oidc/pkg/user"
)

type ConfigurationUser struct {
	user.RequirementTemplate `yaml:",inline"`

	CreateIfAbsent bool `yaml:"createIfAbsent,omitempty"`
}

func NewConfigurationUser() (*ConfigurationUser, error) {
	return &ConfigurationUser{
		RequirementTemplate: user.RequirementTemplate{
			Name:        "{{.UserInfo.email}}",
			DisplayName: "{{.UserInfo.displayName}}",
			Group: user.GroupRequirementTemplate{
				Name: "sso",
			},
		},
		CreateIfAbsent: true,
	}, nil
}
