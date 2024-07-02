package user

import "github.com/engity/pam-oidc/pkg/template"

type GroupRequirementTemplate struct {
	Gid  template.Uint64 `yaml:"gid,omitempty"`
	Name template.String `yaml:"name,omitempty"`
}

type GroupRequirementTemplates []GroupRequirementTemplate
