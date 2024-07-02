package user

import (
	"github.com/engity/pam-oidc/pkg/template"
)

type RequirementTemplate struct {
	Name        template.String           `yaml:"name,omitempty"`
	DisplayName template.String           `yaml:"displayName,omitempty"`
	Uid         template.Uint64           `yaml:"uid,omitempty"`
	Group       GroupRequirementTemplate  `yaml:"group,omitempty"`
	Groups      GroupRequirementTemplates `yaml:"groups,omitempty"`
	Shell       template.String           `yaml:"shell,omitempty"`
	HomeDir     template.String           `yaml:"homeDir,omitempty"`
	Skel        template.String           `yaml:"skel,omitempty"`
}
