package user

import (
	"fmt"
	"github.com/engity/pam-oidc/pkg/common"
	"github.com/engity/pam-oidc/pkg/errors"
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

func (this RequirementTemplate) Validate(key common.StructuredKey) error {
	fail := func(err error) error {
		return err
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.Newf(errors.TypeConfig, msg, args...))
	}

	if this.Name.IsZero() {
		return failf("required option %v", key.Child("name"))
	}

	return nil
}

func (this RequirementTemplate) Render(key common.StructuredKey, data any) (result Requirement, err error) {
	if result.Name, err = this.Name.Render(data); err != nil {
		return Requirement{}, fmt.Errorf("[%v] %w", key.Child("name"), err)
	}
	if result.DisplayName, err = this.DisplayName.Render(data); err != nil {
		return Requirement{}, fmt.Errorf("[%v] %w", key.Child("displayName"), err)
	}
	if result.Uid, err = this.Uid.Render(data); err != nil {
		return Requirement{}, fmt.Errorf("[%v] %w", key.Child("uid"), err)
	}
	if result.Group, err = this.Group.Render(key.Child("group"), data); err != nil {
		return Requirement{}, err
	}
	if result.Groups, err = this.Groups.Render(key.Child("groups"), data); err != nil {
		return Requirement{}, err
	}
	if result.Shell, err = this.Shell.Render(data); err != nil {
		return Requirement{}, fmt.Errorf("[%v] %w", key.Child("shell"), err)
	}
	if result.HomeDir, err = this.HomeDir.Render(data); err != nil {
		return Requirement{}, fmt.Errorf("[%v] %w", key.Child("homeDir"), err)
	}
	if result.Skel, err = this.Skel.Render(data); err != nil {
		return Requirement{}, fmt.Errorf("[%v] %w", key.Child("skel"), err)
	}
	return result, nil
}
