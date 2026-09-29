//go:build windows

package configuration

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/template"
)

// WindowsUserRequirementTemplate uses SID strings for UID and group GID.
type WindowsUserRequirementTemplate struct {
	Name        template.String                      `yaml:"name,omitempty"`
	Uid         template.String                      `yaml:"uid,omitempty"`
	DisplayName template.String                      `yaml:"displayName,omitempty"`
	Groups      WindowsUserGroupRequirementTemplates `yaml:"groups,omitempty"`
	Skel        template.String                      `yaml:"skel,omitempty"`
}

func (this *WindowsUserRequirementTemplate) SetDefaults() error {
	return setDefaults(this,
		noopSetDefault[WindowsUserRequirementTemplate]("name"),
		noopSetDefault[WindowsUserRequirementTemplate]("uid"),
		fixedDefault("displayName", func(v *WindowsUserRequirementTemplate) *template.String { return &v.DisplayName }, DefaultEnvironmentLocalDisplayName),
		func(v *WindowsUserRequirementTemplate) (string, defaulter) { return "groups", &v.Groups },
		noopSetDefault[WindowsUserRequirementTemplate]("skel"),
	)
}

func (this *WindowsUserRequirementTemplate) Trim() error {
	return trim(this,
		noopTrim[WindowsUserRequirementTemplate]("name"),
		noopTrim[WindowsUserRequirementTemplate]("uid"),
		noopTrim[WindowsUserRequirementTemplate]("displayName"),
		func(v *WindowsUserRequirementTemplate) (string, trimmer) { return "groups", &v.Groups },
		noopTrim[WindowsUserRequirementTemplate]("skel"),
	)
}

func (this *WindowsUserRequirementTemplate) Validate() error {
	if this.Name.IsZero() && this.Uid.IsZero() {
		return fmt.Errorf("name or uid is required")
	}
	return validate(this,
		func(v *WindowsUserRequirementTemplate) (string, validator) { return "name", &v.Name },
		func(v *WindowsUserRequirementTemplate) (string, validator) { return "uid", &v.Uid },
		func(v *WindowsUserRequirementTemplate) (string, validator) { return "displayName", &v.DisplayName },
		func(v *WindowsUserRequirementTemplate) (string, validator) { return "groups", &v.Groups },
		func(v *WindowsUserRequirementTemplate) (string, validator) { return "skel", &v.Skel },
	)
}

func (this WindowsUserRequirementTemplate) IsEqualTo(other any) bool {
	switch that := other.(type) {
	case WindowsUserRequirementTemplate:
		return isEqual(&this.Name, &that.Name) &&
			isEqual(&this.Uid, &that.Uid) &&
			isEqual(&this.DisplayName, &that.DisplayName) &&
			isEqual(&this.Groups, &that.Groups) &&
			isEqual(&this.Skel, &that.Skel)
	case *WindowsUserRequirementTemplate:
		return that != nil && this.IsEqualTo(*that)
	default:
		return false
	}
}
