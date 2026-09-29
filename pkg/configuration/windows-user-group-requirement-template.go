//go:build windows

package configuration

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

type WindowsUserGroupRequirementTemplate struct {
	Name template.String `yaml:"name,omitempty"`
	Gid  template.String `yaml:"gid,omitempty"`
}

type WindowsUserGroupRequirement struct {
	Name string
	Gid  string
}

func (this WindowsUserGroupRequirementTemplate) Render(data any) (result WindowsUserGroupRequirement, err error) {
	if result.Name, err = this.Name.Render(data); err != nil {
		return result, fmt.Errorf("render group name: %w", err)
	}
	if result.Gid, err = this.Gid.Render(data); err != nil {
		return result, fmt.Errorf("render group GID (Windows SID): %w", err)
	}
	if result.Name == "" && result.Gid == "" {
		return result, fmt.Errorf("group requires a name or GID")
	}
	return result, nil
}

func (this *WindowsUserGroupRequirementTemplate) SetDefaults() error { return nil }

func (this *WindowsUserGroupRequirementTemplate) Trim() error {
	return trim(this,
		noopTrim[WindowsUserGroupRequirementTemplate]("name"),
		noopTrim[WindowsUserGroupRequirementTemplate]("gid"),
	)
}

func (this *WindowsUserGroupRequirementTemplate) Validate() error {
	if this.Name.IsZero() && this.Gid.IsZero() {
		return fmt.Errorf("group requires a name or GID")
	}
	return validate(this,
		func(v *WindowsUserGroupRequirementTemplate) (string, validator) { return "name", &v.Name },
		func(v *WindowsUserGroupRequirementTemplate) (string, validator) { return "gid", &v.Gid },
	)
}

func (this *WindowsUserGroupRequirementTemplate) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *WindowsUserGroupRequirementTemplate, node *yaml.Node) error {
		type raw WindowsUserGroupRequirementTemplate
		return node.Decode((*raw)(target))
	})
}

func (this WindowsUserGroupRequirementTemplate) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case WindowsUserGroupRequirementTemplate:
		return isEqual(&this.Name, &v.Name) && isEqual(&this.Gid, &v.Gid)
	case *WindowsUserGroupRequirementTemplate:
		return v != nil && this.IsEqualTo(*v)
	default:
		return false
	}
}

type WindowsUserGroupRequirementTemplates []WindowsUserGroupRequirementTemplate

func (this WindowsUserGroupRequirementTemplates) Render(data any) ([]WindowsUserGroupRequirement, error) {
	result := make([]WindowsUserGroupRequirement, len(this))
	for i, tmpl := range this {
		var err error
		if result[i], err = tmpl.Render(data); err != nil {
			return nil, fmt.Errorf("group %d: %w", i, err)
		}
	}
	return result, nil
}

func (this *WindowsUserGroupRequirementTemplates) SetDefaults() error { return setSliceDefaults(this) }
func (this *WindowsUserGroupRequirementTemplates) Trim() error        { return trimSlice(this) }
func (this WindowsUserGroupRequirementTemplates) Validate() error     { return validateSlice(this) }

func (this *WindowsUserGroupRequirementTemplates) UnmarshalYAML(node *yaml.Node) error {
	*this = WindowsUserGroupRequirementTemplates{}
	return unmarshalYAML(this, node, func(target *WindowsUserGroupRequirementTemplates, node *yaml.Node) error {
		type raw WindowsUserGroupRequirementTemplates
		return node.Decode((*raw)(target))
	})
}

func (this WindowsUserGroupRequirementTemplates) IsEqualTo(other any) bool {
	var otherGroups WindowsUserGroupRequirementTemplates
	switch v := other.(type) {
	case WindowsUserGroupRequirementTemplates:
		otherGroups = v
	case *WindowsUserGroupRequirementTemplates:
		if v == nil {
			return false
		}
		otherGroups = *v
	default:
		return false
	}
	if len(this) != len(otherGroups) {
		return false
	}
	for i := range this {
		if !this[i].IsEqualTo(otherGroups[i]) {
			return false
		}
	}
	return true
}
