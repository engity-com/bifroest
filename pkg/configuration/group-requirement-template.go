package configuration

import (
	"fmt"
	"github.com/engity-com/yasshd/pkg/common"
	"github.com/engity-com/yasshd/pkg/template"
	"github.com/engity-com/yasshd/pkg/user"
	"gopkg.in/yaml.v3"
)

const (
	DefaultGroupNameTmpl = "managed"
)

type GroupRequirementTemplate struct {
	Gid  template.Uint64 `yaml:"gid,omitempty"`
	Name template.String `yaml:"name,omitempty"`
}

func (this GroupRequirementTemplate) Render(key common.StructuredKey, data any) (result user.GroupRequirement, err error) {
	if result.Gid, err = this.Gid.Render(data); err != nil {
		return user.GroupRequirement{}, fmt.Errorf("[%v] %w", key.Child("gid"), err)
	}
	if result.Name, err = this.Name.Render(data); err != nil {
		return user.GroupRequirement{}, fmt.Errorf("[%v] %w", key.Child("name"), err)
	}
	return result, nil
}

func (this *GroupRequirementTemplate) SetDefaults() error {
	return setDefaults(this,
		noopSetDefault[GroupRequirementTemplate]("gid"),
		fixedDefault("name", func(v *GroupRequirementTemplate) *template.String { return &v.Name }, template.MustNewString(DefaultGroupNameTmpl)),
	)
}

func (this *GroupRequirementTemplate) Trim() error {
	return trim(this,
		noopTrim[GroupRequirementTemplate]("gid"),
		noopTrim[GroupRequirementTemplate]("name"),
	)
}

func (this *GroupRequirementTemplate) Validate() error {
	return validate(this,
		noopValidate[GroupRequirementTemplate]("gid"),
		noopValidate[GroupRequirementTemplate]("name"),
	)
}

func (this *GroupRequirementTemplate) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *GroupRequirementTemplate, node *yaml.Node) error {
		type raw GroupRequirementTemplate
		return node.Decode((*raw)(target))
	})
}

func (this GroupRequirementTemplate) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case GroupRequirementTemplate:
		return this.isEqualTo(&v)
	case *GroupRequirementTemplate:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this GroupRequirementTemplate) isEqualTo(other *GroupRequirementTemplate) bool {
	return isEqual(&this.Gid, &other.Gid) &&
		isEqual(&this.Name, &other.Name)
}

type GroupRequirementTemplates []GroupRequirementTemplate

func (this GroupRequirementTemplates) Render(key common.StructuredKey, data any) (result user.GroupRequirements, err error) {
	result = make(user.GroupRequirements, len(this))
	for i, tmpl := range this {
		iKey := key.Index(i)
		if result[i], err = tmpl.Render(iKey, data); err != nil {
			return nil, fmt.Errorf("[%v] %w", iKey, err)
		}
	}
	return result, nil
}

func (this *GroupRequirementTemplates) SetDefaults() error {
	return setSliceDefaults(this)
}

func (this *GroupRequirementTemplates) Trim() error {
	return trimSlice(this)
}

func (this GroupRequirementTemplates) Validate() error {
	return validateSlice(this)
}

func (this GroupRequirementTemplates) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case GroupRequirementTemplates:
		return this.isEqualTo(&v)
	case *GroupRequirementTemplates:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this GroupRequirementTemplates) isEqualTo(other *GroupRequirementTemplates) bool {
	if len(this) != len(*other) {
		return false
	}
	for i, tv := range this {
		if !tv.IsEqualTo((*other)[i]) {
			return false
		}
	}
	return true
}
