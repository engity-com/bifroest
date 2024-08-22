//go:build windows

package configuration

import (
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
	"gopkg.in/yaml.v3"
)

var (
	DefaultUserRequirementShell = template.MustNewString(`cmd.exe`)
)

type UserRequirementTemplate struct {
	Name  template.String                             `yaml:"name,omitempty"`
	Uid   *template.TextMarshaller[user.Id, *user.Id] `yaml:"uid,omitempty"`
	Shell template.String                             `yaml:"shell,omitempty"`
}

func (this *UserRequirementTemplate) SetDefaults() error {
	return setDefaults(this,
		noopSetDefault[UserRequirementTemplate]("name"),
		noopSetDefault[UserRequirementTemplate]("uid"),
		fixedDefault("shell", func(v *UserRequirementTemplate) *template.String { return &v.Shell }, DefaultUserRequirementShell),
	)
}

func (this *UserRequirementTemplate) Trim() error {
	return trim(this,
		noopTrim[UserRequirementTemplate]("name"),
		noopTrim[UserRequirementTemplate]("uid"),
		noopTrim[UserRequirementTemplate]("shell"),
	)
}

func (this *UserRequirementTemplate) Validate() error {
	return validate(this,
		notZeroValidate("name", func(v *UserRequirementTemplate) *template.String { return &v.Name }),
		noopValidate[UserRequirementTemplate]("uid"),
		notZeroValidate("shell", func(v *UserRequirementTemplate) *template.String { return &v.Shell }),
	)
}

func (this *UserRequirementTemplate) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *UserRequirementTemplate, node *yaml.Node) error {
		type raw UserRequirementTemplate
		return node.Decode((*raw)(target))
	})
}

func (this UserRequirementTemplate) Render(key common.StructuredKey, data any) (_ *user.Requirement, err error) {
	result := user.Requirement{}
	if result.Name, err = this.Name.Render(data); err != nil {
		return nil, fmt.Errorf("[%v] %w", key.Child("name"), err)
	}
	if v := this.Uid; v != nil {
		buf, err := this.Uid.Render(data)
		if err != nil {
			return nil, fmt.Errorf("[%v] %w", key.Child("uid"), err)
		}
		result.Uid = &buf
	}
	return &result, nil
}

func (this UserRequirementTemplate) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case UserRequirementTemplate:
		return this.isEqualTo(&v)
	case *UserRequirementTemplate:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this UserRequirementTemplate) isEqualTo(other *UserRequirementTemplate) bool {
	return isEqual(&this.Name, &other.Name) &&
		isEqual(&this.Uid, &other.Uid)
}
