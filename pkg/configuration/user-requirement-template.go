package configuration

import (
	"fmt"
	"github.com/engity-com/yasshd/pkg/common"
	"github.com/engity-com/yasshd/pkg/template"
	"github.com/engity-com/yasshd/pkg/user"
	"gopkg.in/yaml.v3"
)

const (
	DefaultUserNameTmpl        = "{{.Authorization.IdToken.Claims.email}}"
	DefaultUserDisplayNameTmpl = "{{.Authorization.IdToken.Claims.name}}"
	DefaultUserShellTmpl       = "/bin/bash"
	DefaultUserHomeDirTmpl     = "/home/managed/{{.Authorization.IdToken.Claims.email}}"
)

type UserRequirementTemplate struct {
	Name        template.String           `yaml:"name,omitempty"`
	DisplayName template.String           `yaml:"displayName,omitempty"`
	Uid         template.Uint64           `yaml:"uid,omitempty"`
	Group       GroupRequirementTemplate  `yaml:"group,omitempty"`
	Groups      GroupRequirementTemplates `yaml:"groups,omitempty"`
	Shell       template.String           `yaml:"shell,omitempty"`
	HomeDir     template.String           `yaml:"homeDir,omitempty"`
	Skel        template.String           `yaml:"skel,omitempty"`
}

func (this *UserRequirementTemplate) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("name", func(v *UserRequirementTemplate) *template.String { return &v.Name }, template.MustNewString(DefaultUserNameTmpl)),
		fixedDefault("displayName", func(v *UserRequirementTemplate) *template.String { return &v.DisplayName }, template.MustNewString(DefaultUserDisplayNameTmpl)),
		noopSetDefault[UserRequirementTemplate]("uid"),
		func(v *UserRequirementTemplate) (string, defaulter) { return "group", &v.Group },
		noopSetDefault[UserRequirementTemplate]("groups"),
		fixedDefault("shell", func(v *UserRequirementTemplate) *template.String { return &v.Shell }, template.MustNewString(DefaultUserShellTmpl)),
		fixedDefault("homeDir", func(v *UserRequirementTemplate) *template.String { return &v.HomeDir }, template.MustNewString(DefaultUserHomeDirTmpl)),
		noopSetDefault[UserRequirementTemplate]("skel"),
	)
}

func (this *UserRequirementTemplate) Trim() error {
	return trim(this,
		noopTrim[UserRequirementTemplate]("name"),
		noopTrim[UserRequirementTemplate]("displayName"),
		noopTrim[UserRequirementTemplate]("uid"),
		func(v *UserRequirementTemplate) (string, trimmer) { return "group", &v.Group },
		func(v *UserRequirementTemplate) (string, trimmer) { return "groups", &v.Groups },
		noopTrim[UserRequirementTemplate]("shell"),
		noopTrim[UserRequirementTemplate]("homeDir"),
		noopTrim[UserRequirementTemplate]("skel"),
	)
}

func (this *UserRequirementTemplate) Validate() error {
	return validate(this,
		notZeroValidate("name", func(v *UserRequirementTemplate) *template.String { return &v.Name }),
		noopValidate[UserRequirementTemplate]("displayName"),
		noopValidate[UserRequirementTemplate]("uid"),
		noopValidate[UserRequirementTemplate]("group"),
		noopValidate[UserRequirementTemplate]("groups"),
		noopValidate[UserRequirementTemplate]("shell"),
		noopValidate[UserRequirementTemplate]("homeDir"),
		noopValidate[UserRequirementTemplate]("skel"),
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
	if result.DisplayName, err = this.DisplayName.Render(data); err != nil {
		return nil, fmt.Errorf("[%v] %w", key.Child("displayName"), err)
	}
	if result.Uid, err = this.Uid.Render(data); err != nil {
		return nil, fmt.Errorf("[%v] %w", key.Child("uid"), err)
	}
	if result.Group, err = this.Group.Render(key.Child("group"), data); err != nil {
		return nil, err
	}
	if result.Groups, err = this.Groups.Render(key.Child("groups"), data); err != nil {
		return nil, err
	}
	if result.Shell, err = this.Shell.Render(data); err != nil {
		return nil, fmt.Errorf("[%v] %w", key.Child("shell"), err)
	}
	if result.HomeDir, err = this.HomeDir.Render(data); err != nil {
		return nil, fmt.Errorf("[%v] %w", key.Child("homeDir"), err)
	}
	if result.Skel, err = this.Skel.Render(data); err != nil {
		return nil, fmt.Errorf("[%v] %w", key.Child("skel"), err)
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
		isEqual(&this.DisplayName, &other.DisplayName) &&
		isEqual(&this.Uid, &other.Uid) &&
		isEqual(&this.Group, &other.Group) &&
		isEqual(&this.Groups, &other.Groups) &&
		isEqual(&this.Shell, &other.Shell) &&
		isEqual(&this.Skel, &other.Skel)
}
