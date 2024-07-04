package user

import (
	"fmt"
	"github.com/engity/pam-oidc/pkg/common"
	"github.com/engity/pam-oidc/pkg/template"
)

type GroupRequirementTemplate struct {
	Gid  template.Uint64 `yaml:"gid,omitempty"`
	Name template.String `yaml:"name,omitempty"`
}

func (this GroupRequirementTemplate) Render(key common.StructuredKey, data any) (result GroupRequirement, err error) {
	if result.Gid, err = this.Gid.Render(data); err != nil {
		return GroupRequirement{}, fmt.Errorf("[%v] %w", key.Child("gid"), err)
	}
	if result.Name, err = this.Name.Render(data); err != nil {
		return GroupRequirement{}, fmt.Errorf("[%v] %w", key.Child("name"), err)
	}
	return result, nil
}

type GroupRequirementTemplates []GroupRequirementTemplate

func (this GroupRequirementTemplates) Render(key common.StructuredKey, data any) (result GroupRequirements, err error) {
	result = make(GroupRequirements, len(this))
	for i, tmpl := range this {
		iKey := key.Index(i)
		if result[i], err = tmpl.Render(iKey, data); err != nil {
			return nil, fmt.Errorf("[%v] %w", iKey, err)
		}
	}
	return result, nil
}
