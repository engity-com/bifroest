package configuration

import (
	"github.com/engity/pam-oidc/pkg/common"
	"gopkg.in/yaml.v3"
)

type FlowRequirement struct {
	IncludedRequestingName common.Regexp `yaml:"includedRequestingName,omitempty"`
	ExcludedRequestingName common.Regexp `yaml:"excludedRequestingName,omitempty"`
}

func (this *FlowRequirement) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("includedRequestingName", func(v *FlowRequirement) *common.Regexp { return &v.IncludedRequestingName }, common.MustNewRegexp("")),
		fixedDefault("excludedRequestingName", func(v *FlowRequirement) *common.Regexp { return &v.ExcludedRequestingName }, common.MustNewRegexp("")),
	)
}

func (this *FlowRequirement) Trim() error {
	return trim(this,
		noopTrim[FlowRequirement]("includedRequestingName"),
		noopTrim[FlowRequirement]("excludedRequestingName"),
	)
}

func (this *FlowRequirement) Validate() error {
	return validate(this,
		noopValidate[FlowRequirement]("includedRequestingName"),
		noopValidate[FlowRequirement]("excludedRequestingName"),
	)
}

func (this *FlowRequirement) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *FlowRequirement, node *yaml.Node) error {
		type raw FlowRequirement
		return node.Decode((*raw)(target))
	})
}

func (this FlowRequirement) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case FlowRequirement:
		return this.isEqualTo(&v)
	case *FlowRequirement:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this FlowRequirement) isEqualTo(other *FlowRequirement) bool {
	return isEqual(&this.IncludedRequestingName, &other.IncludedRequestingName) &&
		isEqual(&this.ExcludedRequestingName, &other.ExcludedRequestingName)
}
