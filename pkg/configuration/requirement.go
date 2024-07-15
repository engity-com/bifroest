package configuration

import (
	"github.com/engity-com/yasshd/pkg/common"
	"gopkg.in/yaml.v3"
)

var (
	DefaultRequirementIncludedRequestingName = common.MustNewRegexp("")
	DefaultRequirementExcludedRequestingName = common.MustNewRegexp("")
)

type Requirement struct {
	IncludedRequestingName common.Regexp `yaml:"includedRequestingName,omitempty"`
	ExcludedRequestingName common.Regexp `yaml:"excludedRequestingName,omitempty"`
}

func (this *Requirement) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("includedRequestingName", func(v *Requirement) *common.Regexp { return &v.IncludedRequestingName }, DefaultRequirementIncludedRequestingName),
		fixedDefault("excludedRequestingName", func(v *Requirement) *common.Regexp { return &v.ExcludedRequestingName }, DefaultRequirementExcludedRequestingName),
	)
}

func (this *Requirement) Trim() error {
	return trim(this,
		noopTrim[Requirement]("includedRequestingName"),
		noopTrim[Requirement]("excludedRequestingName"),
	)
}

func (this *Requirement) Validate() error {
	return validate(this,
		noopValidate[Requirement]("includedRequestingName"),
		noopValidate[Requirement]("excludedRequestingName"),
	)
}

func (this *Requirement) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *Requirement, node *yaml.Node) error {
		type raw Requirement
		return node.Decode((*raw)(target))
	})
}

func (this Requirement) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Requirement:
		return this.isEqualTo(&v)
	case *Requirement:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Requirement) isEqualTo(other *Requirement) bool {
	return isEqual(&this.IncludedRequestingName, &other.IncludedRequestingName) &&
		isEqual(&this.ExcludedRequestingName, &other.ExcludedRequestingName)
}
