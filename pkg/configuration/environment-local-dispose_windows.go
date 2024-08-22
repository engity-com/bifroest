//go:build windows

package configuration

import (
	"gopkg.in/yaml.v3"
)

type EnvironmentLocalDispose struct{}

func (this *EnvironmentLocalDispose) SetDefaults() error {
	return setDefaults(this)
}

func (this *EnvironmentLocalDispose) Trim() error {
	return trim(this)
}

func (this *EnvironmentLocalDispose) Validate() error {
	return validate(this)
}

func (this *EnvironmentLocalDispose) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *EnvironmentLocalDispose, node *yaml.Node) error {
		type raw EnvironmentLocalDispose
		return node.Decode((*raw)(target))
	})
}

func (this EnvironmentLocalDispose) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case EnvironmentLocalDispose:
		return this.isEqualTo(&v)
	case *EnvironmentLocalDispose:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this EnvironmentLocalDispose) isEqualTo(_ *EnvironmentLocalDispose) bool {
	return true
}
