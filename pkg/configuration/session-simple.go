package configuration

import (
	"gopkg.in/yaml.v3"
)

// SessionSimple defines an implementation of Session which simply does nothing.
type SessionSimple struct{}

func (this *SessionSimple) SetDefaults() error {
	return setDefaults(this)
}

func (this *SessionSimple) Trim() error {
	return trim(this)
}

func (this *SessionSimple) Validate() error {
	return validate(this)
}

func (this *SessionSimple) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *SessionSimple, node *yaml.Node) error {
		type raw SessionSimple
		return node.Decode((*raw)(target))
	})
}

func (this SessionSimple) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case SessionFs:
		return this.isEqualTo(&v)
	case *SessionFs:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this SessionSimple) isEqualTo(_ *SessionFs) bool {
	return true
}
