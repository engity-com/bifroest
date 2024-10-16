package configuration

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/crypto"
)

type AuthorizationSimpleEntry struct {
	Name               string                    `yaml:"name"`
	AuthorizedKeys     crypto.AuthorizedKeys     `yaml:"authorizedKeys,omitempty"`
	AuthorizedKeysFile crypto.AuthorizedKeysFile `yaml:"authorizedKeysFile,omitempty"`
	Password           crypto.Password           `yaml:"password,omitempty"`
}

func (this *AuthorizationSimpleEntry) GetField(name string) (any, bool, error) {
	switch name {
	case "name":
		return this.Name, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

func (this *AuthorizationSimpleEntry) SetDefaults() error {
	return setDefaults(this,
		noopSetDefault[AuthorizationSimpleEntry]("name"),
		noopSetDefault[AuthorizationSimpleEntry]("authorizedKeys"),
		noopSetDefault[AuthorizationSimpleEntry]("authorizedKeysFile"),
		noopSetDefault[AuthorizationSimpleEntry]("password"),
	)
}

func (this *AuthorizationSimpleEntry) Trim() error {
	return trim(this,
		func(v *AuthorizationSimpleEntry) (string, trimmer) { return "name", &stringTrimmer{&v.Name} },
		func(v *AuthorizationSimpleEntry) (string, trimmer) { return "authorizedKeys", &v.AuthorizedKeys },
		noopTrim[AuthorizationSimpleEntry]("authorizedKeysFile"),
		noopTrim[AuthorizationSimpleEntry]("password"),
	)
}

func (this *AuthorizationSimpleEntry) Validate() error {
	return validate(this,
		notEmptyStringValidate[AuthorizationSimpleEntry]("name", func(v *AuthorizationSimpleEntry) *string { return &v.Name }),
		func(v *AuthorizationSimpleEntry) (string, validator) { return "authorizedKeys", &v.AuthorizedKeys },
		func(v *AuthorizationSimpleEntry) (string, validator) {
			return "authorizedKeysFile", &v.AuthorizedKeysFile
		},
		func(v *AuthorizationSimpleEntry) (string, validator) { return "password", &v.Password },
	)
}

func (this *AuthorizationSimpleEntry) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *AuthorizationSimpleEntry, node *yaml.Node) error {
		type raw AuthorizationSimpleEntry
		return node.Decode((*raw)(target))
	})
}

func (this AuthorizationSimpleEntry) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case AuthorizationSimpleEntry:
		return this.isEqualTo(&v)
	case *AuthorizationSimpleEntry:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this AuthorizationSimpleEntry) isEqualTo(other *AuthorizationSimpleEntry) bool {
	return this.Name == other.Name &&
		isEqual(&this.AuthorizedKeys, &other.AuthorizedKeys) &&
		isEqual(&this.AuthorizedKeysFile, &other.AuthorizedKeysFile) &&
		isEqual(&this.Password, &other.Password)
}

type AuthorizationSimpleEntries []AuthorizationSimpleEntry

func (this *AuthorizationSimpleEntries) SetDefaults() error {
	return setSliceDefaults(this) // Empty, be default.
}

func (this *AuthorizationSimpleEntries) Trim() error {
	return trimSlice(this)
}

func (this AuthorizationSimpleEntries) Validate() error {
	return validateSlice(this)
}

func (this *AuthorizationSimpleEntries) UnmarshalYAML(node *yaml.Node) error {
	// Clear the entries before...
	*this = AuthorizationSimpleEntries{}
	return unmarshalYAML(this, node, func(target *AuthorizationSimpleEntries, node *yaml.Node) error {
		type raw AuthorizationSimpleEntries
		return node.Decode((*raw)(target))
	})
}

func (this AuthorizationSimpleEntries) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case AuthorizationSimpleEntries:
		return this.isEqualTo(&v)
	case *AuthorizationSimpleEntries:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this AuthorizationSimpleEntries) isEqualTo(other *AuthorizationSimpleEntries) bool {
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
