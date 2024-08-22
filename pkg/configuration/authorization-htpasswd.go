package configuration

import (
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/sys"
	"gopkg.in/yaml.v3"
)

var (
	DefaultAuthorizationHtpasswdFile = defaultAuthorizationHtpasswdFile

	_ = RegisterAuthorizationV(func() AuthorizationV {
		return &AuthorizationHtpasswd{}
	})
)

type AuthorizationHtpasswd struct {
	File    crypto.HtpasswdFile `yaml:"file,omitempty"`
	Entries crypto.Htpasswd     `yaml:"entries,omitempty"`
}

func (this *AuthorizationHtpasswd) SetDefaults() error {
	return setDefaults(this,
		func(v *AuthorizationHtpasswd) (string, defaulter) {
			return "file", defaulterFunc(func() error {
				fn := DefaultAuthorizationHtpasswdFile
				var buf crypto.HtpasswdFile
				if fn != "" {
					if err := buf.Set(fn); err != nil && !sys.IsNotExist(err) {
						return err
					}
				}
				v.File = buf
				return nil
			})
		},
		noopSetDefault[AuthorizationHtpasswd]("entries"),
	)
}

func (this *AuthorizationHtpasswd) Trim() error {
	return trim(this,
		noopTrim[AuthorizationHtpasswd]("file"),
		noopTrim[AuthorizationHtpasswd]("entries"),
	)
}

func (this *AuthorizationHtpasswd) Validate() error {
	return validate(this,
		func(v *AuthorizationHtpasswd) (string, validator) { return "file", &v.File },
		func(v *AuthorizationHtpasswd) (string, validator) { return "entries", &v.Entries },
	)
}

func (this *AuthorizationHtpasswd) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *AuthorizationHtpasswd, node *yaml.Node) error {
		type raw AuthorizationHtpasswd
		return node.Decode((*raw)(target))
	})
}

func (this AuthorizationHtpasswd) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case AuthorizationHtpasswd:
		return this.isEqualTo(&v)
	case *AuthorizationHtpasswd:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this AuthorizationHtpasswd) isEqualTo(other *AuthorizationHtpasswd) bool {
	return isEqual(&this.File, &other.File) &&
		isEqual(&this.Entries, &other.Entries)
}

func (this AuthorizationHtpasswd) Types() []string {
	return []string{"htpasswd"}
}
