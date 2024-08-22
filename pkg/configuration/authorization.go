package configuration

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"strings"
)

type Authorization struct {
	V AuthorizationV
}

type AuthorizationV interface {
	defaulter
	trimmer
	validator
	equaler
	Types() []string
}

var (
	typeToAuthorizationFactory = make(map[string]AuthorizationVFactory)
)

type AuthorizationVFactory func() AuthorizationV

func RegisterAuthorizationV(factory AuthorizationVFactory) AuthorizationVFactory {
	pt := factory()
	ts := pt.Types()
	if len(ts) == 0 {
		panic(fmt.Errorf("the instance does not provide any type"))
	}
	for _, t := range ts {
		typeToAuthorizationFactory[t] = factory
	}
	return factory
}

func (this *Authorization) SetDefaults() error {
	*this = Authorization{}
	return nil
}

func (this *Authorization) Trim() error {
	if this.V != nil {
		if err := this.V.Trim(); err != nil {
			return err
		}
	}
	return this.Validate()
}

func (this *Authorization) Validate() error {
	if v := this.V; v != nil {
		return v.Validate()
	}
	return fmt.Errorf("required but absent")
}

func (this *Authorization) UnmarshalYAML(node *yaml.Node) error {
	var typeBuf struct {
		Type string `yaml:"type"`
	}

	if err := node.Decode(&typeBuf); err != nil {
		return reportYamlRelatedErr(node, err)
	}

	if err := this.SetDefaults(); err != nil {
		return reportYamlRelatedErr(node, err)
	}

	if typeBuf.Type == "" {
		return reportYamlRelatedErrf(node, "[type] required but absent")
	}

	factory, ok := typeToAuthorizationFactory[strings.ToLower(typeBuf.Type)]
	if !ok {
		return reportYamlRelatedErrf(node, "[type] illegal type: %q", typeBuf.Type)
	}

	this.V = factory()
	if err := node.Decode(this.V); err != nil {
		return reportYamlRelatedErr(node, err)
	}

	return this.Trim()
}

func (this *Authorization) MarshalYAML() (any, error) {
	typeBuf := struct {
		AuthorizationV `yaml:",inline"`
		Type           string `yaml:"type,omitempty"`
	}{
		AuthorizationV: this.V,
	}

	if this.V != nil {
		typeBuf.Type = this.V.Types()[0]
		typeBuf.AuthorizationV = this.V
	}

	return typeBuf, nil
}

func (this Authorization) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Authorization:
		return this.isEqualTo(&v)
	case *Authorization:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Authorization) isEqualTo(other *Authorization) bool {
	if other.V == nil {
		return this.V == nil
	}
	return this.V.IsEqualTo(other.V)
}

func GetSupportedAuthorizationVs() []string {
	result := make([]string, len(typeToAuthorizationFactory))
	var i int
	for k := range typeToAuthorizationFactory {
		result[i] = strings.Clone(k)
	}
	return result
}
