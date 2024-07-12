package configuration

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"reflect"
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
}

func (this *Authorization) SetDefaults() error {
	*this = Authorization{&AuthorizationOidcDeviceAuth{}}
	if err := this.V.SetDefaults(); err != nil {
		return err
	}
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

	switch strings.ToLower(typeBuf.Type) {
	case "":
		return reportYamlRelatedErrf(node, "[type] required but absent")
	case "oidc-device-auth", "oidc_device_auth", "oidcdeviceauth":
		this.V = &AuthorizationOidcDeviceAuth{}
	default:
		return reportYamlRelatedErrf(node, "[type] illegal type: %q", typeBuf.Type)
	}

	if err := node.Decode(this.V); err != nil {
		return reportYamlRelatedErr(node, err)
	}

	return this.Trim()
}

func (this *Authorization) MarshalYAML() (any, error) {
	typeBuf := struct {
		AuthorizationV `yaml:",inline"`
		Type           string `yaml:"type"`
	}{
		AuthorizationV: this.V,
	}

	switch typeBuf.AuthorizationV.(type) {
	case *AuthorizationOidcDeviceAuth:
		typeBuf.Type = "oidcDeviceAuth"
	default:
		return nil, fmt.Errorf("[type] illegal type: %v", reflect.TypeOf(typeBuf.AuthorizationV))
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
