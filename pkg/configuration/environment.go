package configuration

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"reflect"
)

type Environment struct {
	V EnvironmentV
}

type EnvironmentV interface {
	defaulter
	trimmer
	validator
	equaler
}

func (this *Environment) SetDefaults() error {
	*this = Environment{&EnvironmentLocal{}}
	if err := this.V.SetDefaults(); err != nil {
		return err
	}
	return nil
}

func (this *Environment) Trim() error {
	if this.V != nil {
		if err := this.V.Trim(); err != nil {
			return err
		}
	}
	return this.Validate()
}

func (this *Environment) Validate() error {
	if v := this.V; v != nil {
		return v.Validate()
	}
	return fmt.Errorf("required but absent")
}

func (this *Environment) UnmarshalYAML(node *yaml.Node) error {
	var typeBuf struct {
		Type string `yaml:"type"`
	}

	if err := node.Decode(&typeBuf); err != nil {
		return reportYamlRelatedErr(node, err)
	}

	if err := this.SetDefaults(); err != nil {
		return reportYamlRelatedErr(node, err)
	}

	switch typeBuf.Type {
	case "":
		return reportYamlRelatedErrf(node, "[type] required but absent")
	case "local":
		this.V = &EnvironmentLocal{}
	default:
		return reportYamlRelatedErrf(node, "[type] illegal type: %q", typeBuf.Type)
	}

	if err := node.Decode(this.V); err != nil {
		return reportYamlRelatedErr(node, err)
	}

	return this.Trim()
}

func (this *Environment) MarshalYAML() (any, error) {
	typeBuf := struct {
		EnvironmentV `yaml:",inline"`
		Type         string `yaml:"type"`
	}{
		EnvironmentV: this.V,
	}

	switch typeBuf.EnvironmentV.(type) {
	case *EnvironmentLocal:
		typeBuf.Type = "local"
	default:
		return nil, fmt.Errorf("[type] illegal type: %v", reflect.TypeOf(typeBuf.EnvironmentV))
	}

	return typeBuf, nil
}

func (this Environment) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Environment:
		return this.isEqualTo(&v)
	case *Environment:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Environment) isEqualTo(other *Environment) bool {
	if other.V == nil {
		return this.V == nil
	}
	return this.V.IsEqualTo(other.V)
}
