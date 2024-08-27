package configuration

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Environment struct {
	V EnvironmentV
}

type EnvironmentV interface {
	defaulter
	trimmer
	validator
	equaler
	Types() []string
	FeatureFlags() []string
}

var (
	typeToEnvironmentFactory = make(map[string]EnvironmentVFactory)
	environmentVs            []EnvironmentV
)

type EnvironmentVFactory func() EnvironmentV

func RegisterEnvironmentV(factory EnvironmentVFactory) EnvironmentVFactory {
	pt := factory()
	ts := pt.Types()
	if len(ts) == 0 {
		panic(fmt.Errorf("the instance does not provide any type"))
	}
	for _, t := range ts {
		typeToEnvironmentFactory[strings.ToLower(t)] = factory
	}
	environmentVs = append(environmentVs, pt)
	return factory
}

func (this *Environment) SetDefaults() error {
	*this = Environment{}
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

	if typeBuf.Type == "" {
		return reportYamlRelatedErrf(node, "[type] required but absent")
	}

	factory, ok := typeToEnvironmentFactory[strings.ToLower(typeBuf.Type)]
	if !ok {
		return reportYamlRelatedErrf(node, "[type] illegal type: %q", typeBuf.Type)
	}

	this.V = factory()
	if err := node.Decode(this.V); err != nil {
		return reportYamlRelatedErr(node, err)
	}

	return this.Trim()
}

func (this *Environment) MarshalYAML() (any, error) {
	typeBuf := struct {
		EnvironmentV `yaml:",inline"`
		Type         string `yaml:"type,omitempty"`
	}{}

	if this.V != nil {
		typeBuf.Type = this.V.Types()[0]
		typeBuf.EnvironmentV = this.V
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

func GetSupportedEnvironmentFeatureFlags() []string {
	var result []string
	for _, v := range environmentVs {
		result = append(result, v.FeatureFlags()...)
	}
	sort.Strings(result)
	return result
}
