package configuration

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Environment struct {
	Variables EnvironmentVariables `yaml:"variables,omitempty" sensitive:"true"`
	V         EnvironmentV         `yaml:"-"`
	// Reference is the configured definition name; V is the effective per-flow value.
	Reference string `yaml:"-"`
	resolved  bool
}

type EnvironmentV interface {
	defaulter
	trimmer
	validator
	equaler
	Types() []string
	FeatureFlags() []string
}

type EnvironmentVariablesAware interface {
	SupportsEnvironmentVariables() bool
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
	return this.Variables.SetDefaults()
}

func (this *Environment) Trim() error {
	if this.V != nil {
		if err := this.V.Trim(); err != nil {
			return err
		}
	}
	if err := this.Variables.Trim(); err != nil {
		return configurationFieldError(this, "variables", err)
	}
	return this.Validate()
}

func (this *Environment) Validate() error {
	if err := this.Variables.Validate(); err != nil {
		return configurationFieldError(this, "variables", err)
	}
	if v := this.V; v != nil {
		if !this.Variables.IsZero() {
			support, ok := v.(EnvironmentVariablesAware)
			if !ok || !support.SupportsEnvironmentVariables() {
				return fmt.Errorf("[variables] not supported by environment type %q", v.Types()[0])
			}
		}
		return v.Validate()
	}
	return fmt.Errorf("required but absent")
}

func (this *Environment) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		*this = Environment{Reference: node.Value}
		return nil
	}
	if _, err := effectiveHttpFields(node); err != nil {
		return err
	}
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
	if err := rejectUnknownConfigurationFields(node, this.V, "type", "variables"); err != nil {
		return err
	}
	if err := node.Decode(this.V); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	var common struct {
		Variables EnvironmentVariables `yaml:"variables,omitempty" sensitive:"true"`
	}
	if err := decodeConfigurationFields(node, &common); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	this.Variables = common.Variables

	return this.Trim()
}

func (this Environment) MarshalYAML() (any, error) {
	if this.Reference != "" {
		return this.Reference, nil
	}
	if this.resolved || this.V == nil {
		return nil, nil
	}
	var result yaml.Node
	if err := result.Encode(this.V); err != nil {
		return nil, err
	}
	if result.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("environment %T does not encode as a mapping", this.V)
	}
	result.Content = append([]*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "type"},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: this.V.Types()[0]},
	}, result.Content...)
	if !this.Variables.IsZero() {
		var variables yaml.Node
		if err := variables.Encode(this.Variables); err != nil {
			return nil, err
		}
		result.Content = append(result.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "variables"}, &variables)
	}
	return &result, nil
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
	if other == nil || this.Reference != other.Reference || (this.Reference == "" && this.resolved != other.resolved) {
		return false
	}
	if !isEqual(&this.Variables, &other.Variables) {
		return false
	}
	if other.V == nil {
		return this.V == nil
	}
	return this.V != nil && this.V.IsEqualTo(other.V)
}

func GetSupportedEnvironmentFeatureFlags() []string {
	var result []string
	for _, v := range environmentVs {
		result = append(result, v.FeatureFlags()...)
	}
	sort.Strings(result)
	return result
}
