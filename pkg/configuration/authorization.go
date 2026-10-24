package configuration

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/template"
)

type Authorization struct {
	V         AuthorizationV
	Principal template.String
}

type AuthorizationV interface {
	defaulter
	trimmer
	validator
	equaler
	Types() []string
	FeatureFlags() []string
}

var (
	typeToAuthorizationFactory = make(map[string]AuthorizationVFactory)
	authorizationVs            []AuthorizationV
)

type AuthorizationVFactory func() AuthorizationV

func RegisterAuthorizationV(factory AuthorizationVFactory) AuthorizationVFactory {
	pt := factory()
	ts := pt.Types()
	if len(ts) == 0 {
		panic(fmt.Errorf("the instance does not provide any type"))
	}
	for _, t := range ts {
		typeToAuthorizationFactory[strings.ToLower(t)] = factory
	}
	authorizationVs = append(authorizationVs, pt)
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
	if err := this.Principal.Validate(); err != nil {
		return fmt.Errorf("[principal] %w", err)
	}
	if !this.Principal.IsZero() {
		if _, anonymous := this.V.(*AuthorizationNone); anonymous {
			return fmt.Errorf("[principal] cannot map an anonymous authorization to an authenticated principal")
		}
		if this.Principal.IsHardCoded() {
			if err := (authentication.Identity{Principal: this.Principal.String(), Issuer: "configuration", Subject: "configuration"}).Validate(); err != nil {
				return fmt.Errorf("[principal] %w", err)
			}
		}
	}
	if v := this.V; v != nil {
		return v.Validate()
	}
	return fmt.Errorf("required but absent")
}

func (this *Authorization) UnmarshalYAML(node *yaml.Node) error {
	var typeBuf struct {
		Type      string          `yaml:"type"`
		Principal template.String `yaml:"principal,omitempty"`
	}

	if err := node.Decode(&typeBuf); err != nil {
		return reportYamlRelatedErr(node, err)
	}

	if err := this.SetDefaults(); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	this.Principal = typeBuf.Principal

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

func (this Authorization) MarshalYAML() (any, error) {
	if this.V == nil {
		return struct{}{}, nil
	}
	var result yaml.Node
	if err := result.Encode(this.V); err != nil {
		return nil, err
	}
	if result.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("authorization %T does not encode as a mapping", this.V)
	}
	result.Content = append([]*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "type"},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: this.V.Types()[0]},
	}, result.Content...)
	if !this.Principal.IsZero() {
		result.Content = append(result.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "principal"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: this.Principal.String()},
		)
	}
	return &result, nil
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
	if other == nil || !this.Principal.IsEqualTo(other.Principal) {
		return false
	}
	if other.V == nil {
		return this.V == nil
	}
	return this.V != nil && this.V.IsEqualTo(other.V)
}

func GetSupportedAuthorizationFeatureFlags() []string {
	var result []string
	for _, v := range authorizationVs {
		result = append(result, v.FeatureFlags()...)
	}
	sort.Strings(result)
	return result
}
