package configuration

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

// An absent switch means enabled, including for programmatically constructed
// configurations that have never passed through the YAML defaults machinery.
type FlowSsh struct {
	Enabled *bool `yaml:"enabled,omitempty"`
}

func (this FlowSsh) IsEnabled() bool { return this.Enabled == nil || *this.Enabled }
func (this FlowSsh) IsZero() bool    { return this.Enabled == nil }
func (this *FlowSsh) SetDefaults() error {
	*this = FlowSsh{}
	return nil
}
func (this *FlowSsh) Trim() error { return this.Validate() }
func (*FlowSsh) Validate() error  { return nil }
func (this *FlowSsh) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *FlowSsh, node *yaml.Node) error {
		if err := validateFlowTransportFields(node, "enabled"); err != nil {
			return err
		}
		type raw FlowSsh
		return node.Decode((*raw)(target))
	})
}
func (this FlowSsh) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case FlowSsh:
		return this.IsEnabled() == value.IsEnabled()
	case *FlowSsh:
		return value != nil && this.IsEnabled() == value.IsEnabled()
	default:
		return false
	}
}

type FlowHttp struct {
	Enabled     *bool                                                                      `yaml:"enabled,omitempty"`
	RequestUser *bool                                                                      `yaml:"requestUser,omitempty"`
	KeepAlive   template.Enforceable[template.Duration, time.Duration, *template.Duration] `yaml:"keepAlive,omitempty"`
}

func (this FlowHttp) IsEnabled() bool          { return this.Enabled == nil || *this.Enabled }
func (this FlowHttp) RequestUserEnabled() bool { return this.RequestUser == nil || *this.RequestUser }
func (this FlowHttp) IsZero() bool {
	return this.Enabled == nil && this.RequestUser == nil && this.KeepAlive.IsZero()
}
func (this *FlowHttp) SetDefaults() error {
	*this = FlowHttp{}
	return nil
}
func (this *FlowHttp) Trim() error { return this.Validate() }
func (this *FlowHttp) Validate() error {
	if this.KeepAlive.IsHardCoded() {
		_, err := this.ResolveKeepAlive(nil)
		return err
	}
	return nil
}
func (this *FlowHttp) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *FlowHttp, node *yaml.Node) error {
		if err := validateFlowTransportFields(node, "enabled", "requestUser", "keepAlive"); err != nil {
			return err
		}
		type raw FlowHttp
		return node.Decode((*raw)(target))
	})
}
func (this FlowHttp) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case FlowHttp:
		return this.IsEnabled() == value.IsEnabled() && this.RequestUserEnabled() == value.RequestUserEnabled() && this.KeepAlive.IsEqualTo(value.KeepAlive)
	case *FlowHttp:
		return value != nil && this.IsEnabled() == value.IsEnabled() && this.RequestUserEnabled() == value.RequestUserEnabled() && this.KeepAlive.IsEqualTo(value.KeepAlive)
	default:
		return false
	}
}

func validateFlowTransportFields(node *yaml.Node, known ...string) error {
	if err := rejectUnknownAuditlogFields(node, known...); err != nil {
		return err
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		value := node.Content[index+1]
		if value.Kind == yaml.AliasNode && value.Alias != nil {
			value = value.Alias
		}
		if node.Content[index].Value == "keepAlive" {
			if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
				return fmt.Errorf("[keepAlive] must be a string")
			}
			continue
		}
		if value.Tag != "!!bool" {
			return fmt.Errorf("[%s] must be a boolean", node.Content[index].Value)
		}
	}
	return nil
}
