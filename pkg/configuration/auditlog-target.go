package configuration

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/engity-com/bifroest/pkg/template"
	"gopkg.in/yaml.v3"
)

var DefaultAuditlogTargetPublishAttemptTimeout = template.DurationOf(2 * time.Minute)

func effectiveAuditlogTargetPublishAttemptTimeout(value template.Duration) template.Duration {
	if value.IsZero() {
		return DefaultAuditlogTargetPublishAttemptTimeout
	}
	return value
}

func validateAuditlogTargetPublishAttemptTimeout(value template.Duration) error {
	value = effectiveAuditlogTargetPublishAttemptTimeout(value)
	if err := value.Validate(); err != nil {
		return err
	}
	if value.IsHardCoded() {
		rendered, err := value.Render(nil)
		if err != nil {
			return err
		}
		if rendered <= 0 {
			return fmt.Errorf("must be positive")
		}
	}
	return nil
}

func renderAuditlogTargetPublishAttemptTimeout(value template.Duration, data any) (time.Duration, error) {
	rendered, err := effectiveAuditlogTargetPublishAttemptTimeout(value).Render(data)
	if err != nil {
		return 0, err
	}
	if rendered <= 0 {
		return 0, fmt.Errorf("must be positive after rendering")
	}
	return rendered, nil
}

type AuditlogTarget struct {
	Name AuditlogTargetName `yaml:"name"`
	V    AuditlogTargetV    `yaml:"-"`
}

type AuditlogTargetV interface {
	defaulter
	trimmer
	validator
	equaler
	UnmarshalYAML(*yaml.Node) error
	Types() []string
	FeatureFlags() []string
}

var (
	typeToAuditlogTargetFactory = make(map[string]AuditlogTargetVFactory)
	auditlogTargetVs            []AuditlogTargetV
)

type AuditlogTargetVFactory func() AuditlogTargetV

// RegisterAuditlogTargetV registers a target configuration during package
// initialization. Type aliases are case-insensitive and must be unique.
func RegisterAuditlogTargetV(factory AuditlogTargetVFactory) AuditlogTargetVFactory {
	if factory == nil {
		panic("nil auditlog target configuration factory")
	}
	target := factory()
	if isNilAuditlogTargetV(target) {
		panic("auditlog target configuration factory returned nil")
	}
	types := target.Types()
	if len(types) == 0 {
		panic("auditlog target configuration does not provide any type")
	}
	keys := make([]string, 0, len(types))
	for _, targetType := range types {
		trimmed := strings.TrimSpace(targetType)
		if trimmed == "" || trimmed != targetType {
			panic(fmt.Sprintf("illegal auditlog target type %q", targetType))
		}
		key := strings.ToLower(targetType)
		if _, exists := typeToAuditlogTargetFactory[key]; exists {
			panic(fmt.Sprintf("duplicate auditlog target type %q", targetType))
		}
		for _, candidate := range keys {
			if candidate == key {
				panic(fmt.Sprintf("duplicate auditlog target type %q", targetType))
			}
		}
		keys = append(keys, key)
	}
	for _, key := range keys {
		typeToAuditlogTargetFactory[key] = factory
	}
	auditlogTargetVs = append(auditlogTargetVs, target)
	return factory
}

func (this *AuditlogTarget) SetDefaults() error {
	*this = AuditlogTarget{}
	return nil
}

func (this *AuditlogTarget) Trim() error {
	this.Name = AuditlogTargetName(strings.TrimSpace(this.Name.String()))
	if !isNilAuditlogTargetV(this.V) {
		if err := this.V.Trim(); err != nil {
			return err
		}
	}
	return this.Validate()
}

func (this *AuditlogTarget) Validate() error {
	if err := this.Name.Validate(); err != nil {
		return fmt.Errorf("[name] %w", err)
	}
	if isNilAuditlogTargetV(this.V) {
		return fmt.Errorf("[type] required but absent")
	}
	return this.V.Validate()
}

func (this *AuditlogTarget) UnmarshalYAML(node *yaml.Node) error {
	if err := this.SetDefaults(); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	if node.Kind != yaml.MappingNode {
		return reportYamlRelatedErrf(node, "auditlog target must be a mapping")
	}
	var common struct {
		Name string `yaml:"name"`
		Type string `yaml:"type"`
	}
	if err := node.Decode(&common); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	targetType := strings.TrimSpace(common.Type)
	if targetType == "" {
		return reportYamlRelatedErrf(node, "[type] required but absent")
	}
	factory, exists := typeToAuditlogTargetFactory[strings.ToLower(targetType)]
	if !exists {
		return reportYamlRelatedErrf(node, "[type] illegal type: %q", common.Type)
	}
	target := factory()
	if isNilAuditlogTargetV(target) {
		return reportYamlRelatedErrf(node, "[type] factory for %q returned nil", targetType)
	}
	specific := auditlogTargetSpecificNode(node)
	if err := specific.Decode(target); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	*this = AuditlogTarget{Name: AuditlogTargetName(common.Name), V: target}
	if err := this.Trim(); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	return nil
}

func auditlogTargetSpecificNode(node *yaml.Node) yaml.Node {
	result := *node
	result.Content = make([]*yaml.Node, 0, len(node.Content))
	for index := 0; index < len(node.Content); index += 2 {
		key := node.Content[index]
		if key.Value == "name" || key.Value == "type" {
			continue
		}
		result.Content = append(result.Content, key, node.Content[index+1])
	}
	return result
}

func (this AuditlogTarget) MarshalYAML() (any, error) {
	result := yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	result.Content = append(result.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "name"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: this.Name.String()},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "type"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str"},
	)
	if !isNilAuditlogTargetV(this.V) {
		if types := this.V.Types(); len(types) > 0 {
			result.Content[3].Value = types[0]
		}
		var specific yaml.Node
		if err := specific.Encode(this.V); err != nil {
			return nil, err
		}
		if specific.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("auditlog target type %q must encode as a mapping", result.Content[3].Value)
		}
		for index := 0; index < len(specific.Content); index += 2 {
			key := specific.Content[index]
			if key.Value == "name" || key.Value == "type" {
				return nil, fmt.Errorf("auditlog target type %q uses reserved field %q", result.Content[3].Value, key.Value)
			}
			result.Content = append(result.Content, key, specific.Content[index+1])
		}
	}
	return &result, nil
}

func (this AuditlogTarget) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch value := other.(type) {
	case AuditlogTarget:
		return this.isEqualTo(&value)
	case *AuditlogTarget:
		return value != nil && this.isEqualTo(value)
	default:
		return false
	}
}

func (this AuditlogTarget) isEqualTo(other *AuditlogTarget) bool {
	if this.Name != other.Name {
		return false
	}
	if isNilAuditlogTargetV(other.V) {
		return isNilAuditlogTargetV(this.V)
	}
	return !isNilAuditlogTargetV(this.V) && this.V.IsEqualTo(other.V)
}

func isNilAuditlogTargetV(target AuditlogTargetV) bool {
	if target == nil {
		return true
	}
	value := reflect.ValueOf(target)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

type AuditlogTargets []AuditlogTarget

func (this *AuditlogTargets) SetDefaults() error {
	*this = nil
	return nil
}

func (this *AuditlogTargets) Trim() error {
	if err := trimSlice(this); err != nil {
		return err
	}
	return this.validateUniqueNames()
}

func (this AuditlogTargets) Validate() error {
	if err := this.validateUniqueNames(); err != nil {
		return err
	}
	return validateSlice(this)
}

func (this AuditlogTargets) validateUniqueNames() error {
	indices := make(map[AuditlogTargetName]int, len(this))
	for index, target := range this {
		if previous, exists := indices[target.Name]; exists {
			return fmt.Errorf("[%d][name] duplicates [%d][name] %q", index, previous, target.Name)
		}
		indices[target.Name] = index
	}
	return nil
}

func (this AuditlogTargets) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch value := other.(type) {
	case AuditlogTargets:
		return this.isEqualTo(&value)
	case *AuditlogTargets:
		return value != nil && this.isEqualTo(value)
	default:
		return false
	}
}

func (this AuditlogTargets) isEqualTo(other *AuditlogTargets) bool {
	if len(this) != len(*other) {
		return false
	}
	for index, target := range this {
		if !target.IsEqualTo((*other)[index]) {
			return false
		}
	}
	return true
}

func GetSupportedAuditlogTargetFeatureFlags() []string {
	var result []string
	for _, target := range auditlogTargetVs {
		result = append(result, target.FeatureFlags()...)
	}
	sort.Strings(result)
	return result
}
