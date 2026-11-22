package configuration

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/management/access"
)

var _ = RegisterEnvironmentV(func() EnvironmentV { return &EnvironmentManagement{} })

// EnvironmentManagement makes the management commands available to
// an explicitly authorized management flow over SSH or HTTP.
type EnvironmentManagement struct {
	Access access.Policy `yaml:"access"`
}

func (this *EnvironmentManagement) SetDefaults() error {
	*this = EnvironmentManagement{}
	return nil
}

func (this *EnvironmentManagement) Trim() error {
	return this.Validate()
}

func (this *EnvironmentManagement) Validate() error {
	return nil
}

func (this *EnvironmentManagement) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *EnvironmentManagement, node *yaml.Node) error {
		if err := rejectUnknownAuditlogFields(node, "type", "variables", "access"); err != nil {
			return err
		}
		fields, err := effectiveHttpFields(node)
		if err != nil {
			return err
		}
		type raw EnvironmentManagement
		if err := node.Decode((*raw)(target)); err != nil {
			return err
		}
		if value, present := fields["access"]; present {
			if err := target.Access.UnmarshalYAML(&value); err != nil {
				return fmt.Errorf("[access] %w", err)
			}
		}
		return nil
	})
}

func (this EnvironmentManagement) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case EnvironmentManagement:
		return this.Access.IsEqualTo(value.Access)
	case *EnvironmentManagement:
		return value != nil && this.Access.IsEqualTo(value.Access)
	default:
		return false
	}
}

func (this EnvironmentManagement) Types() []string { return []string{"management"} }

func (this EnvironmentManagement) FeatureFlags() []string { return []string{"management"} }
