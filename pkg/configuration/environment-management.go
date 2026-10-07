package configuration

import "gopkg.in/yaml.v3"

var _ = RegisterEnvironmentV(func() EnvironmentV { return &EnvironmentManagement{} })

// EnvironmentManagement makes the read-only management commands available to
// an explicitly authorized SSH flow.
type EnvironmentManagement struct {
	IncludingCredentials  bool `yaml:"includingCredentials,omitempty"`
	AllowArtifactTransfer bool `yaml:"allowArtifactTransfer,omitempty"`
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
		if err := rejectUnknownAuditlogFields(node, "type", "variables", "includingCredentials", "allowArtifactTransfer"); err != nil {
			return err
		}
		type raw EnvironmentManagement
		return node.Decode((*raw)(target))
	})
}

func (this EnvironmentManagement) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case EnvironmentManagement:
		return this.IncludingCredentials == value.IncludingCredentials && this.AllowArtifactTransfer == value.AllowArtifactTransfer
	case *EnvironmentManagement:
		return value != nil && this.IncludingCredentials == value.IncludingCredentials && this.AllowArtifactTransfer == value.AllowArtifactTransfer
	default:
		return false
	}
}

func (this EnvironmentManagement) Types() []string { return []string{"management"} }

func (this EnvironmentManagement) FeatureFlags() []string { return []string{"management"} }
