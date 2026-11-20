package configuration

import "gopkg.in/yaml.v3"

// HttpComponent defaults to enabled, including in programmatic configurations.
type HttpComponent struct {
	Enabled *bool `yaml:"enabled,omitempty"`
}

func (this HttpComponent) IsEnabled() bool { return this.Enabled == nil || *this.Enabled }
func (this HttpComponent) IsEqualTo(other HttpComponent) bool {
	return this.IsEnabled() == other.IsEnabled()
}
func (this *HttpComponent) UnmarshalYAML(node *yaml.Node) error {
	type raw HttpComponent
	return decodeHttpFields(node, (*raw)(this), map[string]string{"enabled": "!!bool"})
}
