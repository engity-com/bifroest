package configuration

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

var _ = RegisterAuditlogTargetCodec(func() AuditlogTargetV {
	return &testAuditlogTarget{}
})

type testAuditlogTarget struct {
	Endpoint     string `yaml:"endpoint"`
	Required     string `yaml:"required,omitempty"`
	defaultCalls int    `yaml:"-"`
}

func (this *testAuditlogTarget) SetDefaults() error {
	this.defaultCalls++
	this.Endpoint = "default.example.invalid"
	return nil
}

func (this *testAuditlogTarget) Trim() error {
	this.Endpoint = strings.TrimSpace(this.Endpoint)
	this.Required = strings.TrimSpace(this.Required)
	return this.Validate()
}

func (this *testAuditlogTarget) Validate() error {
	if this.Endpoint == "" {
		return fmt.Errorf("[endpoint] required but absent")
	}
	return nil
}

func (this *testAuditlogTarget) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *testAuditlogTarget, node *yaml.Node) error {
		if err := rejectUnknownAuditlogFields(node, "endpoint", "required"); err != nil {
			return err
		}
		type raw testAuditlogTarget
		return node.Decode((*raw)(target))
	})
}

func (this testAuditlogTarget) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case testAuditlogTarget:
		return this.Endpoint == value.Endpoint && this.Required == value.Required
	case *testAuditlogTarget:
		return value != nil && this.Endpoint == value.Endpoint && this.Required == value.Required
	default:
		return false
	}
}

func (this testAuditlogTarget) Types() []string {
	return []string{"test-remote", "test-remote-alias"}
}

func (this testAuditlogTarget) FeatureFlags() []string {
	return []string{"test-remote-z", "test-remote-a"}
}

func TestAuditlogTargetsUnmarshalAndRoundTrip(t *testing.T) {
	var actual Auditlog
	require.NoError(t, yaml.Unmarshal([]byte(`
enabled: true
targets:
  - name: " archive "
    type: TEST-REMOTE-ALIAS
    endpoint: " https://archive.example.invalid/audit "
    required: parent-codec-specific
  - name: backup
    type: test-remote
`), &actual))
	require.Equal(t, AuditlogTargets{
		{Name: "archive", V: &testAuditlogTarget{Endpoint: "https://archive.example.invalid/audit", Required: "parent-codec-specific", defaultCalls: 1}},
		{Name: "backup", V: &testAuditlogTarget{Endpoint: "default.example.invalid", defaultCalls: 1}},
	}, actual.Targets)

	encoded, err := yaml.Marshal(actual)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "type: test-remote")
	require.NotContains(t, string(encoded), "test-remote-alias")
	var roundTripped Auditlog
	require.NoError(t, yaml.Unmarshal(encoded, &roundTripped))
	require.True(t, actual.IsEqualTo(roundTripped))
}

func TestAuditlogTargetsRejectInvalidConfigurations(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		expected string
	}{
		{"missing-name", "targets:\n  - type: test-remote\n", "illegal auditlog target name"},
		{"missing-type", "targets:\n  - name: archive\n", "[type] required but absent"},
		{"unknown-type", "targets:\n  - name: archive\n    type: missing\n", "illegal type"},
		{"unsafe-name", "targets:\n  - name: ../archive\n    type: test-remote\n", "illegal auditlog target name"},
		{"missing-value", "targets:\n  - name: archive\n    type: test-remote\n    endpoint: ' '\n", "[endpoint] required but absent"},
		{"unknown-field", "targets:\n  - name: archive\n    type: test-remote\n    unknown: true\n", "field unknown not found"},
		{"duplicate-name", "targets:\n  - name: archive\n    type: test-remote\n  - name: archive\n    type: test-remote\n", "duplicates"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var actual Auditlog
			err := yaml.Unmarshal([]byte(test.yaml), &actual)
			require.ErrorContains(t, err, test.expected)
		})
	}
}

func TestAuditlogTargetNamesAndFeatureFlags(t *testing.T) {
	require.NoError(t, AuditlogTargetName("archive.eu-1").Validate())
	for _, invalid := range []AuditlogTargetName{"", ".", "..", "a/b", `a\b`, "has space", AuditlogTargetName(strings.Repeat("a", maximumAuditlogTargetNameLength+1))} {
		require.Error(t, invalid.Validate(), invalid)
	}
	flags := GetSupportedAuditlogTargetFeatureFlags()
	require.True(t, sort.StringsAreSorted(flags))
	require.Subset(t, flags, []string{"test-remote-a", "test-remote-z"})
}

func TestAuditlogEqualityIncludesTargets(t *testing.T) {
	left := Auditlog{
		Name:         "log",
		IdentityFile: "identity",
		Journal:      AuditlogJournal{Directory: "journal"},
		Targets:      AuditlogTargets{{Name: "archive", V: &testAuditlogTarget{Endpoint: "one"}}},
	}
	right := left
	right.Targets = AuditlogTargets{{Name: "archive", V: &testAuditlogTarget{Endpoint: "two"}}}
	require.False(t, left.IsEqualTo(right))
	right.Targets = AuditlogTargets{{Name: "archive", V: &testAuditlogTarget{Endpoint: "one"}}}
	require.True(t, left.IsEqualTo(right))
}
