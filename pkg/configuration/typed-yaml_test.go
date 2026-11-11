package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

func TestTypedConfigurationYAMLIncludesTypesForValuesAndPointers(t *testing.T) {
	authorization := Authorization{V: &AuthorizationSimple{}}
	environment := Environment{V: &EnvironmentDummy{}}
	for _, test := range []struct {
		name     string
		value    any
		typeName string
	}{
		{"authorization-value", authorization, "simple"},
		{"authorization-pointer", &authorization, "simple"},
		{"environment-value", environment, "dummy"},
		{"environment-pointer", &environment, "dummy"},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := yaml.Marshal(test.value)
			require.NoError(t, err)
			var properties map[string]any
			require.NoError(t, yaml.Unmarshal(encoded, &properties))
			require.Equal(t, test.typeName, properties["type"])
			require.NotContains(t, properties, "v")
		})
	}
}

func TestFlowYAMLRoundTripPreservesTypedFieldsAndMappings(t *testing.T) {
	var original Flow
	require.NoError(t, yaml.Unmarshal([]byte(`name: test
authorization:
  type: simple
  principal: '{{ .authorization.entry.name }}'
  entries:
    - name: alice
      password: plain:example
environment:
  type: ssh
  address: target.example.org:22
  user: alice
  acceptAllHostKeys: true
  variables:
    EXAMPLE: value
`), &original))
	for _, value := range []any{original, &original} {
		encoded, err := yaml.Marshal(value)
		require.NoError(t, err)
		var restored Flow
		require.NoError(t, yaml.Unmarshal(encoded, &restored), string(encoded))
		require.True(t, original.IsEqualTo(restored))
		require.True(t, restored.Authorization.Principal.IsEqualTo(template.MustNewString("{{ .authorization.entry.name }}")))
		require.Len(t, restored.Environment.Variables, 1)
	}
}
