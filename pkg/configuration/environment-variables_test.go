package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestEnvironmentVariablesRender(t *testing.T) {
	var actual struct {
		Values EnvironmentVariables `yaml:"values"`
	}
	require.NoError(t, yaml.Unmarshal([]byte("values:\n  FIRST: one\n  SECOND: two\n"), &actual))
	require.NoError(t, actual.Values.Validate())

	rendered, err := actual.Values.Render(nil)
	require.NoError(t, err)
	require.Equal(t, "one", rendered["FIRST"])
	require.Equal(t, "two", rendered["SECOND"])
}

func TestEnvironmentVariablesRejectInvalidName(t *testing.T) {
	var actual struct {
		Values EnvironmentVariables `yaml:"values"`
	}
	require.NoError(t, yaml.Unmarshal([]byte("values:\n  INVALID-NAME: value\n"), &actual))
	require.Error(t, actual.Values.Validate())
}

func TestEnvironmentVariablesRejectNonAsciiName(t *testing.T) {
	actual := EnvironmentVariables{"KEY": {}}
	require.Error(t, actual.Validate())
}

func TestEnvironmentVariableName(t *testing.T) {
	require.NoError(t, EnvironmentVariableName("VALID_NAME_2").Validate())
	require.Error(t, EnvironmentVariableName("2_INVALID").Validate())
	require.Error(t, EnvironmentVariableName("INVALID-NAME").Validate())
}

func TestDummyEnvironmentRejectsVariables(t *testing.T) {
	var environment Environment
	err := yaml.Unmarshal([]byte("type: dummy\nvariables:\n  UNUSED: value\n"), &environment)
	require.ErrorContains(t, err, "not supported by environment type \"dummy\"")
}
