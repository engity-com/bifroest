package management

import (
	"bytes"
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestFlowCommandsRedactCredentialsInAllFormats(t *testing.T) {
	conf := &configuration.Configuration{Flows: configuration.Flows{{
		Name: "production", Auditlog: "default",
		Authorization: configuration.Authorization{V: &configuration.AuthorizationNone{}},
		Environment: configuration.Environment{
			V:         &configuration.EnvironmentDocker{ImagePullCredentials: template.MustNewString("REGISTRY_SECRET")},
			Variables: configuration.EnvironmentVariables{"AUTH_TOKEN": template.MustNewString("ENV_SECRET")},
		},
	}}}
	for _, format := range []Format{FormatTable, FormatJSON, FormatYAML} {
		t.Run(string(format), func(t *testing.T) {
			for _, includeCredentials := range []bool{false, true} {
				var output bytes.Buffer
				app := kingpin.New("bifroest", "test").Terminate(func(int) {})
				RegisterFlowCommands(app, func(path string) (*configuration.Configuration, error) {
					require.Empty(t, path)
					return conf, nil
				}, &output, includeCredentials, false)
				_, err := app.Parse([]string{"flow", "show", "production", "--format=" + string(format)})
				require.NoError(t, err)
				if includeCredentials {
					require.Contains(t, output.String(), "REGISTRY_SECRET")
					require.Contains(t, output.String(), "ENV_SECRET")
				} else {
					require.NotContains(t, output.String(), "REGISTRY_SECRET")
					require.NotContains(t, output.String(), "ENV_SECRET")
					require.Contains(t, output.String(), "***redacted***")
				}
				require.Contains(t, output.String(), "production")
			}
		})
	}
	var output bytes.Buffer
	require.NoError(t, ListFlows(&output, FormatTable, conf))
	require.True(t, strings.HasPrefix(output.String(), "NAME"))
	require.Contains(t, output.String(), "production")
	require.ErrorContains(t, ShowFlow(&output, FormatJSON, conf, "missing", false), "does not exist")
}

func TestFlowRedactionHandlesNestedEntries(t *testing.T) {
	settings := map[string]any{
		"authorization": map[string]any{"entries": []any{map[string]any{"passwordFile": "PRIVATE_FILE", "name": "alice"}}},
		"environment":   map[string]any{"imagePullCredentials": "PULL_SECRET", "image": "alpine", "arguments": []any{[]any{"EMBEDDED_SECRET"}}},
	}
	redactFlowSettings(settings)
	value := settings["authorization"].(map[string]any)["entries"].([]any)[0].(map[string]any)
	require.Equal(t, "***redacted***", value["passwordFile"])
	require.Equal(t, "alice", value["name"])
	require.Equal(t, "***redacted***", settings["environment"].(map[string]any)["imagePullCredentials"])
	require.Equal(t, "***redacted***", settings["environment"].(map[string]any)["image"])
	require.Equal(t, "***redacted***", settings["environment"].(map[string]any)["arguments"].([]any)[0].([]any)[0])
	var output bytes.Buffer
	require.NoError(t, WriteFlowSettings(&output, FormatTable, settings))
	require.Contains(t, output.String(), "authorization.entries[0].passwordFile")
	require.Contains(t, output.String(), "authorization.entries[0].name")
	require.NotContains(t, output.String(), "PRIVATE_FILE")
}

func TestFlowShowRedactsConfiguredSimplePassword(t *testing.T) {
	var conf configuration.Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(`
flows:
  - name: demonstration
    authorization:
      type: simple
      entries:
        - name: bob
          password: plain:super-secret-password
    environment:
      type: dummy
`), "flow-with-password.yaml"))
	var output bytes.Buffer
	require.NoError(t, ShowFlow(&output, FormatJSON, &conf, "demonstration", false))
	require.NotContains(t, output.String(), "super-secret-password")
	require.Contains(t, output.String(), "***redacted***")
	output.Reset()
	require.NoError(t, ShowFlow(&output, FormatJSON, &conf, "demonstration", true))
	require.Contains(t, output.String(), "super-secret-password")
}

func TestFlowShowRedactsEmbeddedSecretsInCommandsAndStrings(t *testing.T) {
	secret := "review-embedded-token-1234"
	conf := &configuration.Configuration{Flows: configuration.Flows{{
		Name: "production", Auditlog: "default",
		Authorization: configuration.Authorization{V: &configuration.AuthorizationNone{}},
		Environment: configuration.Environment{V: &configuration.EnvironmentDocker{
			Image:           template.MustNewString("alpine"),
			ImagePullPolicy: configuration.PullPolicyAlways,
			ShellCommand:    template.MustNewStrings("sh", "-c", "curl -H 'Authorization: Bearer "+secret+"' https://example.invalid"),
		}},
	}}}
	for _, format := range []Format{FormatTable, FormatJSON, FormatYAML} {
		var output bytes.Buffer
		require.NoError(t, ShowFlow(&output, format, conf, "production", false))
		require.NotContains(t, output.String(), secret)
		require.Contains(t, output.String(), "alpine")
		require.Contains(t, output.String(), "always")
		require.Contains(t, output.String(), "***redacted***")
		require.Contains(t, output.String(), "production")
		output.Reset()
		require.NoError(t, ShowFlow(&output, format, conf, "production", true))
		require.Contains(t, output.String(), secret)
	}
}

func TestFlowShowDoesNotExposeUnvalidatedImageStrings(t *testing.T) {
	for _, image := range []string{"https://admin:secret@registry.example.org/private", "{{ .token }}"} {
		conf := &configuration.Configuration{Flows: configuration.Flows{{
			Name: "production", Environment: configuration.Environment{V: &configuration.EnvironmentDocker{Image: template.MustNewString(image)}},
		}}}
		for _, format := range []Format{FormatTable, FormatJSON, FormatYAML} {
			var output bytes.Buffer
			require.NoError(t, ShowFlow(&output, format, conf, "production", false))
			require.NotContains(t, output.String(), image)
			require.Contains(t, output.String(), "***redacted***")
		}
	}
}

func TestFlowShowKeepsValidatedKubernetesImageMetadata(t *testing.T) {
	conf := &configuration.Configuration{Flows: configuration.Flows{{
		Name: "production", Environment: configuration.Environment{V: &configuration.EnvironmentKubernetes{
			Os: sys.OsLinux, Arch: sys.ArchAmd64, Image: template.MustNewString("registry.example.org/team/service:1.2.3"), ImagePullPolicy: configuration.PullPolicyNever,
		}},
	}}}
	var output bytes.Buffer
	require.NoError(t, ShowFlow(&output, FormatJSON, conf, "production", false))
	require.Contains(t, output.String(), "registry.example.org/team/service:1.2.3")
	require.Contains(t, output.String(), "never")
}
