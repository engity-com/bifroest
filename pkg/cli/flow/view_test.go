package flow

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestFlowDetailsRedactArbitraryStringsInEveryFormat(t *testing.T) {
	secret := "embedded-bearer-token"
	conf := &configuration.Configuration{Flows: configuration.Flows{{
		Name: "production", Auditlog: "default",
		Environment: configuration.Environment{
			V: &configuration.EnvironmentDocker{
				Image:           template.MustNewString("registry.example.org/team/" + secret),
				ImagePullPolicy: configuration.PullPolicyAlways,
				ShellCommand:    template.MustNewStrings("sh", "-c", "use "+secret),
			},
			Variables: configuration.EnvironmentVariables{"TOKEN": template.MustNewString(secret)},
		},
	}}}
	for _, selected := range []format.Format{format.Text, format.Json, format.Yaml, format.Cbor} {
		var output bytes.Buffer
		require.NoError(t, ShowFlow(&output, selected, conf, "production", false))
		require.NotContains(t, output.String(), secret)
		require.Contains(t, output.String(), "***redacted***")
		require.Contains(t, output.String(), "always")
	}
	var unredacted bytes.Buffer
	require.NoError(t, ShowFlow(&unredacted, format.Json, conf, "production", true))
	require.Contains(t, unredacted.String(), secret)
}

func TestFlowDetailsRedactNestedStructuralNames(t *testing.T) {
	extensions := configuration.EnvironmentSshCertificateExtensions{
		"name":     template.MustNewString("confidential-extension-name-value"),
		"type":     template.MustNewString("confidential-extension-type-value"),
		"auditlog": template.MustNewString("confidential-extension-auditlog-value"),
	}
	require.NoError(t, extensions.Validate())
	kubernetes := &configuration.EnvironmentKubernetes{}
	require.NoError(t, kubernetes.SetDefaults())
	kubernetes.Name = template.MustNewString("confidential-pod-name-value")
	for _, test := range []struct {
		name        string
		environment configuration.EnvironmentV
		secrets     []string
	}{
		{"ssh-extensions", &configuration.EnvironmentSsh{
			Certificate: &configuration.EnvironmentSshCertificate{Extensions: extensions},
		}, []string{"confidential-extension-name-value", "confidential-extension-type-value", "confidential-extension-auditlog-value"}},
		{"kubernetes-name", kubernetes, []string{"confidential-pod-name-value"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			conf := &configuration.Configuration{Flows: configuration.Flows{{
				Name: "production", Auditlog: "default",
				Authorization: configuration.Authorization{V: &configuration.AuthorizationSimple{}},
				Environment:   configuration.Environment{V: test.environment},
			}}}
			for _, selected := range []format.Format{format.Text, format.Json, format.Yaml, format.Cbor, format.WireCbor} {
				for _, disclose := range []bool{false, true, false} {
					var output bytes.Buffer
					require.NoError(t, ShowFlow(&output, selected, conf, "production", disclose))
					for _, secret := range test.secrets {
						if disclose {
							require.Contains(t, output.String(), secret)
						} else {
							require.NotContains(t, output.String(), secret)
						}
					}
				}
			}
			var output bytes.Buffer
			require.NoError(t, ShowFlow(&output, format.Json, conf, "production", false))
			var settings map[string]any
			require.NoError(t, json.Unmarshal(output.Bytes(), &settings))
			require.Equal(t, "production", settings["name"])
			require.Equal(t, "default", settings["auditlog"])
			require.Equal(t, "simple", settings["authorization"].(map[string]any)["type"])
			require.Equal(t, test.environment.Types()[0], settings["environment"].(map[string]any)["type"])
		})
	}
}

func TestFlowDetailsIncludeTransportSettingsWithoutWeakeningRedaction(t *testing.T) {
	no := false
	conf := &configuration.Configuration{Flows: configuration.Flows{{
		Name: "browser", DiscoverAsSlug: "servers/Example",
		Ssh: configuration.FlowSsh{Enabled: &no}, Http: configuration.FlowHttp{RequestUser: &no},
		Authorization: configuration.Authorization{V: &configuration.AuthorizationNone{}},
		Environment:   configuration.Environment{V: &configuration.EnvironmentDummy{}},
	}}}
	for _, includeCredentials := range []bool{false, true} {
		var output bytes.Buffer
		require.NoError(t, ShowFlow(&output, format.Json, conf, "browser", includeCredentials))
		var settings map[string]any
		require.NoError(t, json.Unmarshal(output.Bytes(), &settings))
		require.Equal(t, false, settings["ssh"].(map[string]any)["enabled"])
		require.Equal(t, false, settings["http"].(map[string]any)["requestUser"])
		if includeCredentials {
			require.Equal(t, "servers/Example", settings["discoverAsSlug"])
		} else {
			require.Equal(t, "***redacted***", settings["discoverAsSlug"])
		}
	}
}

func TestRedactSettingsDefaultsToNoPublicStrings(t *testing.T) {
	settings := map[string]any{
		"name": "private-name", "type": "private-type", "auditlog": "private-auditlog",
		"nested": map[string]any{"name": "private-nested-name"},
		"entries": []any{
			map[string]any{"type": "private-entry-type"},
			[]any{"private-string", map[string]any{"auditlog": "private-inner-auditlog"}},
		},
		"enabled": true, "count": 7,
	}
	RedactSettings(settings)
	encoded, err := json.Marshal(settings)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "private-")
	require.Equal(t, true, settings["enabled"])
	require.Equal(t, 7, settings["count"])
}

func TestRedactSettingsPublicPathsRequireExactFieldsAndSequences(t *testing.T) {
	settings := map[string]any{
		"name":               "production",
		"authorization.type": "private-dotted-key",
		"authorization": map[string]any{
			"type": "simple", "name": "private-authorization-name",
			"nested": map[string]any{"type": "private-nested-type"},
		},
		"targets": []any{
			map[string]any{
				"name": "archive", "type": "webdav",
				"options": map[string]any{"name": "private-option-name", "type": "private-option-type"},
			},
			[]any{map[string]any{"name": "private-extra-array-level"}},
		},
		"recording": map[string]any{
			"targets": map[string]any{"[]": map[string]any{"name": "private-fake-array"}},
		},
		"variables": map[string]any{"name": "private-variable"},
		"password":  "private-password",
	}
	RedactSettings(settings, "name", "authorization.type", "targets.[].name", "targets.[].type",
		"recording.targets.[].name", "variables.name", "password")
	encoded, err := json.Marshal(settings)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "private-")
	require.Equal(t, "production", settings["name"])
	require.Equal(t, "simple", settings["authorization"].(map[string]any)["type"])
	entry := settings["targets"].([]any)[0].(map[string]any)
	require.Equal(t, "archive", entry["name"])
	require.Equal(t, "webdav", entry["type"])
}
