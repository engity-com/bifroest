package configuration

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

const referenceTestDefaults = `environments:
  default: {type: dummy, banner: root-environment}
authorizations:
  default: {type: none}
`

const referenceTestInlineFlow = `flows:
  - name: inline
    environment: {type: dummy}
    authorization: {type: none}
`

func TestEnvironmentDefinitionsPreserveProviderNameFields(t *testing.T) {
	for _, kind := range []string{"local", "kubernetes"} {
		t.Run(kind, func(t *testing.T) {
			source := "environments:\n  default: {type: " + kind + ", name: provider-target}\n  named: {type: " + kind + ", name: other-target}\nauthorizations:\n  default: {type: none}\nflows:\n  - name: implicit\n  - name: explicit\n    environment: named\n"
			var conf Configuration
			require.NoError(t, conf.LoadFromYaml(strings.NewReader(source), ""))
			for index, target := range []string{"provider-target", "other-target"} {
				encoded, err := yaml.Marshal(conf.Flows[index].Environment.V)
				require.NoError(t, err)
				var fields map[string]yaml.Node
				require.NoError(t, yaml.Unmarshal(encoded, &fields))
				require.Equal(t, target, fields["name"].Value, "provider target names are not definition identities")
			}
			encoded, err := yaml.Marshal(conf)
			require.NoError(t, err)
			var restored Configuration
			require.NoError(t, restored.LoadFromYaml(strings.NewReader(string(encoded)), ""))
			require.True(t, conf.IsEqualTo(restored))
			for _, key := range []string{"default", "named"} {
				require.NotSame(t, conf.Environments[key].V, restored.Environments[key].V)
			}
		})
	}
}

func TestConfigurationReferenceDefaults(t *testing.T) {
	for _, value := range []string{"", "null", "''", "default"} {
		for _, field := range []string{"environment", "authorization", "auditlog"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				source := referenceTestDefaults + "auditlogs:\n  default: {}\nflows:\n  - name: first\n"
				if value != "" {
					source += "    " + field + ": " + value + "\n"
				}
				var conf Configuration
				require.NoError(t, conf.LoadFromYaml(strings.NewReader(source), ""))
				require.Len(t, conf.Environments, 1)
				require.Len(t, conf.Authorizations, 1)
				require.Len(t, conf.Auditlogs, 1)
				flow := conf.Flows[0]
				require.Equal(t, DefaultAuditlogName, flow.Auditlog)
				require.IsType(t, &AuthorizationNone{}, flow.Authorization.V)
				require.Equal(t, "root-environment", flow.Environment.V.(*EnvironmentDummy).Banner.String())
				encoded, err := yaml.Marshal(conf)
				require.NoError(t, err)
				var restored Configuration
				require.NoError(t, restored.LoadFromYaml(strings.NewReader(string(encoded)), ""), string(encoded))
				require.True(t, conf.IsEqualTo(restored))
			})
		}
	}
}

func TestConfigurationNoImplicitRootDefinitionsOrAuditlogging(t *testing.T) {
	var defaults Configuration
	require.NoError(t, defaults.SetDefaults())
	require.Empty(t, defaults.Environments)
	require.Empty(t, defaults.Authorizations)
	require.Empty(t, defaults.Auditlogs)
	for _, value := range []string{"", "null", "''"} {
		var conf Configuration
		source := referenceTestInlineFlow
		if value != "" {
			source += "    auditlog: " + value + "\n"
		}
		require.NoError(t, conf.LoadFromYaml(strings.NewReader(source), ""))
		require.Empty(t, conf.Auditlogs)
		require.Empty(t, conf.Flows[0].Auditlog)
		require.NoError(t, conf.Trim())
		require.Empty(t, conf.Auditlogs)
		require.Empty(t, conf.Flows[0].Auditlog)
	}
	var conf Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader("auditlogs: {other: {}}\n"+referenceTestInlineFlow), ""))
	require.Empty(t, conf.Flows[0].Auditlog, "a non-default definition does not enable logging for a flow")
}

func TestConfigurationRequiredValuesDoNotFallBackWithoutDefault(t *testing.T) {
	for _, field := range []string{"environment", "authorization"} {
		for _, value := range []string{"", "null", "''"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				source := referenceTestInlineFlow
				line := "    " + field + ": {type: dummy}\n"
				if field == "authorization" {
					line = "    authorization: {type: none}\n"
				}
				replacement := ""
				if value != "" {
					replacement = "    " + field + ": " + value + "\n"
				}
				source = strings.Replace(source, line, replacement, 1)
				var conf Configuration
				require.ErrorContains(t, conf.LoadFromYaml(strings.NewReader(source), ""), "["+field+"] required but absent")
			})
		}
	}
}

func TestConfigurationRejectsUnknownReferencesDespiteDefaults(t *testing.T) {
	for _, field := range []string{"environment", "authorization", "auditlog"} {
		t.Run(field, func(t *testing.T) {
			source := referenceTestDefaults + "auditlogs: {default: {}}\nflows:\n  - name: first\n    " + field + ": missing\n"
			var conf Configuration
			require.ErrorContains(t, conf.LoadFromYaml(strings.NewReader(source), ""), "references unknown "+field+` "missing"`)
		})
	}
}

func TestConfigurationInvalidInlineValuesNeverUseDefaults(t *testing.T) {
	for _, field := range []string{"environment", "authorization"} {
		for _, value := range []string{"{}", "{type: unknown}", "[]", "[default]", "[{}, {}]", "true", "1"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				var conf Configuration
				source := referenceTestDefaults + "flows:\n  - name: first\n    " + field + ": " + value
				require.Error(t, conf.LoadFromYaml(strings.NewReader(source), ""))
			})
		}
	}
	var conf Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(referenceTestDefaults+referenceTestInlineFlow), ""))
	require.True(t, conf.Flows[0].Environment.V.(*EnvironmentDummy).Banner.IsZero(), "valid inline values override defaults")
}

func TestConfigurationRootDefinitionShapeAndNamesAreStrict(t *testing.T) {
	for _, field := range []string{"environments", "authorizations", "auditlogs"} {
		for _, value := range []string{
			"[]", "null", "default", "{entry: null}", "{entry: default}", "{entry: []}",
			"{'': {}}", "{'  ': {}}", "{entry: {name: entry}}", "{entry: {name: null}}",
			"{entry: {<<: {name: entry}}}",
		} {
			t.Run(field+"/"+value, func(t *testing.T) {
				var conf Configuration
				require.Error(t, conf.LoadFromYaml(strings.NewReader(field+": "+value+"\n"+referenceTestInlineFlow), ""))
			})
		}
	}
	for _, source := range []string{
		"auditlog: {}", "auditlog: []", "auditlog: null",
		"auditlogs: [{name: default}]",
		"environments: {entry: {type: dummy, name: other}}",
		"authorizations: {entry: {type: none, name: other}}",
		"auditlogs: {entry: {enabled: false}}", "auditlogs: {entry: {enabled: true}}",
		"auditlogs: {entry: {enabled: null}}", "auditlogs: {entry: {<<: {enabled: true}}}",
	} {
		t.Run(source, func(t *testing.T) {
			var conf Configuration
			require.Error(t, conf.LoadFromYaml(strings.NewReader(source+"\n"+referenceTestInlineFlow), ""))
		})
	}
}

func TestConfigurationValidatesUnusedDefinitions(t *testing.T) {
	for _, source := range []string{
		"environments: {unused: {type: ssh}}",
		"authorizations: {unused: {type: oidcDeviceAuth}}",
		"auditlogs: {unused: {identityFile: ''}}",
	} {
		var conf Configuration
		require.Error(t, conf.LoadFromYaml(strings.NewReader(source+"\n"+referenceTestInlineFlow), ""))
	}
}

func TestConfigurationRejectsDuplicateKeysAndUnknownFields(t *testing.T) {
	for _, source := range []string{
		"environments: {}\nenvironments: {}",
		"environments: {entry: {type: dummy}, entry: {type: dummy}}",
		"authorizations: {entry: {type: none}, entry: {type: none}}",
		"auditlogs: {entry: {}, entry: {}}",
		"environments: {entry: {type: dummy, type: dummy}}",
		"authorizations: {entry: {type: none, type: none}}",
		"auditlogs: {entry: {directory: a, directory: b}}",
		"unknown: true",
		"environments: {entry: {type: dummy, unknown: true}}",
		"authorizations: {entry: {type: none, unknown: true}}",
		"auditlogs: {entry: {unknown: true}}",
		"environments: {entry: {type: dummy, <<: {unknown: true}}}",
		"authorizations: {entry: {type: none, <<: {unknown: true}}}",
		"auditlogs: {entry: {<<: {unknown: true}}}",
		"flows: [{name: first, environment: {type: dummy}, authorization: {type: none}, unknown: true}]",
		"flows: [{name: first, environment: {type: dummy, unknown: true}, authorization: {type: none}}]",
		"flows: [{name: first, environment: {type: dummy}, authorization: {type: none, unknown: true}}]",
		"flows: [{name: first, environment: {type: dummy}, authorization: {type: none}, environment: {type: dummy}}]",
	} {
		t.Run(source, func(t *testing.T) {
			if !strings.HasPrefix(source, "flows:") {
				source += "\n" + referenceTestInlineFlow
			}
			var conf Configuration
			require.Error(t, conf.LoadFromYaml(strings.NewReader(source), ""))
		})
	}
}

func TestConfigurationReferenceMarshalPreservesDeclarationAndSecrets(t *testing.T) {
	var conf Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(`authorizations:
  shared:
    type: simple
    principal: '{{ .authorization.entry.name }}'
    entries: [{name: alice, password: 'plain:secret-only-in-definition'}]
environments:
  shared:
    type: ssh
    address: target.example.org:22
    user: alice
    acceptAllHostKeys: true
    variables: {TOKEN: secret-environment-only-in-definition}
auditlogs:
  z: {identityFile: z-key, directory: z-journal}
  a: {identityFile: a-key, directory: a-journal}
flows:
  - name: first
    environment: shared
    authorization: shared
    auditlog: a
  - name: second
    environment: shared
    authorization: shared
`), ""))
	require.Equal(t, AuditlogName("a"), conf.Auditlogs[0].Name)
	require.Equal(t, AuditlogName("z"), conf.Auditlogs[1].Name)
	encoded, err := yaml.Marshal(conf)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(encoded), "secret-only-in-definition"))
	require.Equal(t, 1, strings.Count(string(encoded), "secret-environment-only-in-definition"))
	var fields map[string]yaml.Node
	require.NoError(t, yaml.Unmarshal(encoded, &fields))
	require.Equal(t, yaml.MappingNode, fields["auditlogs"].Kind)
	require.NotContains(t, fields, "auditlog")
	flows := fields["flows"]
	for _, node := range flows.Content {
		var flowFields map[string]yaml.Node
		require.NoError(t, node.Decode(&flowFields))
		require.Equal(t, "shared", flowFields["authorization"].Value)
		require.Equal(t, "shared", flowFields["environment"].Value)
	}
	var restored Configuration
	require.NoError(t, restored.LoadFromYaml(strings.NewReader(string(encoded)), ""), string(encoded))
	require.True(t, conf.IsEqualTo(restored))
	first, second := &conf.Flows[0], &conf.Flows[1]
	require.NotSame(t, first.Authorization.V, second.Authorization.V)
	require.NotSame(t, first.Environment.V, second.Environment.V)
	first.Authorization.V.(*AuthorizationSimple).Entries[0].Name = "changed"
	require.Equal(t, "alice", second.Authorization.V.(*AuthorizationSimple).Entries[0].Name)
	require.Equal(t, "alice", conf.Authorizations["shared"].V.(*AuthorizationSimple).Entries[0].Name)
	first.Environment.Variables["TOKEN"] = template.MustNewString("changed")
	require.Equal(t, "secret-environment-only-in-definition", second.Environment.Variables["TOKEN"].String())
	require.Equal(t, "secret-environment-only-in-definition", conf.Environments["shared"].Variables["TOKEN"].String())
}

func TestConfigurationProgrammaticReferencesAndDefaultChanges(t *testing.T) {
	var conf Configuration
	require.NoError(t, conf.SetDefaults())
	conf.Environments = Environments{"default": {V: &EnvironmentDummy{}}, "named": {V: &EnvironmentDummy{}}}
	conf.Authorizations = Authorizations{"default": {V: &AuthorizationNone{}}, "named": {V: &AuthorizationNone{}}}
	conf.Flows = Flows{{Name: "default"}, {Name: "reference", Environment: Environment{Reference: "named"}, Authorization: Authorization{Reference: "named"}}}
	require.NoError(t, conf.Validate())
	require.NoError(t, conf.Trim())
	require.Empty(t, conf.Auditlogs)
	require.Empty(t, conf.Flows[0].Auditlog)
	conf.Environments["default"] = Environment{V: &EnvironmentDummy{Banner: template.MustNewString("changed-default")}}
	require.NoError(t, conf.Validate())
	require.Equal(t, "changed-default", conf.Flows[0].Environment.V.(*EnvironmentDummy).Banner.String())
	require.True(t, conf.Flows[1].Environment.V.(*EnvironmentDummy).Banner.IsZero())
	var auditlog Auditlog
	require.NoError(t, auditlog.SetDefaults())
	conf.Auditlogs = Auditlogs{auditlog}
	require.NoError(t, conf.Validate())
	require.Equal(t, DefaultAuditlogName, conf.Flows[0].Auditlog)
	conf.Auditlogs = nil
	require.NoError(t, conf.Validate())
	require.Empty(t, conf.Flows[0].Auditlog, "removing a default must not turn it into an explicit reference")
	delete(conf.Environments, "default")
	require.ErrorContains(t, conf.Validate(), "[environment] required but absent")
}

func TestConfigurationProgrammaticInvalidDefinitionsAndReferences(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Configuration)
	}{
		{"unused-environment", func(conf *Configuration) { conf.Environments["unused"] = Environment{V: &EnvironmentSsh{}} }},
		{"unused-authorization", func(conf *Configuration) {
			conf.Authorizations["unused"] = Authorization{V: &AuthorizationOidcDeviceAuth{}}
		}},
		{"empty-environment-name", func(conf *Configuration) { conf.Environments[""] = Environment{V: &EnvironmentDummy{}} }},
		{"empty-authorization-name", func(conf *Configuration) { conf.Authorizations[""] = Authorization{V: &AuthorizationNone{}} }},
		{"environment-chain", func(conf *Configuration) { conf.Environments["chain"] = Environment{Reference: "default"} }},
		{"authorization-chain", func(conf *Configuration) { conf.Authorizations["chain"] = Authorization{Reference: "default"} }},
		{"unknown-environment", func(conf *Configuration) { conf.Flows[0].Environment = Environment{Reference: "unknown"} }},
		{"unknown-authorization", func(conf *Configuration) { conf.Flows[0].Authorization = Authorization{Reference: "unknown"} }},
		{"unknown-auditlog", func(conf *Configuration) { conf.Flows[0].Auditlog = "unknown" }},
		{"invalid-inline-environment", func(conf *Configuration) { conf.Flows[0].Environment = Environment{V: &EnvironmentSsh{}} }},
		{"invalid-inline-authorization", func(conf *Configuration) {
			conf.Flows[0].Authorization = Authorization{V: &AuthorizationOidcDeviceAuth{}}
		}},
		{"untyped-inline-environment", func(conf *Configuration) {
			conf.Flows[0].Environment = Environment{Variables: EnvironmentVariables{"TOKEN": template.MustNewString("value")}}
		}},
		{"untyped-inline-authorization", func(conf *Configuration) {
			conf.Flows[0].Authorization = Authorization{Principal: template.MustNewString("alice")}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var conf Configuration
			require.NoError(t, conf.LoadFromYaml(strings.NewReader(referenceTestDefaults+referenceTestInlineFlow), ""))
			test.change(&conf)
			require.Error(t, conf.Validate())
		})
	}
}

func TestConfigurationAuditlogReferencesRequireStrings(t *testing.T) {
	for _, value := range []string{"true", "1", "[]", "{}"} {
		var conf Configuration
		source := fmt.Sprintf("auditlogs: {'true': {}, '1': {identityFile: other-key, directory: other-journal}}\n%s    auditlog: %s\n", referenceTestInlineFlow, value)
		require.ErrorContains(t, conf.LoadFromYaml(strings.NewReader(source), ""), "[auditlog] must be a string reference")
	}
}

func TestConfigurationEqualityPreservesReferenceDeclarations(t *testing.T) {
	load := func(flow string) Configuration {
		var conf Configuration
		require.NoError(t, conf.LoadFromYaml(strings.NewReader(referenceTestDefaults+"auditlogs: {default: {}}\n"+flow), ""))
		return conf
	}
	implicit := load("flows: [{name: first}]\n")
	explicit := load("flows: [{name: first, environment: default, authorization: default, auditlog: default}]\n")
	require.False(t, implicit.IsEqualTo(explicit))
	inline := load("flows: [{name: first, environment: {type: dummy, banner: root-environment}, authorization: {type: none}}]\n")
	require.False(t, implicit.Flows[0].Environment.IsEqualTo(inline.Flows[0].Environment))
	require.False(t, implicit.Flows[0].Authorization.IsEqualTo(inline.Flows[0].Authorization))
	require.False(t, implicit.IsEqualTo(inline))
}

func TestConfigurationAuditlogsMapRoundTripPreservesZeroReserveAndOrdering(t *testing.T) {
	var original Auditlogs
	require.NoError(t, yaml.Unmarshal([]byte(`z: {identityFile: z-key, directory: z-journal, minimumFreeBytes: 0}
a: {identityFile: a-key, directory: a-journal}
`), &original))
	require.Equal(t, AuditlogName("a"), original[0].Name)
	require.Equal(t, uint64(0), original[1].MinimumFreeBytes)
	reversed := Auditlogs{original[1], original[0]}
	require.True(t, original.IsEqualTo(reversed), "identity is the map key, not slice position")
	encoded, err := yaml.Marshal(reversed)
	require.NoError(t, err)
	var restored Auditlogs
	require.NoError(t, yaml.Unmarshal(encoded, &restored))
	require.True(t, original.IsEqualTo(restored))
	require.Equal(t, AuditlogName("a"), restored[0].Name)
	require.NoError(t, reversed.Trim())
	require.Equal(t, AuditlogName("a"), reversed[0].Name)
	restored[0].Name = ""
	require.ErrorContains(t, restored.Validate(), "illegal auditlog name")
	_, err = yaml.Marshal(restored)
	require.Error(t, err)
}

func TestConfigurationFailedReferenceLoadIsTransactional(t *testing.T) {
	var conf Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(referenceTestDefaults+"flows: [{name: first}]"), "original.yaml"))
	previous := cloneConfigurationValue(conf)
	err := conf.LoadFromYaml(strings.NewReader(referenceTestDefaults+"flows: [{name: second, authorization: missing}]"), "invalid.yaml")
	require.ErrorContains(t, err, "unknown authorization")
	require.True(t, previous.IsEqualTo(conf))
	require.Equal(t, "original.yaml", conf.Filename)
}
