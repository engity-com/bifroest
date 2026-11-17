//go:build unix || windows

package configuration

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

func remoteNameOf(value AuthorizationV) *template.String {
	switch current := value.(type) {
	case *AuthorizationSimple:
		return &current.RemoteName
	case *AuthorizationHtpasswd:
		return &current.RemoteName
	case *AuthorizationLocal:
		return &current.RemoteName
	default:
		panic("unexpected fixture type")
	}
}

func TestAuthorizationRemoteNameDefaultsParsingValidationAndEquality(t *testing.T) {
	for _, kind := range []string{"simple", "htpasswd", "local"} {
		t.Run(kind, func(t *testing.T) {
			source := "type: " + kind + "\n"
			if kind == "simple" {
				source += "entries: [{name: alice, password: 'plain:correct'}]\n"
			}
			var original Authorization
			require.NoError(t, yaml.Unmarshal([]byte(source), &original))
			require.Equal(t, "{{.remote.user}}", remoteNameOf(original.V).String())
			var mapped Authorization
			require.NoError(t, yaml.Unmarshal([]byte(source+`remoteName: '{{regexFind "^[^@]+" .remote.user}}'`), &mapped))
			require.False(t, original.IsEqualTo(mapped))
			encoded, err := yaml.Marshal(mapped)
			require.NoError(t, err)
			var restored Authorization
			require.NoError(t, yaml.Unmarshal(encoded, &restored))
			require.True(t, mapped.IsEqualTo(restored))
			for _, invalid := range []string{`''`, `'{{'`, `'  '`, `null`, `true`, `12`, `[]`, `{}`} {
				var rejected Authorization
				require.Error(t, yaml.Unmarshal([]byte(source+"remoteName: "+invalid+"\n"), &rejected))
			}
			*remoteNameOf(original.V) = template.String{}
			require.NoError(t, original.V.Validate(), "programmatic zero-value mapping must preserve existing constructor behavior")
		})
	}
}

func TestRemoteNameReusableAuthorizationDefinitionsAreResolvedPerFlow(t *testing.T) {
	source := `environments: {default: {type: dummy}}
authorizations:
  shared:
    type: simple
    remoteName: '{{regexReplaceAll "@[^@]+$" .remote.user ""}}'
    entries: [{name: alice, password: 'plain:correct'}]
flows:
  - name: one
    authorization: shared
    requirement: {includedRequestingName: '@one$'}
  - name: two
    authorization: shared
    requirement: {includedRequestingName: '@two$'}
`
	var conf Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(source), ""))
	one := conf.Flows[0].Authorization.V.(*AuthorizationSimple)
	two := conf.Flows[1].Authorization.V.(*AuthorizationSimple)
	require.NotSame(t, one, two)
	require.Equal(t, one.RemoteName.String(), two.RemoteName.String())
	require.Equal(t, "shared", conf.Flows[0].Authorization.Reference)
	one.RemoteName = template.MustNewString("different")
	require.NotEqual(t, one.RemoteName.String(), two.RemoteName.String())
}
