package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

func TestAuthorizationPrincipalRoundTrip(t *testing.T) {
	var conf Authorization
	require.NoError(t, yaml.Unmarshal([]byte(`type: simple
principal: '{{ .authorization.entry.name }}'
entries:
  - name: alice
    password: plain:example
`), &conf))
	require.Equal(t, "{{ .authorization.entry.name }}", conf.Principal.String())
	encoded, err := yaml.Marshal(&conf)
	require.NoError(t, err)
	var restored Authorization
	require.NoError(t, yaml.Unmarshal(encoded, &restored))
	require.True(t, conf.IsEqualTo(restored))
	restored.Principal = template.MustNewString("different")
	require.False(t, conf.IsEqualTo(restored))
}

func TestAuthorizationPrincipalValidation(t *testing.T) {
	for _, source := range []string{
		"type: none\nprincipal: admin\n",
		"type: simple\nprincipal: '   '\n",
		"type: simple\nprincipal: '{{'\n",
		"type: simple\nprincipal: first\nprincipal: second\n",
	} {
		var conf Authorization
		require.Error(t, yaml.Unmarshal([]byte(source), &conf))
	}
	var conf Authorization
	require.NoError(t, yaml.Unmarshal([]byte("type: simple\n"), &conf))
	require.True(t, conf.Principal.IsZero())
}
