//go:build unix

package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestEnvironmentLocalUnixAllowsUIDWithoutName(t *testing.T) {
	var env Environment
	require.NoError(t, yaml.Unmarshal([]byte("type: local\nuid: 1234\n"), &env))
	local := env.V.(*EnvironmentLocal)
	require.True(t, local.User.Name.IsZero())
	require.NotNil(t, local.User.Uid)
	uid, err := local.User.Uid.Render(nil)
	require.NoError(t, err)
	require.Equal(t, uint32(1234), uint32(uid))
}

func TestEnvironmentLocalUnixRoundTripRetainsEffectiveAccountSelectors(t *testing.T) {
	for _, test := range []struct{ name, input string }{
		{"name", "type: local\nname: selected-user\n"},
		{"uid", "type: local\nuid: 1234\n"},
		{"complete", "type: local\nname: selected-user\nuid: 1234\ndisplayName: Selected User\nhomeDir: /home/selected-user\nshell: /bin/sh\nskel: /etc/skel\ngroup:\n  name: selected-group\ngroups:\n  - name: secondary\nvariables:\n  EDITOR: vi\n"},
		{"templates-and-policy", "type: local\nname: '{{ .remote.user }}'\nuid: '{{ .user.uid }}'\nhomeDir: '/home/{{ .remote.user }}'\nloginAllowed: false\nportForwardingAllowed: false\ncreateIfAbsent: true\nupdateIfDifferent: true\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var original Environment
			require.NoError(t, yaml.Unmarshal([]byte(test.input), &original))
			encoded, err := yaml.Marshal(original)
			require.NoError(t, err)
			var fields map[string]any
			require.NoError(t, yaml.Unmarshal(encoded, &fields))
			require.NotContains(t, fields, "user", "local account selectors retain the existing flat schema")
			if !original.V.(*EnvironmentLocal).User.Name.IsZero() {
				require.Contains(t, fields, "name")
			}
			var restored Environment
			require.NoError(t, yaml.Unmarshal(encoded, &restored), string(encoded))
			before, after := original.V.(*EnvironmentLocal), restored.V.(*EnvironmentLocal)
			require.True(t, before.User.Name.IsEqualTo(after.User.Name), "target name changed: %s", encoded)
			require.True(t, before.User.HomeDir.IsEqualTo(after.User.HomeDir), "target home changed: %s", encoded)
			require.True(t, original.IsEqualTo(restored), "local target/config changed: %s", encoded)
			direct, err := yaml.Marshal(before)
			require.NoError(t, err)
			var directRestored EnvironmentLocal
			require.NoError(t, yaml.Unmarshal(direct, &directRestored), string(direct))
			require.True(t, before.IsEqualTo(directRestored), "direct local config changed: %s", direct)
		})
	}
}

func TestEnvironmentLocalUnixEqualityDetectsTargetHomeChanges(t *testing.T) {
	var first, second Environment
	require.NoError(t, yaml.Unmarshal([]byte("type: local\nname: same-user\nhomeDir: /home/first\n"), &first))
	require.NoError(t, yaml.Unmarshal([]byte("type: local\nname: same-user\nhomeDir: /home/second\n"), &second))
	require.False(t, first.IsEqualTo(second), "a target home-directory change must not be mistaken for equal configuration")
}
