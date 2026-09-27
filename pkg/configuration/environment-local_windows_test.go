//go:build windows

package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

func TestEnvironmentLocalWindowsRequiresName(t *testing.T) {
	for _, input := range []string{
		"type: local\n",
		"type: local\nname: ''\n",
	} {
		var env Environment
		require.ErrorContains(t, yaml.Unmarshal([]byte(input), &env), "name")
	}
}

func TestEnvironmentLocalWindowsTemplateAndDefaults(t *testing.T) {
	var env Environment
	require.NoError(t, yaml.Unmarshal([]byte("type: local\nname: '{{ .targetUser }}'\n"), &env))
	local, ok := env.V.(*EnvironmentLocal)
	require.True(t, ok)
	name, err := local.Name.Render(map[string]string{"targetUser": "alice"})
	require.NoError(t, err)
	require.Equal(t, "alice", name)
	require.Equal(t, DefaultEnvironmentLocalLoginAllowed, local.LoginAllowed)
	require.Equal(t, DefaultEnvironmentLocalShellCommand, local.ShellCommand)
	require.Equal(t, DefaultEnvironmentLocalExecCommandPrefix, local.ExecCommandPrefix)
	require.Equal(t, DefaultEnvironmentLocalDirectory, local.Directory)
	require.Equal(t, DefaultEnvironmentLocalPortForwardingAllowed, local.PortForwardingAllowed)

	var invalid Environment
	require.Error(t, yaml.Unmarshal([]byte("type: local\nname: '{{ .targetUser | nonexistentFunction }}'\n"), &invalid))
}

func TestEnvironmentLocalWindowsEqualityIncludesName(t *testing.T) {
	first := &EnvironmentLocal{}
	require.NoError(t, first.SetDefaults())
	first.Name = template.MustNewString("alice")
	second := *first
	require.True(t, first.IsEqualTo(second))
	require.True(t, first.IsEqualTo(&second))
	second.Name = template.MustNewString("bob")
	require.False(t, first.IsEqualTo(second))
	require.False(t, second.IsEqualTo(first))
	second = *first
	second.Directory = template.MustNewString(`C:\Users\alice`)
	require.False(t, first.IsEqualTo(second))
}
