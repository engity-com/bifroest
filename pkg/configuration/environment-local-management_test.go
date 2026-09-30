package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

func TestEnvironmentLocalManagementDefaults(t *testing.T) {
	var env Environment
	require.NoError(t, yaml.Unmarshal([]byte("type: local\nname: alice\n"), &env))
	local, ok := env.V.(*EnvironmentLocal)
	require.True(t, ok)
	require.Equal(t, "bifroest-managed", local.ManagedGroup)
	require.Equal(t, template.BoolOf(false), local.ManageSystemUsers)
	require.Equal(t, template.BoolOf(false), local.DeleteOnDispose)
	require.Equal(t, template.BoolOf(true), local.DeleteHomeTogetherWithUser)
	require.Equal(t, "{{ .user.managed }}", local.KillProcessesOnDispose.String())
	require.Equal(t, DefaultEnvironmentLocalShellCommand, local.ShellCommand)
	require.Equal(t, DefaultEnvironmentLocalExecCommandPrefix, local.ExecCommandPrefix)
	require.Equal(t, DefaultEnvironmentLocalDirectory, local.Directory)
}

func TestEnvironmentLocalSessionOverrides(t *testing.T) {
	var env Environment
	require.NoError(t, yaml.Unmarshal([]byte("type: local\nname: alice\nshellCommand: [sh, '-l']\nexecCommandPrefix: [sh, '-c']\ndirectory: '{{ .targetDirectory }}'\n"), &env))
	local := env.V.(*EnvironmentLocal)
	shell, err := local.ShellCommand.Render(nil)
	require.NoError(t, err)
	require.Equal(t, []string{"sh", "-l"}, shell)
	prefix, err := local.ExecCommandPrefix.Render(nil)
	require.NoError(t, err)
	require.Equal(t, []string{"sh", "-c"}, prefix)
	dir, err := local.Directory.Render(map[string]string{"targetDirectory": "/tmp"})
	require.NoError(t, err)
	require.Equal(t, "/tmp", dir)
}

func TestEnvironmentLocalManagementTemplates(t *testing.T) {
	var env Environment
	require.NoError(t, yaml.Unmarshal([]byte("type: local\nname: alice\nmanagedGroup: managed-by-test\nmanageSystemUsers: '{{ .authorization.allowed }}'\ndeleteOnDispose: '{{ .user.managed }}'\ndeleteHomeTogetherWithUser: false\nkillProcessesOnDispose: true\n"), &env))
	local, ok := env.V.(*EnvironmentLocal)
	require.True(t, ok)
	require.Equal(t, "managed-by-test", local.ManagedGroup)
	allowed, err := local.ManageSystemUsers.Render(map[string]any{"authorization": map[string]any{"allowed": true}})
	require.NoError(t, err)
	require.True(t, allowed)
	deleteUser, err := local.DeleteOnDispose.Render(map[string]any{"user": map[string]any{"managed": true}})
	require.NoError(t, err)
	require.True(t, deleteUser)
	require.Equal(t, template.BoolOf(false), local.DeleteHomeTogetherWithUser)
	require.Equal(t, template.BoolOf(true), local.KillProcessesOnDispose)

	copy := *local
	require.True(t, local.IsEqualTo(&copy))
	copy.ManagedGroup = "another-group"
	require.False(t, local.IsEqualTo(&copy))
	copy = *local
	copy.DeleteOnDispose = template.BoolOf(false)
	require.False(t, local.IsEqualTo(&copy))
}

func TestEnvironmentLocalRejectsEmptyManagedGroup(t *testing.T) {
	var env Environment
	require.ErrorContains(t, yaml.Unmarshal([]byte("type: local\nname: alice\nmanagedGroup: ''\n"), &env), "managedGroup")
}

func TestEnvironmentLocalRequiresMigrationOfLegacyDeleteFlag(t *testing.T) {
	for _, setting := range []string{
		"deleteOnDispose: true", "deleteManagedUser: false", "deleteManagedUserHomeDir: true", "killManagedUserProcesses: false",
	} {
		var env Environment
		require.ErrorContains(t, yaml.Unmarshal([]byte("type: local\nname: alice\ndispose:\n  "+setting+"\n"), &env), "replaced by top-level")
	}
}
