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

func TestEnvironmentLocalWindowsAllowsExistingAccountByUID(t *testing.T) {
	var env Environment
	require.NoError(t, yaml.Unmarshal([]byte("type: local\nuid: S-1-5-21-1-2-3-1001\n"), &env))
	local := env.V.(*EnvironmentLocal)
	require.True(t, local.Name.IsZero())
	uid, err := local.Uid.Render(nil)
	require.NoError(t, err)
	require.Equal(t, "S-1-5-21-1-2-3-1001", uid)
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
	require.Equal(t, DefaultEnvironmentLocalDisplayName, local.DisplayName)
	require.Equal(t, DefaultEnvironmentLocalCreateIfAbsent, local.CreateIfAbsent)
	require.Equal(t, DefaultEnvironmentLocalUpdateIfDifferent, local.UpdateIfDifferent)
	require.Equal(t, DefaultEnvironmentLocalManagedGroup, local.ManagedGroup)
	require.Equal(t, DefaultEnvironmentLocalManageSystemUsers, local.ManageSystemUsers)
	require.Equal(t, DefaultEnvironmentLocalDeleteOnDispose, local.DeleteOnDispose)
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
	second = *first
	second.DisplayName = template.MustNewString("Alice")
	require.False(t, first.IsEqualTo(second))
}

func TestEnvironmentLocalWindowsGroupRequirementsAndProfileTemplate(t *testing.T) {
	var env Environment
	require.NoError(t, yaml.Unmarshal([]byte("type: local\nname: alice\ngroups:\n  - name: '{{ .authorization.groupName }}'\n  - gid: '{{ .authorization.groupSid }}'\nskel: 'C:\\profile-template'\n"), &env))
	local := env.V.(*EnvironmentLocal)
	require.Len(t, local.Groups, 2)
	data := map[string]any{"authorization": map[string]any{"groupName": "builders", "groupSid": "S-1-5-32-545"}}
	groups, err := local.Groups.Render(data)
	require.NoError(t, err)
	require.Equal(t, []WindowsUserGroupRequirement{{Name: "builders"}, {Gid: "S-1-5-32-545"}}, groups)
	path, err := local.Skel.Render(data)
	require.NoError(t, err)
	require.Equal(t, `C:\profile-template`, path)

	other := *local
	other.WindowsUserRequirementTemplate.Groups = nil
	require.False(t, local.IsEqualTo(other))
	other = *local
	other.Skel = template.MustNewString(`C:\different`)
	require.False(t, local.IsEqualTo(other))

	var invalid Environment
	require.ErrorContains(t, yaml.Unmarshal([]byte("type: local\nname: alice\ngroups:\n  - {}\n"), &invalid), "group requires a name or GID")
}

func TestEnvironmentLocalWindowsManagementTemplates(t *testing.T) {
	var env Environment
	require.NoError(t, yaml.Unmarshal([]byte("type: local\nname: alice\ndisplayName: '{{ .user.name }}'\ncreateIfAbsent: true\nupdateIfDifferent: '{{ .user.managed }}'\nmanagedGroup: bifroest-test\ndeleteOnDispose: true\n"), &env))
	local := env.V.(*EnvironmentLocal)
	require.Equal(t, "bifroest-test", local.ManagedGroup)
	name, err := local.DisplayName.Render(map[string]any{"user": map[string]string{"name": "alice"}})
	require.NoError(t, err)
	require.Equal(t, "alice", name)
	require.Equal(t, template.BoolOf(true), local.CreateIfAbsent)
	require.Equal(t, template.BoolOf(true), local.DeleteOnDispose)
}
