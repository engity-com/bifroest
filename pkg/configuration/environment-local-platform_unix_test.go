//go:build darwin

package configuration

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/user"
)

func TestEnvironmentLocalTargetAccountPolicyDefaults(t *testing.T) {
	var actual EnvironmentLocal
	require.NoError(t, actual.SetDefaults())

	require.False(t, actual.TargetAccountPolicy.AllowUidZero)
	require.False(t, actual.TargetAccountPolicy.AllowSystemAccounts)
	require.False(t, actual.TargetAccountPolicy.AllowAdministrators)
	require.False(t, actual.TargetAccountPolicy.AllowNonLoginShell)
	require.False(t, actual.TargetAccountPolicy.AllowUnsafeNoneAuthorization)
	require.Empty(t, actual.TargetAccountPolicy.AllowedNames)
	require.Empty(t, actual.TargetAccountPolicy.DeniedNames)
	require.Empty(t, actual.TargetAccountPolicy.AllowedUids)
	require.Empty(t, actual.TargetAccountPolicy.DeniedUids)
	require.Empty(t, actual.TargetAccountPolicy.AllowedGroups)
	require.Empty(t, actual.TargetAccountPolicy.DeniedGroups)
	require.Empty(t, actual.TargetAccountPolicy.AllowedGids)
	require.Empty(t, actual.TargetAccountPolicy.DeniedGids)
}

func TestEnvironmentLocalTargetAccountPolicyYaml(t *testing.T) {
	input := `
name: alice
targetAccountPolicy:
  allowUidZero: true
  allowSystemAccounts: true
  allowAdministrators: true
  allowNonLoginShell: true
  allowUnsafeNoneAuthorization: true
  allowedNames: [" alice "]
  deniedNames: [" mallory "]
  allowedUids: [501]
  deniedUids: [502]
  allowedGroups: [" staff "]
  deniedGroups: [" admin "]
  allowedGids: [20]
  deniedGids: [80]
`
	var actual EnvironmentLocal
	decoder := yaml.NewDecoder(strings.NewReader(input))
	decoder.KnownFields(true)
	require.NoError(t, decoder.Decode(&actual))

	require.Equal(t, EnvironmentLocalTargetAccountPolicy{
		AllowUidZero:                 true,
		AllowSystemAccounts:          true,
		AllowAdministrators:          true,
		AllowNonLoginShell:           true,
		AllowUnsafeNoneAuthorization: true,
		AllowedNames:                 []string{"alice"},
		DeniedNames:                  []string{"mallory"},
		AllowedUids:                  []user.Id{501},
		DeniedUids:                   []user.Id{502},
		AllowedGroups:                []string{"staff"},
		DeniedGroups:                 []string{"admin"},
		AllowedGids:                  []user.GroupId{20},
		DeniedGids:                   []user.GroupId{80},
	}, actual.TargetAccountPolicy)
}

func TestEnvironmentLocalTargetAccountPolicyRejectsEmptyListEntries(t *testing.T) {
	policy := EnvironmentLocalTargetAccountPolicy{AllowedNames: []string{" "}}
	require.ErrorContains(t, policy.Trim(), "allowedNames")
}

func TestEnvironmentLocalTargetAccountPolicyEquality(t *testing.T) {
	left := EnvironmentLocalTargetAccountPolicy{
		AllowUidZero:                 true,
		AllowUnsafeNoneAuthorization: true,
		AllowedNames:                 []string{"alice"},
		DeniedGids:                   []user.GroupId{80},
	}
	right := left
	right.AllowedNames = append([]string(nil), left.AllowedNames...)
	right.DeniedGids = append([]user.GroupId(nil), left.DeniedGids...)
	require.True(t, left.IsEqualTo(right))

	right.DeniedGids[0] = 81
	require.False(t, left.IsEqualTo(right))
	right = left
	right.AllowUnsafeNoneAuthorization = false
	require.False(t, left.IsEqualTo(right))
}

func TestEnvironmentLocalTargetAccountPolicyUnsafeNoneLifecycle(t *testing.T) {
	var policy EnvironmentLocalTargetAccountPolicy
	require.NoError(t, yaml.Unmarshal([]byte("allowUnsafeNoneAuthorization: true\n"), &policy))
	require.True(t, policy.AllowUnsafeNoneAuthorization)
}
