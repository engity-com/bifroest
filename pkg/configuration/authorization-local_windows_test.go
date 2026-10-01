//go:build windows

package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestWindowsLocalAuthorizationConfiguration(t *testing.T) {
	var conf Authorization
	require.NoError(t, yaml.Unmarshal([]byte("type: local\n"), &conf))
	local, ok := conf.V.(*AuthorizationLocal)
	require.True(t, ok)
	require.Equal(t, DefaultAuthorizationLocalAuthorizedKeys, local.AuthorizedKeys)
	require.Empty(t, local.PamService)
	require.Equal(t, DefaultPasswordAllowed, local.Password.Allowed)
	require.Equal(t, DefaultPasswordInteractiveAllowed, local.Password.InteractiveAllowed)
	require.Equal(t, []string{"local"}, local.FeatureFlags())

	require.ErrorContains(t, yaml.Unmarshal([]byte("type: local\npamService: sshd\n"), &conf), "pamService is not supported on Windows")
	require.NoError(t, yaml.Unmarshal([]byte("type: local\nauthorizedKeys: []\npassword:\n  allowed: false\n"), &conf))
	require.Empty(t, conf.V.(*AuthorizationLocal).AuthorizedKeys)
	allowed, err := conf.V.(*AuthorizationLocal).Password.Allowed.Render(nil)
	require.NoError(t, err)
	require.False(t, allowed)
}
