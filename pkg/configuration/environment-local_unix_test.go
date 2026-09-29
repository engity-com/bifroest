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
