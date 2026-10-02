package configuration

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOnHostConfiguration(t *testing.T) {
	var conf Configuration
	require.NoError(t, conf.LoadFromFile(filepath.Join("..", "..", "contrib", "configurations", "on-host.yaml")))
	require.Len(t, conf.Flows, 1)
	require.Equal(t, "local", conf.Flows[0].Name.String())
	require.Len(t, conf.Ssh.Addresses, 1)
	require.Equal(t, ":22", conf.Ssh.Addresses[0].String())
	require.NotEmpty(t, conf.Flows[0].Authorization.V.(*AuthorizationLocal).AuthorizedKeys)
}
