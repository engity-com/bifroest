//go:build unix

package service

import (
	gonet "net"
	"os"
	"os/user"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestLocalEnvironmentReverseTCPBindsInEnvironment(t *testing.T) {
	shadow, err := os.Open("/etc/shadow")
	if err != nil {
		t.Skipf("local user repository requires access to /etc/shadow: %v", err)
	}
	require.NoError(t, shadow.Close())
	current, err := user.Current()
	require.NoError(t, err)
	server := newAuthorizedKeysTestServerWithConfiguration(t, `permitlisten="127.0.0.1:*"`, nil, func(conf *configuration.Configuration) {
		local := &configuration.EnvironmentLocal{}
		require.NoError(t, local.SetDefaults())
		local.User.Name = template.MustNewString(current.Username)
		conf.Flows[0].Environment.V = local
	})
	client := server.mustDial(t)
	listener, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().(*gonet.TCPAddr)
	require.NotZero(t, address.Port)
	probe, err := gonet.Dial("tcp", address.String())
	require.NoError(t, err)
	require.NoError(t, probe.Close())
	require.NoError(t, listener.Close())
	rebound, err := gonet.Listen("tcp", address.String())
	require.NoError(t, err)
	require.NoError(t, rebound.Close())
}
