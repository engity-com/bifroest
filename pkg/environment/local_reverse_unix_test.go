//go:build unix

package environment

import (
	"context"
	gonet "net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/user"
)

func TestLocalListenReverseTCP(t *testing.T) {
	ctx := context.Background()
	env := &local{portForwardingAllowed: true, user: &user.User{Uid: 12345}}
	require.True(t, env.reverseTCPUnprivilegedUser())
	require.False(t, (&local{}).reverseTCPUnprivilegedUser())
	require.False(t, (&local{user: &user.User{Uid: 0}}).reverseTCPUnprivilegedUser())

	for _, port := range []uint16{1, 1023} {
		ln, err := env.ListenReverseTCP(ctx, "localhost", port)
		require.Nil(t, ln)
		require.ErrorContains(t, err, "privileged reverse TCP port")
	}

	for _, tc := range []struct {
		host     string
		loopback bool
	}{
		{"", true},
		{"localhost", true},
		{"*", false},
		{"0.0.0.0", false},
	} {
		t.Run(tc.host, func(t *testing.T) {
			ln, err := env.ListenReverseTCP(ctx, tc.host, 0)
			require.NoError(t, err)
			defer ln.Close()
			addr, ok := ln.Addr().(*gonet.TCPAddr)
			require.True(t, ok)
			require.NotZero(t, addr.Port)
			if tc.loopback {
				require.True(t, addr.IP.IsLoopback(), "address: %s", addr)
			} else {
				require.True(t, addr.IP.IsUnspecified(), "address: %s", addr)
			}
		})
	}
}
