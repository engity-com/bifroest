//go:build unix

package protocol

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/errors"
)

func TestAuthorizeReverseTCPPort(t *testing.T) {
	for _, tc := range []struct {
		name       string
		port       uint16
		user       string
		configured bool
		allowed    bool
	}{
		{"numeric root", 1, "0", true, true},
		{"root with group", 1023, "0:10001", true, true},
		{"named root", 80, "root", true, true},
		{"named root with group", 80, "root:root", true, true},
		{"numeric nonroot", 80, "10001", true, false},
		{"nonroot with root group", 80, "10001:0", true, false},
		{"unknown name", 80, "bifroest-no-such-user-12345", true, false},
		{"invalid name", 80, ":root", true, false},
		{"empty configured", 80, "", true, false},
		{"unconfigured root", 80, "root", false, false},
		{"unconfigured empty", 80, "", false, false},
		{"unconfigured ephemeral", 0, "", false, true},
		{"unconfigured high", 1024, "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := authorizeReverseTCPPortForUID(tc.port, tc.user, tc.configured, 0)
			if tc.allowed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.True(t, errors.Permission.IsErr(err))
			}
		})
	}
	require.True(t, errors.Permission.IsErr(authorizeReverseTCPPortForUID(80, "root", true, 10001)))
}

func TestReverseTCPHandlerRejectsPrivilegedPortOnWire(t *testing.T) {
	for _, tc := range []struct {
		name       string
		user       string
		configured bool
	}{
		{"unconfigured", "", false},
		{"nonroot", "10001", true},
		{"unknown", "bifroest-no-such-user-12345", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			serverDone := make(chan error, 1)
			go func() {
				conn := codec.NewMsgPackConn(server)
				serverDone <- (&imp{Imp: &Imp{ReverseTCPUser: tc.user, ReverseTCPUserConfigured: tc.configured}}).
					handleMethodListenReverseTCP(context.Background(), &Header{Method: MethodListenReverseTCP}, nil, conn)
			}()
			conn := codec.NewMsgPackConn(client)
			require.NoError(t, (reverseTCPRequest{host: "127.0.0.1", port: 80}).EncodeMsgPack(conn))
			var response reverseTCPResponse
			require.NoError(t, response.DecodeMsgPack(conn))
			require.ErrorContains(t, response.err, "requires a configured target user with UID 0")
			require.True(t, errors.Permission.IsErr(response.err))
			require.Empty(t, response.addr)
			require.NoError(t, <-serverDone)
		})
	}
}
