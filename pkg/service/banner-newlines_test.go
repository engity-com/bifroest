package service

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

func dummySshBannerBytes(t *testing.T, banner string, pty bool) []byte {
	t.Helper()
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).Banner = template.MustNewString(banner)
		conf.Ssh.Keys.RememberMeNotification = template.MustNewString("")
	})
	client := server.mustDial(t)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	sess, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	if pty {
		require.NoError(t, sess.RequestPty("xterm", 24, 80, gossh.TerminalModes{}))
	}
	require.NoError(t, sess.Shell())
	require.NoError(t, sess.Wait())
	require.Empty(t, stderr.Bytes())
	return bytes.Clone(stdout.Bytes())
}

func dummyWebBannerBytes(t *testing.T, banner string, pty bool) []byte {
	t.Helper()
	fixture := newWebSocketFixture(t, nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).Banner = template.MustNewString(banner)
	})
	conn := fixture.dial(t)
	open := map[string]any{"type": "open", "slug": "Work", "accessToken": fixture.login(t), "task": "shell"}
	if pty {
		open["pty"] = map[string]any{"term": "xterm", "columns": 80, "rows": 24}
	}
	require.NoError(t, conn.WriteJSON(open))
	requireWebSocketReady(t, conn)
	stdout, stderr, status := webSocketResult(t, conn)
	require.Empty(t, stderr)
	require.Equal(t, `"exit"`, string(status["type"]))
	require.Equal(t, "0", string(status["status"]))
	return stdout
}

func TestDummyBannerLineEndingsAreTransportConsistent(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"LF", "first\n\nsecond\n\nBye!\n"},
		{"CRLF", "first\r\n\r\nsecond\r\n\r\nBye!\r\n"},
		{"mixed carriage returns", "first\rsecond\r\nthird\n"},
	} {
		for _, pty := range []bool{false, true} {
			name := tc.name + "/no-pty"
			if pty {
				name = tc.name + "/pty"
			}
			t.Run(name, func(t *testing.T) {
				sshBytes := dummySshBannerBytes(t, tc.value, pty)
				webBytes := dummyWebBannerBytes(t, tc.value, pty)
				t.Logf("PTY=%t configured=%q SSH=%q HTTP=%q", pty, tc.value, sshBytes, webBytes)
				require.Equal(t, sshBytes, webBytes, "server-generated dummy banner text must have identical terminal semantics")
				if !pty {
					require.Equal(t, []byte(tc.value), webBytes, "non-PTY output must remain byte-exact")
				}
			})
		}
	}
}

func TestBrowserDummyBannerStartsLinesAtColumnZero(t *testing.T) {
	testBrowserLoginUi(t, true, "dummy-banner", func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).Banner = template.MustNewString("DUMMY_BANNER_ONE\n\nDUMMY_BANNER_TWO\n\nDUMMY_BANNER_THREE\n")
	})
}
