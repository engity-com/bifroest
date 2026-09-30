//go:build windows

package environment

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestLocalConPTYFrame(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeLocalConPTYFrame(&buf, localConPTYFrame{kind: 'D', data: []byte("hello")}))
	require.Equal(t, byte('D'), buf.Bytes()[0])
	require.Equal(t, uint32(5), binary.LittleEndian.Uint32(buf.Bytes()[1:5]))
	require.Equal(t, "hello", string(buf.Bytes()[5:]))
}

func TestLocalConPTYCommandFrame(t *testing.T) {
	argv := []string{`C:\Windows\System32\cmd.exe`, "/C", "echo hello"}
	payload, err := json.Marshal(argv)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, writeLocalConPTYFrame(&buf, localConPTYFrame{kind: 'C', data: payload}))
	parsed, err := ReadLocalConPTYCommand(&buf)
	require.NoError(t, err)
	require.Equal(t, argv, parsed)

	buf.Reset()
	require.NoError(t, writeLocalConPTYFrame(&buf, localConPTYFrame{kind: 'R', data: []byte{80, 0, 25, 0}}))
	_, err = ReadLocalConPTYCommand(&buf)
	require.ErrorContains(t, err, "invalid ConPTY command frame")
}

func TestLocalConPTYRelayExitStatus(t *testing.T) {
	for _, code := range []int{0, 1, 255, 65535} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var frame bytes.Buffer
			require.NoError(t, WriteLocalConPTYRelayExitStatus(&frame, code))
			status := &localConPTYRelayStatusWriter{}
			_, err := status.Write([]byte("relay diagnostic\n"))
			require.NoError(t, err)
			_, err = status.Write(frame.Bytes()[:3])
			require.NoError(t, err)
			_, err = status.Write(frame.Bytes()[3:])
			require.NoError(t, err)
			got, diagnostic, err := status.exitStatus()
			require.NoError(t, err)
			require.Equal(t, code, got)
			require.Equal(t, "relay diagnostic", diagnostic)
		})
	}
}

func TestLocalConPTYRelayExitStatusFailsClosed(t *testing.T) {
	var valid bytes.Buffer
	require.NoError(t, WriteLocalConPTYRelayExitStatus(&valid, 1))
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{name: "missing", data: []byte("relay failed\n"), want: "missing"},
		{name: "invalid", data: []byte(localConPTYRelayExitPrefix + "00000x01\n"), want: "invalid"},
		{name: "invalid sign", data: []byte(localConPTYRelayExitPrefix + "+0000001\n"), want: "invalid"},
		{name: "duplicate", data: bytes.Repeat(valid.Bytes(), 2), want: "duplicate"},
		{name: "trailing output", data: append(bytes.Clone(valid.Bytes()), []byte("later\n")...), want: "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := &localConPTYRelayStatusWriter{}
			_, err := status.Write(tc.data)
			require.NoError(t, err)
			_, _, err = status.exitStatus()
			require.ErrorContains(t, err, tc.want)
		})
	}
	status := &localConPTYRelayStatusWriter{}
	large := bytes.Repeat([]byte("x"), 16*1024)
	_, err := status.Write(large)
	require.NoError(t, err)
	_, err = status.Write(valid.Bytes())
	require.NoError(t, err)
	require.Equal(t, len(status.tail), status.length)
	code, diagnostic, err := status.exitStatus()
	require.NoError(t, err)
	require.Equal(t, 1, code)
	require.Contains(t, diagnostic, "[truncated]")
	status = &localConPTYRelayStatusWriter{}
	_, err = status.Write(bytes.Repeat([]byte("x"), len(status.tail)))
	require.NoError(t, err)
	require.False(t, status.truncated)
	require.ErrorContains(t, WriteLocalConPTYRelayExitStatus(io.Discard, -1), "invalid")
}

func TestLocalConPTYRelayRoundTrip(t *testing.T) {
	if os.Getenv("BIFROEST_CONPTY_RELAY_TEST_CHILD") == "1" {
		code, err := RunLocalConPTYRelay(80, 25, []string{os.Args[0], "local-windows-identity-child"})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(code)
	}
	if err := windows.NewLazySystemDLL("kernel32.dll").NewProc("CreatePseudoConsole").Find(); err != nil {
		t.Skip("ConPTY is not available on this Windows version")
	}
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	cmd := exec.Command(os.Args[0], "-test.run=^TestLocalConPTYRelayRoundTrip$")
	cmd.Env = append(os.Environ(), "BIFROEST_CONPTY_RELAY_TEST_CHILD=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	result := make(chan error, 1)
	go func() { result <- cmd.Wait() }()
	select {
	case err := <-result:
		require.NoError(t, err, "%s", stderr.String())
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		<-result
		t.Fatal("ConPTY relay did not stop within 20 seconds")
	}
	_ = stdin.Close()
	require.Contains(t, strings.ToUpper(stdout.String()), strings.ToUpper(self.User.Sid.String()))
}
