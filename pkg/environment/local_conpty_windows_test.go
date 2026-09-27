//go:build windows

package environment

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
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
