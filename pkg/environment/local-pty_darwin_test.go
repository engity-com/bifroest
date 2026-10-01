//go:build darwin

package environment

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestDarwinConfigureCmdForPtyKeepsDescriptorsBlocking(t *testing.T) {
	master, terminal, err := pty.Open()
	require.NoError(t, err)
	t.Cleanup(func() { _ = master.Close() })
	t.Cleanup(func() { _ = terminal.Close() })

	cmd := &exec.Cmd{SysProcAttr: &syscall.SysProcAttr{}}
	require.NoError(t, (&local{}).configureCmdForPty(cmd, master, terminal))
	require.True(t, cmd.SysProcAttr.Setsid)
	require.True(t, cmd.SysProcAttr.Setctty)
	requireBlockingDescriptor(t, master)
	requireBlockingDescriptor(t, terminal)
}

func requireBlockingDescriptor(t *testing.T, file *os.File) {
	t.Helper()
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	require.NoError(t, err)
	require.Zero(t, flags&unix.O_NONBLOCK)
}
