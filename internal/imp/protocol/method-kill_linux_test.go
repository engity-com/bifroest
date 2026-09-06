//go:build linux

package protocol

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/engity-com/bifroest/pkg/sys"
)

func TestSignalPinnedProcessGroupReachesChild(t *testing.T) {
	childPidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.Command("/bin/sh", "-c", "sleep 30 & echo $! > \"$1\"; wait", "sh", childPidFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
	})

	var childPid int
	require.Eventually(t, func() bool {
		content, err := os.ReadFile(childPidFile)
		if err != nil {
			return false
		}
		childPid, err = strconv.Atoi(strings.TrimSpace(string(content)))
		return err == nil
	}, 2*time.Second, 10*time.Millisecond)
	pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	require.NoError(t, err)
	defer unix.Close(pidfd)

	require.NoError(t, signalPinnedProcessGroup(
		context.Background(),
		map[int]int{cmd.Process.Pid: pidfd},
		pidfd,
		cmd.Process.Pid,
		sys.SIGKILL,
	))
	_ = cmd.Wait()
	require.Eventually(t, func() bool {
		return processIsGoneOrZombie(childPid)
	}, 2*time.Second, 10*time.Millisecond)
}
