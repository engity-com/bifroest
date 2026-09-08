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

	log "github.com/echocat/slf4g"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/sys"
)

const boundedPidfdsHelper = "BIFROEST_BOUNDED_PIDFDS_HELPER"

func TestKillProcessesSignalsProcessGroupOnce(t *testing.T) {
	directory := t.TempDir()
	expectedEnv := "BIFROEST_TEST_EXECUTION=signal-once"
	childPidFile := filepath.Join(directory, "child.pid")
	cmd := exec.Command("/bin/sh", "-c", "sleep 30 & echo $! > \"$1\"; wait", "sh", childPidFile)
	cmd.Env = append(os.Environ(), expectedEnv)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
	})
	require.Eventually(t, func() bool {
		_, err := os.Stat(childPidFile)
		return err == nil
	}, 2*time.Second, 10*time.Millisecond)

	originalSendPidfdSignal := sendPidfdSignal
	t.Cleanup(func() { sendPidfdSignal = originalSendPidfdSignal })
	groupSignals := 0
	sendPidfdSignal = func(pidfd int, signal sys.Signal, flags int) error {
		if signal == sys.SIGUSR1 && flags == pidfdSignalProcessGroup {
			groupSignals++
			return nil
		}
		return originalSendPidfdSignal(pidfd, signal, flags)
	}

	response := (&imp{}).killProcesses(
		context.Background(),
		&Header{ConnectionId: connection.MustNewId()},
		log.GetLogger("test"),
		directory,
		connection.MustNewId(),
		expectedEnv,
		0,
		sys.SIGUSR1,
		true,
		true,
	)
	require.NoError(t, response.error)
	require.Equal(t, 1, groupSignals)
}

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
		cmd.Process.Pid,
		pidfd,
		cmd.Process.Pid,
		sys.SIGKILL,
	))
	_ = cmd.Wait()
	require.Eventually(t, func() bool {
		return processIsGoneOrZombie(childPid)
	}, 2*time.Second, 10*time.Millisecond)
}

func TestSignalPinnedProcessGroupUsesBoundedPidfds(t *testing.T) {
	if os.Getenv(boundedPidfdsHelper) != "" {
		cmd := exec.Command("/bin/sh", "-c", "i=0; while [ $i -lt 24 ]; do sleep 30 & i=$((i + 1)); done; wait")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		require.NoError(t, cmd.Start())
		t.Cleanup(func() {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Wait()
		})
		require.Eventually(t, func() bool {
			members := 0
			candidates, err := process.Processes()
			if err != nil {
				return false
			}
			for _, candidate := range candidates {
				if pgid, err := syscall.Getpgid(int(candidate.Pid)); err == nil && pgid == cmd.Process.Pid {
					members++
				}
			}
			return members >= 20
		}, 2*time.Second, 10*time.Millisecond)

		anchorPidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
		require.NoError(t, err)
		defer unix.Close(anchorPidfd)
		openFiles, err := os.ReadDir("/proc/self/fd")
		require.NoError(t, err)
		var limit unix.Rlimit
		require.NoError(t, unix.Getrlimit(unix.RLIMIT_NOFILE, &limit))
		originalLimit := limit
		defer func() { require.NoError(t, unix.Setrlimit(unix.RLIMIT_NOFILE, &originalLimit)) }()
		limit.Cur = uint64(len(openFiles) + 8)
		require.NoError(t, unix.Setrlimit(unix.RLIMIT_NOFILE, &limit))

		require.NoError(t, signalPinnedProcessGroup(context.Background(), cmd.Process.Pid, anchorPidfd, cmd.Process.Pid, sys.SIGKILL))
		return
	}

	executable, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.Command(executable, "-test.run=^TestSignalPinnedProcessGroupUsesBoundedPidfds$")
	cmd.Env = append(os.Environ(), boundedPidfdsHelper+"=1")
	require.NoError(t, cmd.Run())
}

func TestKillProcessGroupWithoutLeader(t *testing.T) {
	expectedEnv := "BIFROEST_TEST_EXECUTION=orphaned-group"
	childPidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.Command("/bin/sh", "-c", "sleep 30 & echo $! > \"$1\"; wait", "sh", childPidFile)
	cmd.Env = append(os.Environ(), expectedEnv)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())
	leaderPid := cmd.Process.Pid

	var childPid int
	require.Eventually(t, func() bool {
		content, err := os.ReadFile(childPidFile)
		if err != nil {
			return false
		}
		childPid, err = strconv.Atoi(strings.TrimSpace(string(content)))
		return err == nil
	}, 2*time.Second, 10*time.Millisecond)
	t.Cleanup(func() { _ = syscall.Kill(childPid, syscall.SIGKILL) })

	require.NoError(t, syscall.Kill(leaderPid, syscall.SIGKILL))
	require.Error(t, cmd.Wait())
	require.Equal(t, leaderPid, mustGetProcessGroup(t, childPid))

	require.NoError(t, (&imp{}).kill(context.Background(), processTarget{
		pid:              childPid,
		processGroup:     true,
		expectedEnv:      expectedEnv,
		groupExpectedEnv: expectedEnv,
	}, sys.SIGKILL, make(signaledProcessGroups)))
	require.Eventually(t, func() bool {
		return processIsGoneOrZombie(childPid)
	}, 2*time.Second, 10*time.Millisecond)
}

func TestKillProcessGroupWithZombieLeader(t *testing.T) {
	expectedEnv := "BIFROEST_TEST_EXECUTION=zombie-leader"
	childPidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.Command("/bin/sh", "-c", "sleep 30 & echo $! > \"$1\"; wait", "sh", childPidFile)
	cmd.Env = append(os.Environ(), expectedEnv)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())
	leaderPid := cmd.Process.Pid
	leaderPidfd, err := unix.PidfdOpen(leaderPid, 0)
	require.NoError(t, err)
	defer unix.Close(leaderPidfd)

	var childPid int
	require.Eventually(t, func() bool {
		content, err := os.ReadFile(childPidFile)
		if err != nil {
			return false
		}
		childPid, err = strconv.Atoi(strings.TrimSpace(string(content)))
		return err == nil
	}, 2*time.Second, 10*time.Millisecond)
	t.Cleanup(func() {
		_ = syscall.Kill(childPid, syscall.SIGKILL)
		_ = cmd.Wait()
	})

	require.NoError(t, syscall.Kill(leaderPid, syscall.SIGKILL))
	require.Eventually(t, func() bool {
		exited, err := pidfdExited(leaderPidfd)
		return err == nil && exited
	}, 2*time.Second, 10*time.Millisecond)
	require.Equal(t, leaderPid, mustGetProcessGroup(t, childPid))

	require.NoError(t, (&imp{}).kill(context.Background(), processTarget{
		pid:              childPid,
		processGroup:     true,
		expectedEnv:      expectedEnv,
		groupExpectedEnv: expectedEnv,
	}, sys.SIGKILL, make(signaledProcessGroups)))
	require.Eventually(t, func() bool {
		return processIsGoneOrZombie(childPid)
	}, 2*time.Second, 10*time.Millisecond)
}
