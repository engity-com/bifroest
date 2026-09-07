//go:build unix

package protocol

import (
	"context"
	"errors"
	"fmt"
	gonet "net"
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

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/execution"
	"github.com/engity-com/bifroest/pkg/sys"
)

func TestKillProcessGroupReachesChild(t *testing.T) {
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

	require.NoError(t, (&imp{}).kill(context.Background(), processTarget{pid: cmd.Process.Pid, processGroup: true}, sys.SIGKILL, make(signaledProcessGroups)))
	_ = cmd.Wait()
	require.Eventually(t, func() bool {
		err := syscall.Kill(childPid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return true
		}
		status, readErr := os.ReadFile("/proc/" + strconv.Itoa(childPid) + "/stat")
		return readErr == nil && len(strings.Fields(string(status))) >= 3 && strings.Fields(string(status))[2] == "Z"
	}, 2*time.Second, 10*time.Millisecond)
}

func TestKillProcessGroupUsingNonLeaderReachesSiblings(t *testing.T) {
	directory := t.TempDir()
	expectedEnv := "BIFROEST_TEST_EXECUTION=owned"
	targetPidFile := filepath.Join(directory, "target.pid")
	siblingPidFile := filepath.Join(directory, "sibling.pid")
	cmd := exec.Command("/bin/sh", "-c", "sleep 30 & echo $! > \"$1\"; sleep 30 & echo $! > \"$2\"; wait", "sh", targetPidFile, siblingPidFile)
	cmd.Env = append(os.Environ(), expectedEnv)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
	})

	readPid := func(path string) int {
		var pid int
		require.Eventually(t, func() bool {
			content, err := os.ReadFile(path)
			if err != nil {
				return false
			}
			pid, err = strconv.Atoi(strings.TrimSpace(string(content)))
			return err == nil
		}, 2*time.Second, 10*time.Millisecond)
		return pid
	}
	targetPid := readPid(targetPidFile)
	siblingPid := readPid(siblingPidFile)
	require.NotEqual(t, cmd.Process.Pid, targetPid)
	require.Equal(t, cmd.Process.Pid, mustGetProcessGroup(t, targetPid))

	require.NoError(t, (&imp{}).kill(context.Background(), processTarget{
		pid:              targetPid,
		processGroup:     true,
		expectedEnv:      expectedEnv,
		groupExpectedEnv: expectedEnv,
	}, sys.SIGKILL, make(signaledProcessGroups)))
	_ = cmd.Wait()
	require.Eventually(t, func() bool {
		return processIsGoneOrZombie(targetPid) && processIsGoneOrZombie(siblingPid)
	}, 2*time.Second, 10*time.Millisecond)
}

func TestKillProcessGroupRejectsUnverifiedLeader(t *testing.T) {
	directory := t.TempDir()
	expectedEnv := "BIFROEST_TEST_EXECUTION=owned"
	targetPidFile := filepath.Join(directory, "target.pid")
	cmd := exec.Command("/bin/sh", "-c", "env BIFROEST_TEST_EXECUTION=owned sleep 30 & echo $! > \"$1\"; wait", "sh", targetPidFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
	})

	var targetPid int
	require.Eventually(t, func() bool {
		content, err := os.ReadFile(targetPidFile)
		if err != nil {
			return false
		}
		targetPid, err = strconv.Atoi(strings.TrimSpace(string(content)))
		return err == nil
	}, 2*time.Second, 10*time.Millisecond)

	err := (&imp{}).kill(context.Background(), processTarget{
		pid:              targetPid,
		processGroup:     true,
		expectedEnv:      expectedEnv,
		groupExpectedEnv: expectedEnv,
	}, sys.SIGKILL, make(signaledProcessGroups))
	require.ErrorIs(t, err, ErrNoSuchProcess)
	require.NoError(t, syscall.Kill(cmd.Process.Pid, 0))
	require.NoError(t, syscall.Kill(targetPid, 0))
}

func mustGetProcessGroup(t *testing.T, pid int) int {
	t.Helper()
	pgid, err := syscall.Getpgid(pid)
	require.NoError(t, err)
	return pgid
}

func processIsGoneOrZombie(pid int) bool {
	err := syscall.Kill(pid, 0)
	if errors.Is(err, syscall.ESRCH) {
		return true
	}
	status, readErr := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	return readErr == nil && len(strings.Fields(string(status))) >= 3 && strings.Fields(string(status))[2] == "Z"
}

func TestRegisteredProcessRejectsReusedPid(t *testing.T) {
	p, err := process.NewProcess(int32(os.Getpid()))
	require.NoError(t, err)
	createdAt, err := p.CreateTime()
	require.NoError(t, err)

	pid, expectedCreatedAt, ok := registeredProcess([]byte(fmt.Sprintf("%d %d", os.Getpid(), createdAt)))
	require.True(t, ok)
	require.Equal(t, os.Getpid(), pid)
	require.NotNil(t, expectedCreatedAt)
	require.Equal(t, createdAt, *expectedCreatedAt)
	require.ErrorIs(t, (&imp{}).kill(context.Background(), processTarget{
		pid:               pid,
		expectedCreatedAt: ptr(createdAt + 1),
	}, sys.Signal(0), make(signaledProcessGroups)), ErrNoSuchProcess)
}

func ptr[T any](value T) *T { return &value }

func TestKillProcessesRejectsUnsafePid(t *testing.T) {
	pids := []int{-1}
	if strconv.IntSize > 32 {
		tooLarge := int64(1) << 32
		pids = append(pids, int(tooLarge))
	}
	for _, pid := range pids {
		response := (&imp{}).killProcesses(
			context.Background(),
			&Header{ConnectionId: connection.MustNewId()},
			log.GetLogger("test"),
			t.TempDir(),
			connection.MustNewId(),
			"",
			pid,
			sys.SIGKILL,
			false,
		)
		require.ErrorIs(t, response.error, ErrNoSuchProcess)
	}
}

func TestHandleMethodKillFallsBackToExecutionProcessGroup(t *testing.T) {
	connectionId := connection.MustNewId()
	executionId, err := execution.NewId()
	require.NoError(t, err)
	directory := t.TempDir()
	stateDirectory := filepath.Join(directory, execution.StateDirectoryName)
	require.NoError(t, os.MkdirAll(stateDirectory, 0700))
	childPidFile := filepath.Join(directory, "child.pid")
	cmd := exec.Command("/bin/sh", "-c", `env -u BIFROEST_EXECUTION_ID sh -c 'sleep 30 & echo $! > "$1"; wait' sh "$1" & wait`, "sh", childPidFile)
	cmd.Env = append(os.Environ(), execution.EnvName+"="+executionId.String())
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
	stalePidPath := filepath.Join(stateDirectory, executionId.String()+".pid")
	require.NoError(t, os.WriteFile(stalePidPath, []byte(strconv.Itoa(os.Getpid())), 0600))

	server, client := gonet.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	serverConn := codec.NewMsgPackConn(server)
	clientConn := codec.NewMsgPackConn(client)
	handlerDone := make(chan error, 1)
	go func() {
		handlerDone <- (&imp{Imp: &Imp{ExitCodeByConnectionIdPath: directory}}).handleMethodKillExecution(
			context.Background(),
			&Header{Method: MethodKillExecution, ConnectionId: connectionId},
			log.GetLogger("test"),
			serverConn,
		)
	}()

	require.NoError(t, (methodKillExecutionRequest{executionId: executionId, signal: sys.SIGKILL}).EncodeMsgPack(clientConn))
	var response methodKillResponse
	require.NoError(t, response.DecodeMsgPack(clientConn))
	require.NoError(t, response.error)
	require.NoError(t, <-handlerDone)
	require.NoFileExists(t, stalePidPath)
	_ = cmd.Wait()

	require.Eventually(t, func() bool {
		err := syscall.Kill(childPid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return true
		}
		status, readErr := os.ReadFile("/proc/" + strconv.Itoa(childPid) + "/stat")
		return readErr == nil && len(strings.Fields(string(status))) >= 3 && strings.Fields(string(status))[2] == "Z"
	}, 2*time.Second, 10*time.Millisecond)
}
