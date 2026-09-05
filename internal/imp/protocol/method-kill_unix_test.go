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

	require.NoError(t, (&imp{}).kill(context.Background(), cmd.Process.Pid, sys.SIGKILL, true))
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

func TestRegisteredProcessRejectsReusedPid(t *testing.T) {
	p, err := process.NewProcess(int32(os.Getpid()))
	require.NoError(t, err)
	createdAt, err := p.CreateTime()
	require.NoError(t, err)

	pid, ok := registeredProcess([]byte(fmt.Sprintf("%d %d", os.Getpid(), createdAt)), "")
	require.True(t, ok)
	require.Equal(t, os.Getpid(), pid)
	_, ok = registeredProcess([]byte(fmt.Sprintf("%d %d", os.Getpid(), createdAt+1)), "")
	require.False(t, ok)
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
