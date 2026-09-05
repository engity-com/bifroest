//go:build unix

package main

import (
	goerrors "errors"
	goos "os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/execution"
)

func TestDoExecUsesOnlyExplicitEnvironmentAndStoresExecutionResult(t *testing.T) {
	t.Setenv("BIFROEST_SECRET_VALUE", "must-not-leak")
	directory := t.TempDir()
	connectionId := connection.MustNewId()
	executionId := connection.MustNewId()
	opts := execOpts{
		storeExitCodeForConnectionId: true,
		exitCodeByConnectionIdPath:   directory,
		connectionId:                 connectionId,
		executionId:                  executionId,
		workingDirectory:             directory,
		environment: map[string]string{
			"BIFROEST_OVERRIDE_VALUE": "from-session",
		},
		path: "/bin/sh",
		argv: []string{"sh", "-c", "test -z \"$BIFROEST_SECRET_VALUE\" && test \"$BIFROEST_OVERRIDE_VALUE\" = from-session && test \"$BIFROEST_CONNECTION_ID\" = " + connectionId.String() + " && test \"$BIFROEST_EXECUTION_ID\" = " + executionId.String() + "; exit 27"},
	}

	require.NoError(t, doExec(&opts))
	stateDirectory := filepath.Join(directory, execution.StateDirectoryName)
	content, err := goos.ReadFile(executionStatePath(stateDirectory, executionId, ""))
	require.NoError(t, err)
	require.Equal(t, "27", string(content))
	require.NoFileExists(t, executionStatePath(stateDirectory, executionId, ".pid"))
	matches, err := filepath.Glob(filepath.Join(stateDirectory, ".bifroest-execution-*"))
	require.NoError(t, err)
	require.Empty(t, matches)
}

func TestDoExecStoresSignalExitCode(t *testing.T) {
	directory := t.TempDir()
	executionId := connection.MustNewId()
	opts := execOpts{
		storeExitCodeForConnectionId: true,
		exitCodeByConnectionIdPath:   directory,
		executionId:                  executionId,
		workingDirectory:             directory,
		environment:                  map[string]string{},
		path:                         "/bin/sh",
		argv:                         []string{"sh", "-c", "kill -TERM $$"},
	}

	started := time.Now()
	require.NoError(t, doExec(&opts))
	require.Less(t, time.Since(started), 5*time.Second)
	content, err := goos.ReadFile(executionStatePath(filepath.Join(directory, execution.StateDirectoryName), executionId, ""))
	require.NoError(t, err)
	require.Equal(t, "143", string(content))
}

func TestDoExecRejectsExitCodeStorageWithoutExecutionId(t *testing.T) {
	err := doExec(&execOpts{storeExitCodeForConnectionId: true})
	require.ErrorContains(t, err, "--executionId is required")
}

func TestDoExecUsesConnectionIdForLegacyExitCodeStorage(t *testing.T) {
	directory := t.TempDir()
	connectionId := connection.MustNewId()
	opts := execOpts{
		storeExitCodeForConnectionId: true,
		exitCodeByConnectionIdPath:   directory,
		connectionId:                 connectionId,
		workingDirectory:             directory,
		environment:                  map[string]string{},
		path:                         "/bin/sh",
		argv:                         []string{"sh", "-c", "test \"$BIFROEST_EXECUTION_ID\" = \"$BIFROEST_CONNECTION_ID\"; exit 19"},
	}

	require.NoError(t, doExec(&opts))
	content, err := goos.ReadFile(executionStatePath(directory, connectionId, ""))
	require.NoError(t, err)
	require.Equal(t, "19", string(content))
}

func TestDoExecKillsDaemonizedDescendantsAfterMainProcessExits(t *testing.T) {
	directory := t.TempDir()
	pidFile := filepath.Join(directory, "background.pid")
	opts := execOpts{
		workingDirectory: directory,
		environment:      map[string]string{},
		path:             "/bin/sh",
		argv: []string{
			"sh", "-c",
			"setsid env -i /bin/sleep 30 </dev/null >/dev/null 2>&1 & printf %s $! > " + pidFile,
		},
	}

	require.NoError(t, doExec(&opts))
	rawPid, err := goos.ReadFile(pidFile)
	require.NoError(t, err)
	pid, err := strconv.Atoi(string(rawPid))
	require.NoError(t, err)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	require.Eventually(t, func() bool {
		return goerrors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	}, time.Second, 10*time.Millisecond)
}

func TestEnrichExecCmdSetsSupplementaryGroups(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)
	wantIds, err := current.GroupIds()
	require.NoError(t, err)
	want := make([]uint32, len(wantIds))
	for i, id := range wantIds {
		value, err := strconv.ParseUint(id, 10, 32)
		require.NoError(t, err)
		want[i] = uint32(value)
	}

	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	opts := execOpts{user: current.Uid}
	require.NoError(t, enrichExecCmd(cmd, &opts))
	require.Equal(t, want, cmd.SysProcAttr.Credential.Groups)
}

func TestEnrichExecCmdAcceptsNumericCredentialsWithoutNssEntries(t *testing.T) {
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	opts := execOpts{user: "4294967294", group: "4294967293"}

	require.NoError(t, enrichExecCmd(cmd, &opts))
	require.Equal(t, uint32(4294967294), cmd.SysProcAttr.Credential.Uid)
	require.Equal(t, uint32(4294967293), cmd.SysProcAttr.Credential.Gid)
	require.NotNil(t, cmd.SysProcAttr.Credential.Groups)
	require.Empty(t, cmd.SysProcAttr.Credential.Groups)
}

func TestEnrichExecCmdDoesNotUseRootGroupForUnknownNumericUser(t *testing.T) {
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	opts := execOpts{user: "4294967294"}

	require.NoError(t, enrichExecCmd(cmd, &opts))
	require.Equal(t, uint32(4294967294), cmd.SysProcAttr.Credential.Uid)
	require.Equal(t, uint32(4294967294), cmd.SysProcAttr.Credential.Gid)
	require.NotNil(t, cmd.SysProcAttr.Credential.Groups)
	require.Empty(t, cmd.SysProcAttr.Credential.Groups)
}

func TestEnrichExecCmdAcceptsGroupWithoutUser(t *testing.T) {
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	opts := execOpts{group: "4294967293"}

	require.NoError(t, enrichExecCmd(cmd, &opts))
	require.Equal(t, uint32(goos.Geteuid()), cmd.SysProcAttr.Credential.Uid)
	require.Equal(t, uint32(4294967293), cmd.SysProcAttr.Credential.Gid)
}

func TestExecutionStatePathUsesExecutionId(t *testing.T) {
	executionId := connection.MustNewId()
	require.Equal(t, filepath.Join("state", executionId.String()+".pid"), executionStatePath("state", execution.Id(executionId), ".pid"))
}
