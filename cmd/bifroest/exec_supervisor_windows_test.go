package main

import (
	"errors"
	goos "os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

const execSupervisorHelperMode = "BIFROEST_EXEC_SUPERVISOR_HELPER"

func TestExecProcessSupervisorLifecycle(t *testing.T) {
	switch goos.Getenv(execSupervisorHelperMode) {
	case "parent":
		executable, err := goos.Executable()
		require.NoError(t, err)
		cmd := exec.Command(executable, "-test.run=^TestExecProcessSupervisorLifecycle$")
		cmd.Env = append(goos.Environ(), execSupervisorHelperMode+"=child")
		require.NoError(t, cmd.Run())
		return
	case "child":
		pidFile := goos.Getenv("BIFROEST_EXEC_SUPERVISOR_PID_FILE")
		require.NoError(t, goos.WriteFile(pidFile, []byte(strconv.Itoa(goos.Getpid())), 0600))
		for {
			time.Sleep(time.Hour)
		}
	}

	supervisor, err := newExecProcessSupervisor()
	require.NoError(t, err)
	t.Cleanup(func() { _ = supervisor.Cleanup() })

	pidFile := filepath.Join(t.TempDir(), "child.pid")
	executable, err := goos.Executable()
	require.NoError(t, err)
	cmd := exec.Command(executable, "-test.run=^TestExecProcessSupervisorLifecycle$")
	cmd.Env = append(goos.Environ(),
		execSupervisorHelperMode+"=parent",
		"BIFROEST_EXEC_SUPERVISOR_PID_FILE="+pidFile,
	)
	require.NoError(t, supervisor.Prepare(cmd))
	require.NotZero(t, cmd.SysProcAttr.CreationFlags&windows.CREATE_SUSPENDED)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	time.Sleep(100 * time.Millisecond)
	_, err = goos.Stat(pidFile)
	require.ErrorIs(t, err, goos.ErrNotExist)
	require.NoError(t, supervisor.Attach(cmd))

	var childPid uint64
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		value, err := goos.ReadFile(pidFile)
		if !assert.NoError(t, err) {
			return
		}
		childPid, err = strconv.ParseUint(string(value), 10, 32)
		assert.NoError(t, err)
	}, 10*time.Second, 50*time.Millisecond)

	parent, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
	require.NoError(t, err)
	defer func() { _ = windows.CloseHandle(parent) }()
	child, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(childPid))
	require.NoError(t, err)
	defer func() { _ = windows.CloseHandle(child) }()

	require.NoError(t, supervisor.Cleanup())
	for _, process := range []windows.Handle{parent, child} {
		status, err := windows.WaitForSingleObject(process, 10_000)
		require.NoError(t, err)
		require.Equal(t, uint32(windows.WAIT_OBJECT_0), status)
	}
}

func TestExecProcessSupervisorAttachRejectsInheritedJobWithoutNesting(t *testing.T) {
	originalAssign := assignProcessToJobObject
	originalClose := closeWindowsHandle
	originalOpen := openWindowsProcess
	originalResume := resumeExecProcess
	t.Cleanup(func() {
		openWindowsProcess = originalOpen
		assignProcessToJobObject = originalAssign
		closeWindowsHandle = originalClose
		resumeExecProcess = originalResume
	})

	var closed []windows.Handle
	openWindowsProcess = func(uint32, bool, uint32) (windows.Handle, error) {
		return windows.Handle(7), nil
	}
	assignProcessToJobObject = func(windows.Handle, windows.Handle) error {
		return windows.ERROR_ACCESS_DENIED
	}
	closeWindowsHandle = func(handle windows.Handle) error {
		closed = append(closed, handle)
		return nil
	}
	resumeExecProcess = func(uint32) error {
		t.Fatal("must not resume a process without reliable descendant supervision")
		return nil
	}

	supervisor := &execProcessSupervisor{job: windows.Handle(42)}
	cmd := &exec.Cmd{Process: &goos.Process{Pid: 123}}
	require.ErrorIs(t, supervisor.Attach(cmd), windows.ERROR_ACCESS_DENIED)
	require.Equal(t, windows.Handle(42), supervisor.job)
	require.Equal(t, []windows.Handle{7}, closed)
}

func TestExecProcessSupervisorAttachReturnsUnexpectedAssignmentError(t *testing.T) {
	originalAssign := assignProcessToJobObject
	originalClose := closeWindowsHandle
	originalOpen := openWindowsProcess
	originalResume := resumeExecProcess
	t.Cleanup(func() {
		openWindowsProcess = originalOpen
		assignProcessToJobObject = originalAssign
		closeWindowsHandle = originalClose
		resumeExecProcess = originalResume
	})

	expected := errors.New("assignment failed")
	openWindowsProcess = func(uint32, bool, uint32) (windows.Handle, error) {
		return windows.Handle(7), nil
	}
	assignProcessToJobObject = func(windows.Handle, windows.Handle) error { return expected }
	closeWindowsHandle = func(windows.Handle) error { return nil }
	resumeExecProcess = func(uint32) error {
		t.Fatal("must not resume after an unexpected assignment error")
		return nil
	}

	supervisor := &execProcessSupervisor{job: windows.Handle(42)}
	cmd := &exec.Cmd{Process: &goos.Process{Pid: 123}}
	require.ErrorIs(t, supervisor.Attach(cmd), expected)
	require.Equal(t, windows.Handle(42), supervisor.job)
}
