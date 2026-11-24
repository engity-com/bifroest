package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	createJobObject          = kernel32.NewProc("CreateJobObjectW")
	assignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	terminateJobObject       = kernel32.NewProc("TerminateJobObject")
	setInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	createThreadSnapshot     = kernel32.NewProc("CreateToolhelp32Snapshot")
	thread32First            = kernel32.NewProc("Thread32First")
	thread32Next             = kernel32.NewProc("Thread32Next")
	openThread               = kernel32.NewProc("OpenThread")
	resumeThread             = kernel32.NewProc("ResumeThread")
)

func configureCommand(cmd *exec.Cmd) (func() error, func(), error) {
	// Suspend the initial thread until job assignment to avoid a race where go
	// spawns children before the job can track them. No shell/taskkill is used.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000004} // CREATE_SUSPENDED
	h, _, err := createJobObject.Call(0, 0)
	if h == 0 {
		return nil, nil, fmt.Errorf("create child job: %w", err)
	}
	if err := killJobOnClose(h); err != nil {
		_ = syscall.CloseHandle(syscall.Handle(h))
		return nil, nil, err
	}
	var mu sync.Mutex
	cancelled := false
	cmd.Cancel = func() error {
		mu.Lock()
		defer mu.Unlock()
		cancelled = true
		_, _, _ = terminateJobObject.Call(h, 1)
		return cmd.Process.Kill()
	}
	attach := func() error {
		mu.Lock()
		defer mu.Unlock()
		if cancelled {
			_ = cmd.Process.Kill()
			return os.ErrProcessDone
		}
		process, err := syscall.OpenProcess(0x0100|0x0001, false, uint32(cmd.Process.Pid)) // SET_QUOTA | TERMINATE
		if err != nil {
			return fmt.Errorf("open child for job assignment: %w", err)
		}
		defer syscall.CloseHandle(process)
		ok, _, assignErr := assignProcessToJobObject.Call(h, uintptr(process))
		if ok == 0 {
			return fmt.Errorf("assign child job: %w", assignErr)
		}
		return resumeChild(uint32(cmd.Process.Pid))
	}
	cleanup := func() {
		mu.Lock()
		defer mu.Unlock()
		_, _, _ = terminateJobObject.Call(h, 1)
		_ = syscall.CloseHandle(syscall.Handle(h))
	}
	return attach, cleanup, nil
}

func signalExitCode(*os.ProcessState) int { return 1 }

func rss(*os.ProcessState) (*uint64, string) { return nil, "" }

func killJobOnClose(job uintptr) error {
	// JOBOBJECT_EXTENDED_LIMIT_INFORMATION has a stable LimitFlags offset of
	// 16 on Win32/Win64; its total size is 112/144 bytes. A byte buffer avoids
	// differences between Go and Win32 C alignment of 64-bit struct members.
	var info [144]byte
	size := uintptr(144)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		size = 112
	}
	binary.LittleEndian.PutUint32(info[16:20], 0x00002000) // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	ok, _, err := setInformationJobObject.Call(job, 9, uintptr(unsafe.Pointer(&info[0])), size)
	if ok == 0 {
		return fmt.Errorf("set child job limits: %w", err)
	}
	return nil
}

type threadEntry32 struct {
	Size, Usage, ThreadID, OwnerPID uint32
	BasePriority, DeltaPriority     int32
	Flags                           uint32
}

func resumeChild(pid uint32) error {
	snapshot, _, err := createThreadSnapshot.Call(0x00000004, 0) // TH32CS_SNAPTHREAD
	if snapshot == ^uintptr(0) {
		return fmt.Errorf("snapshot child thread: %w", err)
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))
	entry := threadEntry32{}
	entry.Size = uint32(unsafe.Sizeof(entry))
	ok, _, _ := thread32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	for ok != 0 {
		if entry.OwnerPID == pid {
			thread, _, err := openThread.Call(0x0002, 0, uintptr(entry.ThreadID)) // THREAD_SUSPEND_RESUME
			if thread == 0 {
				return fmt.Errorf("open child thread: %w", err)
			}
			defer syscall.CloseHandle(syscall.Handle(thread))
			count, _, err := resumeThread.Call(thread)
			if uint32(count) == ^uint32(0) {
				return fmt.Errorf("resume child thread: %w", err)
			}
			if count > 1 {
				return fmt.Errorf("child thread remains suspended")
			}
			return nil
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		ok, _, _ = thread32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	}
	return fmt.Errorf("suspended child thread not found")
}
