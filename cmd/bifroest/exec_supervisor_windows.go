package main

import (
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	openWindowsProcess       = windows.OpenProcess
	assignProcessToJobObject = windows.AssignProcessToJobObject
	closeWindowsHandle       = windows.CloseHandle
	resumeExecProcess        = resumeProcess
)

type execProcessSupervisor struct {
	job windows.Handle
}

func newExecProcessSupervisor() (*execProcessSupervisor, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return nil, err
	}
	return &execProcessSupervisor{job: job}, nil
}

func (*execProcessSupervisor) Prepare(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
	return nil
}

func (this *execProcessSupervisor) Attach(cmd *exec.Cmd) error {
	process, err := openWindowsProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		return err
	}
	defer closeWindowsHandle(process)
	if err := assignProcessToJobObject(this.job, process); err != nil {
		return err
	}
	return resumeExecProcess(uint32(cmd.Process.Pid))
}

func resumeProcess(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	if err := windows.Thread32First(snapshot, &entry); err != nil {
		return err
	}
	for {
		if entry.OwnerProcessID == pid {
			thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
			if err != nil {
				return err
			}
			_, resumeErr := windows.ResumeThread(thread)
			_ = windows.CloseHandle(thread)
			return resumeErr
		}
		if err := windows.Thread32Next(snapshot, &entry); err != nil {
			return err
		}
	}
}

func (this *execProcessSupervisor) Cleanup() error {
	if this.job == 0 {
		return nil
	}
	err := closeWindowsHandle(this.job)
	this.job = 0
	return err
}
