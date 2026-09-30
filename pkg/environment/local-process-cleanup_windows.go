//go:build windows

package environment

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func localWindowsProcessMatches(pid, self uint32, targetSID, processSID string) bool {
	return pid != 0 && pid != self && targetSID != "" && targetSID != "S-1-5-18" && processSID == targetSID
}

func localWindowsKillUserProcesses(ctx context.Context, account windowsLocalAccount, allowSystemUsers bool) error {
	if localSAMProtectedAccount(account) && !allowSystemUsers {
		return fmt.Errorf("refusing to kill processes of protected local account %q", account.Name)
	}
	sid, err := windows.StringToSid(account.SID)
	if err != nil || sid == nil || !sid.IsValid() || sid.String() == "S-1-5-18" {
		return fmt.Errorf("invalid or LocalSystem process cleanup SID %q: %v", account.SID, err)
	}
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || self == nil || self.User.Sid == nil || !self.User.Sid.IsValid() {
		return fmt.Errorf("cannot verify process cleanup against own identity: %v", err)
	}
	if account.SID == self.User.Sid.String() {
		return fmt.Errorf("refusing to clean up processes of the running service identity %q", account.SID)
	}
	return localWindowsSweepProcessesUntilEmpty(ctx, time.Now().Add(10*time.Second), func(deadline time.Time) (bool, error) {
		return localWindowsKillUserProcessesOnce(ctx, account.SID, deadline)
	})
}

func localWindowsSweepProcessesUntilEmpty(ctx context.Context, deadline time.Time, sweep func(time.Time) (bool, error)) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("windows process cleanup did not finish before timeout")
		}
		matched, err := sweep(deadline)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("windows process cleanup did not finish before timeout")
		}
		if !matched {
			return nil
		}
	}
}

func localWindowsKillUserProcessesOnce(ctx context.Context, targetSID string, deadline time.Time) (bool, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false, fmt.Errorf("snapshot processes: %w", err)
	}
	defer func() { _ = windows.CloseHandle(snapshot) }()

	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snapshot, &entry); err != nil {
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return false, nil
		}
		return false, fmt.Errorf("enumerate processes: %w", err)
	}
	self := uint32(os.Getpid())
	matched := false
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if !time.Now().Before(deadline) {
			return false, fmt.Errorf("windows process cleanup did not finish before timeout")
		}
		if entry.ProcessID != 0 && entry.ProcessID != self {
			found, err := localWindowsKillProcess(ctx, entry.ProcessID, self, targetSID, deadline)
			if err != nil {
				return false, fmt.Errorf("cleanup process %d: %w", entry.ProcessID, err)
			}
			matched = matched || found
		}
		err = windows.Process32Next(snapshot, &entry)
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return matched, nil
		}
		if err != nil {
			return false, fmt.Errorf("enumerate processes: %w", err)
		}
	}
}

func localWindowsKillProcess(ctx context.Context, pid, self uint32, targetSID string, deadline time.Time) (bool, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_FOUND) {
		return false, nil // Exited after the snapshot.
	}
	if err != nil {
		return false, localWindowsUnverifiedProcessError(pid, targetSID, err, localWindowsForeignProcess)
	}
	defer func() { _ = windows.CloseHandle(process) }()
	processSID, err := localWindowsProcessSID(process)
	if err != nil {
		if localWindowsProcessExited(process) {
			return false, nil
		}
		return false, localWindowsUnverifiedProcessError(pid, targetSID, err, localWindowsForeignProcess)
	}
	if !localWindowsProcessMatches(pid, self, targetSID, processSID) {
		return false, nil
	}

	// Keep the query handle open so this PID cannot be reused between checks.
	target, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_FOUND) {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	defer func() { _ = windows.CloseHandle(target) }()
	confirmedSID, err := localWindowsProcessSID(target)
	if err != nil {
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) && localWindowsProcessExited(target) {
			return true, nil
		}
		return true, err
	}
	if !localWindowsProcessMatches(pid, self, targetSID, confirmedSID) || confirmedSID != processSID {
		return true, nil
	}
	if err := ctx.Err(); err != nil {
		return true, err
	}
	if !time.Now().Before(deadline) {
		return true, fmt.Errorf("windows process cleanup did not finish before timeout")
	}
	if err := windows.TerminateProcess(target, 1); err != nil {
		status, waitErr := windows.WaitForSingleObject(target, 0)
		if waitErr != nil || status != windows.WAIT_OBJECT_0 {
			return true, err
		}
		return true, nil // The process exited before termination was requested.
	}
	for {
		if err := ctx.Err(); err != nil {
			return true, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return true, fmt.Errorf("windows process %d did not exit before timeout", pid)
		}
		status, err := windows.WaitForSingleObject(target, uint32(max(1, min(remaining.Milliseconds(), 200))))
		if err != nil {
			return true, fmt.Errorf("wait for windows process %d to exit: %w", pid, err)
		}
		if status == windows.WAIT_OBJECT_0 {
			return true, nil
		}
		if status != uint32(windows.WAIT_TIMEOUT) {
			return true, fmt.Errorf("windows process %d did not exit (wait status %#x)", pid, status)
		}
	}
}

func localWindowsUnverifiedProcessError(pid uint32, targetSID string, processErr error, foreignProcess func(uint32, string) (bool, error)) error {
	if !errors.Is(processErr, windows.ERROR_ACCESS_DENIED) {
		return processErr
	}
	foreign, err := foreignProcess(pid, targetSID)
	if err != nil {
		return errors.Join(processErr, err)
	}
	if foreign {
		return nil
	}
	return processErr
}

type localWTSProcessInfo struct {
	SessionID uint32
	ProcessID uint32
	Name      *uint16
	UserSID   *windows.SID
}

func localWindowsForeignProcess(pid uint32, targetSID string) (bool, error) {
	proc := windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSEnumerateProcessesW")
	if err := proc.Find(); err != nil {
		return false, fmt.Errorf("enumerate Windows process identities: %w", err)
	}
	var records *localWTSProcessInfo
	var count uint32
	ok, _, callErr := proc.Call(0, 0, 1, uintptr(unsafe.Pointer(&records)), uintptr(unsafe.Pointer(&count)))
	if ok == 0 {
		return false, fmt.Errorf("enumerate Windows process identities: %w", localS4UCallError(callErr))
	}
	if records == nil {
		return false, fmt.Errorf("windows process identities returned no data")
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(records)))
	for _, record := range unsafe.Slice(records, count) {
		if record.ProcessID != pid {
			continue
		}
		if record.UserSID == nil || !record.UserSID.IsValid() {
			return false, fmt.Errorf("windows process %d has no valid enumerated SID", pid)
		}
		return record.UserSID.String() != targetSID, nil
	}
	return false, fmt.Errorf("windows process %d has no enumerated SID", pid)
}

func localWindowsProcessSID(process windows.Handle) (string, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	if user.User.Sid == nil || !user.User.Sid.IsValid() {
		return "", fmt.Errorf("process token has no valid user SID")
	}
	return user.User.Sid.String(), nil
}

func localWindowsProcessExited(process windows.Handle) bool {
	var code uint32
	return windows.GetExitCodeProcess(process, &code) == nil && code != 259 // STILL_ACTIVE
}
