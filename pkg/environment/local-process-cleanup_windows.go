//go:build windows

package environment

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func localWindowsProcessMatches(pid, self uint32, targetSID, processSID string) bool {
	return pid != 0 && pid != self && targetSID != "" && targetSID != "S-1-5-18" && processSID == targetSID
}

func localWindowsKillUserProcesses(account windowsLocalAccount, allowSystemUsers bool) error {
	if localSAMProtectedAccount(account) && !allowSystemUsers {
		return fmt.Errorf("refusing to kill processes of protected local account %q", account.Name)
	}
	sid, err := windows.StringToSid(account.SID)
	if err != nil || sid == nil || !sid.IsValid() || sid.String() == "S-1-5-18" {
		return fmt.Errorf("invalid or LocalSystem process cleanup SID %q: %v", account.SID, err)
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return fmt.Errorf("snapshot processes: %w", err)
	}
	defer func() { _ = windows.CloseHandle(snapshot) }()

	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snapshot, &entry); err != nil {
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return nil
		}
		return fmt.Errorf("enumerate processes: %w", err)
	}
	self := uint32(os.Getpid())
	for {
		if entry.ProcessID != 0 && entry.ProcessID != self {
			if err := localWindowsKillProcess(entry.ProcessID, self, account.SID); err != nil {
				return fmt.Errorf("cleanup process %d: %w", entry.ProcessID, err)
			}
		}
		err = windows.Process32Next(snapshot, &entry)
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("enumerate processes: %w", err)
		}
	}
}

func localWindowsKillProcess(pid, self uint32, targetSID string) error {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_FOUND) {
		return nil // Exited after the snapshot.
	}
	if err != nil {
		return localWindowsUnverifiedProcessError(pid, targetSID, err, localWindowsForeignProcess)
	}
	defer func() { _ = windows.CloseHandle(process) }()
	processSID, err := localWindowsProcessSID(process)
	if err != nil {
		if localWindowsProcessExited(process) {
			return nil
		}
		return localWindowsUnverifiedProcessError(pid, targetSID, err, localWindowsForeignProcess)
	}
	if !localWindowsProcessMatches(pid, self, targetSID, processSID) {
		return nil
	}

	// Keep the query handle open so this PID cannot be reused between checks.
	target, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(target) }()
	confirmedSID, err := localWindowsProcessSID(target)
	if err != nil {
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) && localWindowsProcessExited(target) {
			return nil
		}
		return err
	}
	if !localWindowsProcessMatches(pid, self, targetSID, confirmedSID) || confirmedSID != processSID {
		return nil
	}
	if err := windows.TerminateProcess(target, 1); err != nil {
		return err
	}
	return nil
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
