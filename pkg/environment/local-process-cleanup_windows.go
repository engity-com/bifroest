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
		return err
	}
	defer func() { _ = windows.CloseHandle(process) }()
	processSID, err := localWindowsProcessSID(process)
	if err != nil {
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) && localWindowsProcessExited(process) {
			return nil
		}
		return err
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
