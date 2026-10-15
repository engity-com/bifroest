//go:build windows

package common

import "golang.org/x/sys/windows"

func DeleteOpenWindowsFile(file windows.Handle) error {
	deleteFile := byte(1)
	var status windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(file, &status, &deleteFile, 1, windows.FileDispositionInformation)
}
