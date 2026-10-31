//go:build windows

package crypto

import (
	"os"

	"golang.org/x/sys/windows"
)

func createPrivateDirectory(path string) error {
	attributes, err := protectedWindowsSecurityAttributes()
	if err != nil {
		return err
	}
	name, err := windowsPathPointer(path)
	if err != nil {
		return err
	}
	return windows.CreateDirectory(name, attributes)
}

func validatePrivateDirectory(path string, file *os.File, _ os.FileInfo) error {
	return validatePrivateWindowsAccess(path, file)
}
