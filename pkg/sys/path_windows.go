//go:build windows

package sys

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// WindowsPathPointer converts a path to an extended-length UTF-16 path.
func WindowsPathPointer(path string) (*uint16, error) {
	extended, err := WindowsExtendedPath(path)
	if err != nil {
		return nil, err
	}
	return windows.UTF16PtrFromString(extended)
}

// WindowsExtendedPath makes a path absolute and applies the matching drive or
// UNC extended-length prefix while preserving existing device paths.
func WindowsExtendedPath(path string) (string, error) {
	if strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\.\`) {
		return path, nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(absolute, `\\`) {
		return `\\?\UNC\` + strings.TrimPrefix(absolute, `\\`), nil
	}
	return `\\?\` + absolute, nil
}
