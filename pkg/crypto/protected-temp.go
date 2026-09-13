package crypto

import (
	"fmt"
	"os"
)

// CreateProtectedTempFile creates a private temporary file. Modes granting
// group or other permissions are rejected instead of being silently clamped.
func CreateProtectedTempFile(parent, pattern string, mode os.FileMode) (*os.File, error) {
	if mode.Perm()&0077 != 0 {
		return nil, fmt.Errorf("temporary private file mode %04o grants group or other permissions", mode.Perm())
	}
	return createProtectedTempFile(parent, pattern, mode)
}

// CreateProtectedTempDirectory creates a private mode-0700 temporary directory.
func CreateProtectedTempDirectory(parent, pattern string) (string, error) {
	return createProtectedTempDirectory(parent, pattern)
}
