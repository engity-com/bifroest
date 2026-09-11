//go:build unix

package main

import (
	"fmt"
	goos "os"
)

func validateAuditPrivateKeyPermissions(path string, info goos.FileInfo) error {
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("private key %q is accessible by group or others", path)
	}
	return nil
}
