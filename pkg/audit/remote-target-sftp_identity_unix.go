//go:build unix

package audit

import (
	"fmt"
	"os"
	"syscall"
)

func validateSftpIdentityFilePermissions(identityPath string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private key %q is accessible by group or others", identityPath)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of private key %q", identityPath)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("private key %q is owned by user %d instead of %d", identityPath, stat.Uid, os.Geteuid())
	}
	return nil
}
