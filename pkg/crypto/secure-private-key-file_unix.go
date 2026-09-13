//go:build unix

package crypto

import (
	"fmt"
	"os"
	"syscall"
)

func validateSecurePrivateKeyFile(path string, _ *os.File, info os.FileInfo) error {
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("private key %q is accessible by group or others", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner and link count of private key %q", path)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("private key %q is owned by user %d instead of %d", path, stat.Uid, os.Geteuid())
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("private key %q has %d hard links instead of one", path, stat.Nlink)
	}
	return nil
}
