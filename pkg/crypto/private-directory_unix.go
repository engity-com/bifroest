//go:build unix

package crypto

import (
	"fmt"
	"os"
	"syscall"
)

func createPrivateDirectory(path string) error { return os.Mkdir(path, 0700) }

func validatePrivateDirectory(_ string, _ *os.File, info os.FileInfo) error {
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("private directory is accessible by group or others")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("private directory is not owned by the service user")
	}
	return nil
}
