//go:build unix

package crypto

import (
	"os"
	"syscall"
)

func validateServicePrivateKeyFile(path string, file *os.File, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	// Root-owned, no owner/group writes, no access for others, one hard link,
	// and the primary service group only. Do not trust supplementary groups.
	if ok && stat.Uid == 0 && stat.Gid == uint32(os.Getegid()) && stat.Nlink == 1 && info.Mode().Perm()&^0440 == 0 {
		return nil
	}
	return validateSecurePrivateKeyFile(path, file, info)
}
