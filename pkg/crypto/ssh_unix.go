//go:build unix

package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// DoWithEachAuthorizedKeyForUser accepts files owned by the local account,
// root, or the service account only if no other user can replace a path
// component or change the file.
func DoWithEachAuthorizedKeyForUser[R any](uid uint32, requireExistence bool, callback func(ssh.PublicKey, []AuthorizedKeyOption) (result R, canContinue bool, err error), files ...string) (R, error) {
	return doWithEachAuthorizedKey(requireExistence, callback, func(path string) (*os.File, error) {
		return openUserAuthorizedKeys(path, uid)
	}, files...)
}

func openUserAuthorizedKeys(path string, uid uint32) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	current, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(current) }()
	if err := checkUserAuthorizedKeysOwner(current, uid, true); err != nil {
		return nil, fmt.Errorf("unsafe authorized keys directory %q: %w", string(filepath.Separator), err)
	}
	components := strings.Split(strings.TrimPrefix(filepath.Clean(absolute), string(filepath.Separator)), string(filepath.Separator))
	for i, component := range components {
		last := i == len(components)-1
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if last {
			flags |= unix.O_NONBLOCK
		} else {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(current, component, flags, 0)
		if err != nil {
			return nil, err
		}
		if err := checkUserAuthorizedKeysOwner(next, uid, !last); err != nil {
			_ = unix.Close(next)
			return nil, fmt.Errorf("unsafe authorized keys path component %q: %w", component, err)
		}
		if last {
			return os.NewFile(uintptr(next), absolute), nil
		}
		_ = unix.Close(current)
		current = next
	}
	return nil, fmt.Errorf("invalid authorized keys path %q", path)
}

func checkUserAuthorizedKeysOwner(fd int, uid uint32, directory bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	// The service account can already change its own configuration and is
	// therefore trusted alongside root and the selected local account.
	if stat.Uid != 0 && stat.Uid != uid && stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("unexpected owner %d", stat.Uid)
	}
	if directory {
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return fmt.Errorf("not a directory")
		}
		// Root-owned sticky directories such as /tmp protect their entries
		// against replacement by unrelated local users.
		if stat.Mode&0022 != 0 && (stat.Uid != 0 || stat.Mode&unix.S_ISVTX == 0) {
			return fmt.Errorf("directory writable by other users")
		}
	} else {
		if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			return fmt.Errorf("not a regular file")
		}
		if stat.Mode&0022 != 0 {
			return fmt.Errorf("file writable by other users")
		}
	}
	return nil
}
