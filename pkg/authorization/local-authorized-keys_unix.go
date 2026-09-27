//go:build unix

package authorization

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/user"
)

const maximumLocalAuthorizedKeysFileSize = 16 * 1024 * 1024

func secureLocalAuthorizedKeysReader(uid user.Id) crypto.AuthorizedKeysReader {
	return func(path string) ([]byte, error) {
		file, err := openSecureLocalAuthorizedKeysFile(path, uint32(uid))
		if err != nil {
			return nil, err
		}
		defer func() { _ = file.Close() }()

		return readSecureLocalAuthorizedKeysFile(file, path)
	}
}

func openSecureLocalAuthorizedKeysFile(path string, uid uint32) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, &os.PathError{Op: "open", Path: path, Err: fmt.Errorf("authorized keys path is not absolute")}
	}

	cleaned := filepath.Clean(path)
	components := strings.Split(strings.TrimPrefix(cleaned, string(filepath.Separator)), string(filepath.Separator))
	if len(components) == 0 || components[0] == "" {
		return nil, &os.PathError{Op: "open", Path: path, Err: fmt.Errorf("authorized keys path does not name a file")}
	}

	directoryFlags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	directoryFD, err := unix.Open(string(filepath.Separator), directoryFlags, 0)
	if err != nil {
		return nil, localAuthorizedKeysPathError("open", path, err)
	}
	defer func() {
		if directoryFD >= 0 {
			_ = unix.Close(directoryFD)
		}
	}()

	if err := validateLocalAuthorizedKeysDescriptor(directoryFD, string(filepath.Separator), uid, true); err != nil {
		return nil, localAuthorizedKeysPathError("validate", path, err)
	}

	currentPath := string(filepath.Separator)
	for _, component := range components[:len(components)-1] {
		nextFD, openErr := unix.Openat(directoryFD, component, directoryFlags, 0)
		if openErr != nil {
			return nil, localAuthorizedKeysPathError("open", path, openErr)
		}
		_ = unix.Close(directoryFD)
		directoryFD = nextFD
		currentPath = filepath.Join(currentPath, component)
		if err := validateLocalAuthorizedKeysDescriptor(directoryFD, currentPath, uid, true); err != nil {
			return nil, localAuthorizedKeysPathError("validate", path, err)
		}
	}

	fileFD, err := unix.Openat(directoryFD, components[len(components)-1], unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, localAuthorizedKeysPathError("open", path, err)
	}
	if err := validateLocalAuthorizedKeysDescriptor(fileFD, cleaned, uid, false); err != nil {
		_ = unix.Close(fileFD)
		return nil, localAuthorizedKeysPathError("validate", path, err)
	}

	file := os.NewFile(uintptr(fileFD), cleaned)
	if file == nil {
		_ = unix.Close(fileFD)
		return nil, localAuthorizedKeysPathError("open", path, fmt.Errorf("cannot create file for descriptor"))
	}
	return file, nil
}

func validateLocalAuthorizedKeysDescriptor(fd int, path string, uid uint32, directory bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("cannot stat %q: %w", path, err)
	}

	return validateLocalAuthorizedKeysStat(path, uid, directory, &stat)
}

func validateLocalAuthorizedKeysStat(path string, uid uint32, directory bool, stat *unix.Stat_t) error {
	if stat.Uid != 0 && stat.Uid != uid {
		return fmt.Errorf("%q is owned by user %d instead of root or target user %d", path, stat.Uid, uid)
	}
	if stat.Mode&0022 != 0 {
		return fmt.Errorf("%q is writable by group or others", path)
	}

	fileType := stat.Mode & unix.S_IFMT
	if directory {
		if fileType != unix.S_IFDIR {
			return fmt.Errorf("parent path %q is not a directory", path)
		}
		return nil
	}
	if fileType != unix.S_IFREG {
		return fmt.Errorf("authorized keys path %q is not a regular file", path)
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("authorized keys file %q has %d hard links instead of one", path, stat.Nlink)
	}
	if stat.Size < 0 || stat.Size > maximumLocalAuthorizedKeysFileSize {
		return fmt.Errorf("authorized keys file %q exceeds the %d byte size limit", path, maximumLocalAuthorizedKeysFileSize)
	}
	return nil
}

func readSecureLocalAuthorizedKeysFile(file *os.File, path string) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(file, maximumLocalAuthorizedKeysFileSize+1))
	if err != nil {
		return nil, localAuthorizedKeysPathError("read", path, err)
	}
	if len(content) > maximumLocalAuthorizedKeysFileSize {
		return nil, localAuthorizedKeysPathError("read", path, fmt.Errorf("authorized keys file exceeds the %d byte size limit", maximumLocalAuthorizedKeysFileSize))
	}
	return content, nil
}

func localAuthorizedKeysPathError(op, path string, err error) error {
	return &os.PathError{Op: op, Path: path, Err: err}
}
