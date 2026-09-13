//go:build windows

package crypto

import (
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/sys"
)

func createProtectedTempFile(parent, pattern string, _ os.FileMode) (*os.File, error) {
	if !strings.HasSuffix(pattern, "*") {
		return nil, fmt.Errorf("temporary file pattern %q does not end in *", pattern)
	}
	attributes, err := protectedWindowsSecurityAttributes()
	if err != nil {
		return nil, err
	}
	prefix := strings.TrimSuffix(pattern, "*")
	for range 100 {
		var random [16]byte
		if _, err := crand.Read(random[:]); err != nil {
			return nil, err
		}
		path := filepath.Join(parent, prefix+hex.EncodeToString(random[:]))
		name, err := windowsPathPointer(path)
		if err != nil {
			return nil, err
		}
		handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(handle), path), nil
	}
	return nil, fmt.Errorf("cannot create a unique temporary file in %q", parent)
}

func createProtectedTempDirectory(parent, pattern string) (string, error) {
	if !strings.HasSuffix(pattern, "*") {
		return "", fmt.Errorf("temporary directory pattern %q does not end in *", pattern)
	}
	attributes, err := protectedWindowsSecurityAttributes()
	if err != nil {
		return "", err
	}
	prefix := strings.TrimSuffix(pattern, "*")
	for range 100 {
		var random [16]byte
		if _, err := crand.Read(random[:]); err != nil {
			return "", err
		}
		path := filepath.Join(parent, prefix+hex.EncodeToString(random[:]))
		name, err := windowsPathPointer(path)
		if err != nil {
			return "", err
		}
		err = windows.CreateDirectory(name, attributes)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return "", err
		}
		return path, nil
	}
	return "", fmt.Errorf("cannot create a unique temporary directory in %q", parent)
}

func protectedWindowsSecurityAttributes() (*windows.SecurityAttributes, error) {
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;OW)")
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}, nil
}

func windowsPathPointer(path string) (*uint16, error) {
	return sys.WindowsPathPointer(path)
}

func windowsExtendedPath(path string) (string, error) {
	return sys.WindowsExtendedPath(path)
}
