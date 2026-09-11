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
)

func createProtectedTempFile(parent, pattern string, _ os.FileMode) (*os.File, error) {
	if !strings.HasSuffix(pattern, "*") {
		return nil, fmt.Errorf("temporary file pattern %q does not end in *", pattern)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;OW)")
	if err != nil {
		return nil, err
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
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

func windowsPathPointer(path string) (*uint16, error) {
	extended, err := windowsExtendedPath(path)
	if err != nil {
		return nil, err
	}
	return windows.UTF16PtrFromString(extended)
}

func windowsExtendedPath(path string) (string, error) {
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
