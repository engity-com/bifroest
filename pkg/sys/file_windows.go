//go:build windows

package sys

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func openFileForRotation(path string) (file *os.File, resultErr error) {
	defer func() {
		if resultErr != nil {
			resultErr = &os.PathError{Op: "open", Path: path, Err: resultErr}
		}
	}()
	name, err := WindowsPathPointer(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	file = os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("cannot wrap file handle")
	}
	return file, nil
}

func cloneFile(f CloneableFile) (*os.File, error) {
	var h windows.Handle
	p := windows.CurrentProcess()
	if err := windows.DuplicateHandle(p, windows.Handle(f.Fd()), p, &h, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}
	cloned := os.NewFile(uintptr(h), f.Name())
	return cloned, nil
}
