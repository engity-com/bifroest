//go:build windows

package sys

import (
	"os"

	"golang.org/x/sys/windows"
)

func cloneFile(f CloneableFile) (*os.File, error) {
	var h windows.Handle
	p := windows.CurrentProcess()
	if err := windows.DuplicateHandle(p, windows.Handle(f.Fd()), p, &h, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}
	cloned := os.NewFile(uintptr(h), f.Name())
	return cloned, nil
}
