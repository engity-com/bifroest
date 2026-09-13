//go:build windows

package audit

import (
	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/sys"
)

func availableJournalBytes(path string) (uint64, error) {
	directory, err := sys.WindowsPathPointer(path)
	if err != nil {
		return 0, err
	}
	var available uint64
	if err := windows.GetDiskFreeSpaceEx(directory, &available, nil, nil); err != nil {
		return 0, err
	}
	return available, nil
}
