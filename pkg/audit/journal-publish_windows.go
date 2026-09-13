//go:build windows

package audit

import (
	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/sys"
)

func publishJournalFile(source, target string) error {
	from, err := sys.WindowsPathPointer(source)
	if err != nil {
		return err
	}
	to, err := sys.WindowsPathPointer(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}
