package common

import (
	"io/fs"
	"os"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/sys"
)

type outputMount uint32

func locateSingleLinkOutput(output *os.File, _ fs.FileInfo) (string, outputMount, bool) {
	// The old Go directory-entry mode follows directory reparse points during
	// inventory walks. Keep that conservative walk when explicitly requested.
	if strings.Contains(","+os.Getenv("GODEBUG")+",", ",winsymlink=0,") {
		return "", 0, false
	}
	handle := windows.Handle(output.Fd())
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil || info.NumberOfLinks != 1 {
		return "", 0, false
	}
	for size := uint32(256); size <= 32768; {
		buffer := make([]uint16, size)
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], size, 0)
		if err != nil || length == 0 {
			return "", 0, false
		}
		if length < size {
			return windows.UTF16ToString(buffer[:length]), outputMount(info.VolumeSerialNumber), true
		}
		size = length + 1
	}
	return "", 0, false
}

func (this outputMount) matches(directory string) bool {
	name, err := sys.WindowsPathPointer(directory)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return false
	}
	return uint32(this) == info.VolumeSerialNumber
}
