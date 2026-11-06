//go:build windows

package metadatacache

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

func identityAndChange(file *os.File, _ os.FileInfo) (string, error) {
	var identity windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &identity); err != nil {
		return "", err
	}
	var change struct {
		CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
		Attributes                                              uint32
	}
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileBasicInfo, (*byte)(unsafe.Pointer(&change)), uint32(unsafe.Sizeof(change))); err != nil {
		return "", err
	}
	change.LastAccessTime = 0
	return fmt.Sprintf("%d/%d/%d/%#v", identity.VolumeSerialNumber, identity.FileIndexHigh, identity.FileIndexLow, change), nil
}
