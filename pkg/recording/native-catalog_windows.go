//go:build windows

package recording

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func nativeCatalogFileChange(file *os.File, _ os.FileInfo) (any, error) {
	// FILE_BASIC_INFO includes ChangeTime, unlike os.FileInfo.Sys() on Windows.
	var info struct {
		CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
		FileAttributes                                          uint32
	}
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileBasicInfo,
		(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return nil, err
	}
	info.LastAccessTime = 0 // Reads may update access time, not ChangeTime.
	return info, nil
}
