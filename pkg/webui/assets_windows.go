//go:build windows

package webui

import (
	"os"

	"golang.org/x/sys/windows"
)

func singleLink(file *os.File, _ os.FileInfo) bool {
	var info windows.ByHandleFileInformation
	return windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info) == nil && info.NumberOfLinks == 1
}
