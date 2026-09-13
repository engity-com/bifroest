//go:build windows

package audit

import (
	"encoding/binary"
	"os"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
)

func verifierFileIdentity(path string, file *os.File, _ os.FileInfo) ([16]byte, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return [16]byte{}, errors.System.Newf("cannot determine filesystem identity of %q: %w", path, err)
	}
	var result [16]byte
	binary.BigEndian.PutUint32(result[:4], info.VolumeSerialNumber)
	binary.BigEndian.PutUint32(result[8:12], info.FileIndexHigh)
	binary.BigEndian.PutUint32(result[12:], info.FileIndexLow)
	return result, nil
}
