//go:build windows

package recording

import (
	goerrors "errors"
	"os"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
)

type localInventoryFileIdentity struct {
	volume uint32
	index  uint64
}

func inventoryLocalFileIdentity(path string, expected os.FileInfo) (localInventoryFileIdentity, error) {
	file, err := os.Open(path)
	if err != nil {
		return localInventoryFileIdentity{}, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(expected, opened) {
		return localInventoryFileIdentity{}, goerrors.Join(errors.System.Newf("local recording file changed during spool inventory"), err, file.Close())
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &information); err != nil {
		return localInventoryFileIdentity{}, goerrors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return localInventoryFileIdentity{}, err
	}
	return localInventoryFileIdentity{
		volume: information.VolumeSerialNumber,
		index:  uint64(information.FileIndexHigh)<<32 | uint64(information.FileIndexLow),
	}, nil
}
