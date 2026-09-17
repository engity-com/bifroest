//go:build windows

package main

import (
	crand "crypto/rand"
	"encoding/hex"
	goerrors "errors"
	"fmt"
	"io"
	stdos "os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/sys"
)

func snapshotRecordingInput(input *stdos.File, size int64) (_ *stdos.File, rErr error) {
	if input == nil || size < 1 {
		return nil, fmt.Errorf("illegal Recording snapshot input")
	}
	if err := validateRecordingSnapshotSize(input, size); err != nil {
		return nil, err
	}
	snapshot, err := createWindowsRecordingSnapshot()
	if err != nil {
		return nil, err
	}
	defer func() {
		if rErr != nil {
			rErr = goerrors.Join(rErr, snapshot.Close())
			if err := stdos.Remove(snapshot.Name()); err != nil && !goerrors.Is(err, stdos.ErrNotExist) {
				rErr = goerrors.Join(rErr, err)
			}
		}
	}()
	written, err := io.Copy(snapshot, io.NewSectionReader(input, 0, size))
	if err != nil {
		return nil, err
	}
	if written != size {
		return nil, fmt.Errorf("recording input changed while being snapshotted")
	}
	if err := snapshot.Sync(); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func createWindowsRecordingSnapshot() (*stdos.File, error) {
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;OW)")
	if err != nil {
		return nil, err
	}
	attributes := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	for range 100 {
		var random [16]byte
		if _, err := crand.Read(random[:]); err != nil {
			return nil, err
		}
		path := filepath.Join(stdos.TempDir(), ".bifroest-recording-input-"+hex.EncodeToString(random[:]))
		name, err := sys.WindowsPathPointer(path)
		if err != nil {
			return nil, err
		}
		handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if goerrors.Is(err, windows.ERROR_FILE_EXISTS) || goerrors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return stdos.NewFile(uintptr(handle), path), nil
	}
	return nil, fmt.Errorf("cannot create a unique private Recording snapshot")
}
