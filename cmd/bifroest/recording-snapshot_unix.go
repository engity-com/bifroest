//go:build unix

package main

import (
	goerrors "errors"
	"fmt"
	"io"
	stdos "os"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func snapshotRecordingInput(input *stdos.File, size int64) (_ *stdos.File, rErr error) {
	if input == nil || size < 1 {
		return nil, fmt.Errorf("illegal Recording snapshot input")
	}
	if err := validateRecordingSnapshotSize(input, size); err != nil {
		return nil, err
	}
	writable, err := bfcrypto.CreateProtectedTempFile(stdos.TempDir(), ".bifroest-recording-input-*", 0600)
	if err != nil {
		return nil, err
	}
	path := writable.Name()
	defer func() {
		if writable != nil {
			rErr = goerrors.Join(rErr, writable.Close())
		}
		if err := stdos.Remove(path); err != nil && !goerrors.Is(err, stdos.ErrNotExist) {
			rErr = goerrors.Join(rErr, err)
		}
	}()
	written, err := io.Copy(writable, io.NewSectionReader(input, 0, size))
	if err != nil {
		return nil, err
	}
	if written != size {
		return nil, fmt.Errorf("recording input changed while being snapshotted")
	}
	if err := writable.Sync(); err != nil {
		return nil, err
	}
	if err := writable.Chmod(0400); err != nil {
		return nil, err
	}
	readonly, err := openRecordingFile(path)
	if err != nil {
		return nil, err
	}
	writableInfo, err := writable.Stat()
	if err != nil {
		_ = readonly.Close()
		return nil, err
	}
	readonlyInfo, err := readonly.Stat()
	if err != nil || !stdos.SameFile(writableInfo, readonlyInfo) {
		return nil, goerrors.Join(fmt.Errorf("recording snapshot changed while being sealed"), err, readonly.Close())
	}
	if err := writable.Close(); err != nil {
		_ = readonly.Close()
		writable = nil
		return nil, err
	}
	writable = nil
	if err := stdos.Remove(path); err != nil {
		_ = readonly.Close()
		return nil, err
	}
	return readonly, nil
}
