//go:build windows

package audit

import (
	"os"
	"sync"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
)

type journalProcessLock struct {
	file       *os.File
	overlapped windows.Overlapped
	once       sync.Once
	err        error
}

func acquireJournalProcessLock(path string, mode os.FileMode) (*journalProcessLock, error) {
	file, err := openJournalLockFile(path, mode)
	if err != nil {
		return nil, errors.System.Newf("cannot open audit journal lock file %q: %w", path, err)
	}
	result := &journalProcessLock{file: file}
	err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &result.overlapped)
	if err != nil {
		_ = file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errors.System.Newf("audit journal %q is already locked by another process", path)
		}
		return nil, errors.System.Newf("cannot determine lock state of audit journal %q: %w", path, err)
	}
	return result, nil
}

func (this *journalProcessLock) Close() error {
	if this == nil {
		return nil
	}
	this.once.Do(func() {
		if err := windows.UnlockFileEx(windows.Handle(this.file.Fd()), 0, 1, 0, &this.overlapped); err != nil {
			this.err = errors.System.Newf("cannot release audit journal lock: %w", err)
		}
		if err := this.file.Close(); err != nil && this.err == nil {
			this.err = errors.System.Newf("cannot close audit journal lock: %w", err)
		}
	})
	return this.err
}
