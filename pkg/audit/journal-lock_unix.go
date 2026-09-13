//go:build unix

package audit

import (
	"os"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/engity-com/bifroest/pkg/errors"
)

type journalProcessLock struct {
	file *os.File
	once sync.Once
	err  error
}

func acquireJournalProcessLock(path string, mode os.FileMode) (*journalProcessLock, error) {
	file, err := openJournalLockFile(path, mode)
	if err != nil {
		return nil, errors.System.Newf("cannot open audit journal lock file %q: %w", path, err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errors.System.Newf("audit journal %q is already locked by another process", path)
		}
		return nil, errors.System.Newf("cannot determine lock state of audit journal %q: %w", path, err)
	}
	return &journalProcessLock{file: file}, nil
}

func (this *journalProcessLock) Close() error {
	if this == nil {
		return nil
	}
	this.once.Do(func() {
		if err := unix.Flock(int(this.file.Fd()), unix.LOCK_UN); err != nil {
			this.err = errors.System.Newf("cannot release audit journal lock: %w", err)
		}
		if err := this.file.Close(); err != nil && this.err == nil {
			this.err = errors.System.Newf("cannot close audit journal lock: %w", err)
		}
	})
	return this.err
}
