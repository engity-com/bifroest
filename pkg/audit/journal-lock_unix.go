//go:build unix

package audit

import (
	goerrors "errors"
	"os"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/engity-com/bifroest/pkg/errors"
)

type journalProcessLock struct {
	file *os.File
	path string
	once sync.Once
	err  error
}

func openJournalLockFile(path string, mode os.FileMode) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, mode)
	if err != nil {
		return nil, err
	}
	return prepareJournalLockFile(path, file)
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
	return &journalProcessLock{file: file, path: path}, nil
}

func sameJournalProcessLockFile(file *os.File, path string) (bool, error) {
	openInfo, err := file.Stat()
	if err != nil {
		return false, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	return pathInfo.Mode().IsRegular() && os.SameFile(openInfo, pathInfo), nil
}

func (this *journalProcessLock) Close() error {
	if this == nil {
		return nil
	}
	this.once.Do(func() {
		this.err = removeJournalProcessLock(this, this.path)
		if err := unix.Flock(int(this.file.Fd()), unix.LOCK_UN); err != nil {
			this.err = goerrors.Join(this.err, errors.System.Newf("cannot release audit journal lock: %w", err))
		}
		if err := this.file.Close(); err != nil {
			this.err = goerrors.Join(this.err, errors.System.Newf("cannot close audit journal lock: %w", err))
		}
	})
	return this.err
}
