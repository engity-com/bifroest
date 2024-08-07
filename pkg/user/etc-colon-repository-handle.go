package user

import (
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/fsnotify/fsnotify"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

type etcColonRepositoryHandle[T any, PT etcColonEntryValue[T]] struct {
	owner *EtcColonRepository

	fn             string
	numberOfColons int

	watcher       *fsnotify.Watcher
	entries       etcColonEntries[T, PT]
	numberOfReads uint64
}

func (this *etcColonRepositoryHandle[T, PT]) init(fn, defFn string, numberOfColons int, owner *EtcColonRepository) error {
	if this.watcher != nil {
		return nil
	}

	this.owner = owner
	this.fn = fn
	if this.fn == "" {
		this.fn = defFn
	}
	this.numberOfColons = numberOfColons

	success := false
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("cannot initialize file watcher for %q: %w", this.fn, err)
	}
	defer func() {
		if !success {
			_ = watcher.Close()
		}
	}()
	this.watcher = watcher
	defer func() {
		if !success {
			this.watcher = nil
		}
	}()

	go this.watchForChanges(watcher)

	if err := watcher.Add(this.fn); err != nil {
		fail := func(err error) error {
			return fmt.Errorf("cannot watch for filesystem changes of %q: %w", this.fn, err)
		}
		if os.IsNotExist(err) {
			if this.owner.getCreateFilesIfAbsent() {
				_ = os.MkdirAll(filepath.Dir(this.fn), 0700)
				if f, oErr := os.OpenFile(this.fn, os.O_CREATE|os.O_EXCL, 0600); oErr != nil && !os.IsExist(oErr) {
					return fail(err)
				} else {
					defer common.IgnoreCloseError(f)
				}
				if aErr := watcher.Add(this.fn); aErr != nil {
					return fail(aErr)
				}
			} else {
				return &fs.PathError{
					Op:   "open",
					Path: this.fn,
					Err:  os.ErrNotExist,
				}
			}
		} else {
			return fail(err)
		}
	}

	success = true
	return nil
}

func (this *etcColonRepositoryHandle[T, PT]) watchForChanges(watcher *fsnotify.Watcher) {
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			l := this.owner.logger().
				With("op", event.Op).
				With("file", this.fn)

			if event.Has(fsnotify.Remove) {
				// TODO! Add handling of remove event ... although this should be really not normal behavior.
				this.owner.onUnhandledAsyncError(l, ErrEtcColonRepositoryUnsupportedRemove, "")
			} else if event.Has(fsnotify.Rename) {
				// TODO! Add handling of rename event ... although this should be really not normal behavior.
				this.owner.onUnhandledAsyncError(l, ErrEtcColonRepositoryUnsupportedRename, "")
			} else if event.Has(fsnotify.Write) {
				this.owner.scheduleReload(l)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			l := this.owner.logger().
				With("file", this.fn)
			this.owner.onUnhandledAsyncError(l, err, "error while handling file watcher events")
		}
	}
}

func (this *etcColonRepositoryHandle[T, PT]) openFile(rw bool) (*openedEtcColonRepositoryHandle[T, PT], error) {
	if this.fn == "" {
		return nil, fmt.Errorf("was not initialized")
	}

	fm := os.O_RDONLY
	lm := syscall.LOCK_SH
	if rw {
		fm = os.O_RDWR | os.O_CREATE
		lm = syscall.LOCK_EX
	}
	success := false

	var err error
	result := openedEtcColonRepositoryHandle[T, PT]{etcColonRepositoryHandle: this}
	if result.f, err = os.OpenFile(this.fn, fm, 0600); err != nil {
		return nil, fmt.Errorf("cannot open %q: %w", this.fn, err)
	}
	defer func() {
		if !success {
			_ = result.f.Close()
		}
	}()

	if err := this.lockFile(result.f, lm); err != nil {
		return nil, err
	}
	success = true
	return &result, nil
}

func (this *etcColonRepositoryHandle[T, PT]) lockFile(which *os.File, how int) error {
	done := false
	doneErrChan := make(chan error, 1)
	defer close(doneErrChan)

	go func(fd, how int) {
		for {
			err := syscall.Flock(fd, how)

			//goland:noinspection GoDirectComparisonOfErrors
			if err == syscall.EINTR {
				if done {
					return
				}
				continue
			}
			doneErrChan <- err
			return
		}
	}(int(which.Fd()), how)

	fail := func(err error) error {
		if err == nil {
			return nil
		}
		var op string
		switch how {
		case syscall.LOCK_EX:
			op = "lock file for write"
		case syscall.LOCK_UN:
			op = "unlock file"
		default:
			op = "lock file for read"
		}
		return fmt.Errorf("cannot %s %q: %w", op, which.Name(), err)
	}
	select {
	case doneErr := <-doneErrChan:
		return fail(doneErr)
	}
}

func (this *etcColonRepositoryHandle[T, PT]) close() (rErr error) {
	if watcher := this.watcher; watcher != nil {
		defer func() {
			this.watcher = nil
		}()
		common.KeepCloseError(&rErr, watcher)
	}

	return nil
}

type openedEtcColonRepositoryHandle[T any, PT etcColonEntryValue[T]] struct {
	*etcColonRepositoryHandle[T, PT]
	f *os.File
}

func (this *openedEtcColonRepositoryHandle[T, PT]) close() (rErr error) {
	if f := this.f; f != nil {
		defer func() {
			this.f = nil
		}()
		defer common.KeepError(&rErr, f.Close)

		return this.lockFile(f, syscall.LOCK_UN)
	}
	return nil
}

func (this *openedEtcColonRepositoryHandle[T, PT]) load() error {
	if err := this.entries.decode(this.numberOfColons, this.owner.getAllowBadName(), this.owner.getAllowBadLine(), this.f); err != nil {
		return err
	}

	this.numberOfReads++
	return nil
}

func (this *openedEtcColonRepositoryHandle[T, PT]) save() error {
	if _, err := this.f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("cannot go to start of %q before write: %w", this.fn, err)
	}
	if err := this.f.Truncate(0); err != nil {
		return fmt.Errorf("cannot truncate %q: %w", this.fn, err)
	}
	return this.entries.encode(this.owner.getAllowBadName(), this.f)
}
