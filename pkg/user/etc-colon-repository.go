//go:build unix && !android

package user

import (
	"context"
	"fmt"
	log "github.com/echocat/slf4g"
	"os"
	"sync"
	"syscall"

	"github.com/fsnotify/fsnotify"
)

var (
	ErrEtcColonRepositoryUnsupportedRemove error = StringError("etc colon repository does not support removing of files")
	ErrEtcColonRepositoryUnsupportedRename error = StringError("etc colon repository does not support renaming of files")
)

type EtcColonRepository struct {
	PasswdFilename        string
	GroupFilename         string
	ShadowFilename        string
	AllowBadName          bool
	AllowBadLine          bool
	OnUnhandledAsyncError func(logger log.Logger, err error, detail string)

	handles     etcUnixModifierHandles
	initOne     sync.Once
	initialized bool
}

func (this *EtcColonRepository) Init(ctx context.Context) error {
	if err := this.handles.init(ctx, this); err != nil {
		return err
	}
	return nil
}

func (this *EtcColonRepository) write(ctx context.Context) error {
	return this.handles.write(ctx)
}

func (this *EtcColonRepository) Close() error {
	return this.handles.Close()
}

func (this *EtcColonRepository) onUnhandledAsyncError(logger log.Logger, err error, detail string) {
	if f := this.OnUnhandledAsyncError; f != nil {
		f(logger, err, detail)
		return
	}

	canAddErrIfPresent := true
	msgPrefix := detail

	if msgPrefix == "" {
		if sErr, ok := err.(StringError); ok {
			msgPrefix = string(sErr)
			canAddErrIfPresent = false
		} else {
			msgPrefix = "unknown error"
		}
	}

	if canAddErrIfPresent && err != nil {
		logger = logger.WithError(err)
	}

	logger.Fatal(msgPrefix + "; will exit now to and hope for a restart of this service to reset the state (exit code 17)")
	os.Exit(17)
}

type etcUnixModifierHandles struct {
	passwd etcUnixModifierFileHandle[etcPasswdEntry, *etcPasswdEntry]
	group  etcUnixModifierFileHandle[etcGroupEntry, *etcGroupEntry]
	shadow etcUnixModifierFileHandle[etcShadowEntry, *etcShadowEntry]
}

func (this *etcUnixModifierHandles) init(ctx context.Context, owner *EtcColonRepository) error {
	success := false
	defer func() {
		if !success {
			_ = this.Close()
		}
	}()

	if err := this.passwd.init(ctx, owner.PasswdFilename, etcPasswdFn, etcPasswdColons, owner); err != nil {
		return err
	}
	if err := this.group.init(ctx, owner.GroupFilename, etcGroupFn, etcGroupColons, owner); err != nil {
		return err
	}
	if err := this.shadow.init(ctx, owner.ShadowFilename, etcShadowFn, etcShadowColons, owner); err != nil {
		return err
	}

	success = true
	return nil
}

func (this *etcUnixModifierHandles) write(ctx context.Context) error {
	if err := this.passwd.write(ctx); err != nil {
		return err
	}
	if err := this.group.write(ctx); err != nil {
		return err
	}
	if err := this.shadow.write(ctx); err != nil {
		return err
	}

	return nil
}

func (this *etcUnixModifierHandles) Close() (rErr error) {
	defer func() {
		if err := this.passwd.Close(); err != nil && rErr == nil {
			rErr = err
		}
	}()
	defer func() {
		if err := this.group.Close(); err != nil && rErr == nil {
			rErr = err
		}
	}()
	defer func() {
		if err := this.shadow.Close(); err != nil && rErr == nil {
			rErr = err
		}
	}()

	return nil
}

type etcUnixModifierFileHandle[T any, PT etcColonEntryValue[T]] struct {
	owner *EtcColonRepository

	fn             string
	numberOfColons int

	watcher       *fsnotify.Watcher
	entries       etcColonEntries[T, PT]
	numberOfReads uint64

	mutex sync.RWMutex
}

func (this *etcUnixModifierFileHandle[T, PT]) init(ctx context.Context, fn, defFn string, numberOfColons int, owner *EtcColonRepository) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()

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

	if err := this.read(ctx, nil); err != nil {
		return err
	}
	if err := watcher.Add(this.fn); err != nil {
		return fmt.Errorf("cannot watch for filesystem changes of %q: %w", this.fn, err)
	}

	success = true
	return nil
}

func (this *etcUnixModifierFileHandle[T, PT]) watchForChanges(watcher *fsnotify.Watcher) {
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			l := log.
				With("op", event.Op).
				With("file", this.fn)

			if event.Has(fsnotify.Remove) {
				// TODO! Add handling of remove event ... although this should be really not normal behavior.
				this.owner.onUnhandledAsyncError(l, ErrEtcColonRepositoryUnsupportedRemove, "")
			} else if event.Has(fsnotify.Rename) {
				// TODO! Add handling of rename event ... although this should be really not normal behavior.
				this.owner.onUnhandledAsyncError(l, ErrEtcColonRepositoryUnsupportedRename, "")
			} else if event.Has(fsnotify.Write) {
				l.Info("detected change of file; reloading...")
				if err := this.read(context.Background(), &this.mutex); err != nil {
					this.owner.onUnhandledAsyncError(l, err, "cannot update repository after file write event")
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			l := log.
				With("file", this.fn)
			this.owner.onUnhandledAsyncError(l, err, "error while handling file watcher events")
		}
	}
}

func (this *etcUnixModifierFileHandle[T, PT]) read(ctx context.Context, mutex sync.Locker) (rErr error) {
	if this.fn == "" || this.watcher == nil {
		return fmt.Errorf("was not initialized")
	}

	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}

	f, err := this.openFile(ctx, false)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil && rErr == nil {
			rErr = err
		}
	}()

	if err := this.entries.readFrom(ctx, this.numberOfColons, this.owner.AllowBadName, this.owner.AllowBadLine, f); err != nil {
		return err
	}

	this.numberOfReads++
	return nil
}

func (this *etcUnixModifierFileHandle[T, PT]) openFile(ctx context.Context, write bool) (*os.File, error) {
	fm := os.O_RDONLY
	lm := syscall.LOCK_SH
	if write {
		fm = os.O_RDONLY | os.O_TRUNC | os.O_CREATE
		lm = syscall.LOCK_EX
	}
	success := false

	f, err := os.OpenFile(this.fn, fm, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open %q: %w", this.fn, err)
	}
	defer func() {
		if !success {
			_ = f.Close()
		}
	}()

	if err := this.lockFile(ctx, f, lm); err != nil {
		return nil, err
	}
	defer func() {
		if !success {
			_ = this.lockFile(nil, f, syscall.LOCK_UN)
		}
	}()

	success = true
	return f, nil
}

func (this *etcUnixModifierFileHandle[T, PT]) closeFile(f *os.File) (rErr error) {
	if f == nil {
		return nil
	}

	defer func() {
		if err := f.Close(); err != nil && rErr == nil {
			rErr = err
		}
	}()

	return this.lockFile(nil, f, syscall.LOCK_UN)
}

func (this *etcUnixModifierFileHandle[T, PT]) lockFile(ctx context.Context, which *os.File, how int) error {
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

	if ctx == nil {
		ctx = context.Background()
	}

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
	case <-ctx.Done():
		_ = syscall.Kill(os.Getpid(), syscall.SIGUSR1)
		return fail(ctx.Err())
	case doneErr := <-doneErrChan:
		return fail(doneErr)
	}
}

func (this *etcUnixModifierFileHandle[T, PT]) write(ctx context.Context) (rErr error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	f, err := this.openFile(ctx, true)
	if err != nil {
		return err
	}
	defer func() {
		if err := this.closeFile(f); err != nil && rErr == nil {
			rErr = err
		}
	}()

	return this.entries.writeTo(ctx, this.owner.AllowBadName, f)
}

func (this *etcUnixModifierFileHandle[T, PT]) Close() error {
	return this.close(&this.mutex)
}

func (this *etcUnixModifierFileHandle[T, PT]) close(mutex sync.Locker) (rErr error) {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}

	if watcher := this.watcher; watcher != nil {
		defer func() {
			this.watcher = nil
		}()
		return watcher.Close()
	}

	return nil
}
