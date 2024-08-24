//go:build linux

package user

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/engity-com/bifroest/pkg/common"
)

type etcColonRepositoryHandle[T any, PT etcColonEntryValue[T]] struct {
	owner *etcColonRepositoryHandles

	fn             string
	tempFn         string
	numberOfColons int

	entries       etcColonEntries[T, PT]
	numberOfReads uint64
}

func (this *etcColonRepositoryHandle[T, PT]) init(fn, defFn string, numberOfColons int, owner *etcColonRepositoryHandles) error {
	if this.numberOfColons > 0 {
		return nil
	}

	this.owner = owner
	this.fn = fn
	if this.fn == "" {
		this.fn = defFn
	}
	this.tempFn = filepath.Join(filepath.Dir(this.fn), "n"+filepath.Base(this.fn))
	var err error
	if this.fn, err = filepath.Abs(this.fn); err != nil {
		return fmt.Errorf("cannot make %q absolute: %w", this.fn, err)
	}

	this.numberOfColons = numberOfColons
	return nil
}

func (this *etcColonRepositoryHandle[T, PT]) openFile(rw bool) (*openedEtcColonRepositoryHandle[T, PT], error) {
	if this.fn == "" {
		return nil, fmt.Errorf("was not initialized")
	}

	f, err := this.owner.openFile(this.fn, rw, false)
	if err != nil {
		return nil, err
	}
	return &openedEtcColonRepositoryHandle[T, PT]{this, f}, nil
}

func (this *etcColonRepositoryHandle[T, PT]) close() (rErr error) {
	return nil
}

type openedEtcColonRepositoryHandle[T any, PT etcColonEntryValue[T]] struct {
	*etcColonRepositoryHandle[T, PT]
	f *os.File
}

func (this *openedEtcColonRepositoryHandle[T, PT]) close() (rErr error) {
	if this == nil {
		return nil
	}
	if f := this.f; f != nil {
		defer func() {
			this.f = nil
		}()
		defer common.KeepError(&rErr, f.Close)

		return this.owner.lockFile(f, syscall.LOCK_UN)
	}
	return nil
}

func (this *openedEtcColonRepositoryHandle[T, PT]) load() error {
	if err := this.entries.decode(this.numberOfColons, this.owner.owner.getAllowBadName(), this.owner.owner.getAllowBadLine(), this.f); err != nil {
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
	return this.entries.encode(this.owner.owner.getAllowBadName(), this.f)
}
