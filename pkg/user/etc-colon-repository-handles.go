package user

import (
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"os"
	"path/filepath"
	"syscall"
)

type etcColonRepositoryHandles struct {
	owner  *EtcColonRepository
	passwd etcColonRepositoryHandle[etcPasswdEntry, *etcPasswdEntry]
	group  etcColonRepositoryHandle[etcGroupEntry, *etcGroupEntry]
	shadow etcColonRepositoryHandle[etcShadowEntry, *etcShadowEntry]
}

func (this *etcColonRepositoryHandles) init(owner *EtcColonRepository) error {
	success := false
	defer common.DoOnFailureIgnore(&success, this.close)

	this.owner = owner

	if err := this.passwd.init(owner.PasswdFilename, DefaultEtcPasswd, etcPasswdColons, this); err != nil {
		return err
	}
	if err := this.group.init(owner.GroupFilename, DefaultEtcGroup, etcGroupColons, this); err != nil {
		return err
	}
	if err := this.shadow.init(owner.ShadowFilename, DefaultEtcShadow, etcShadowColons, this); err != nil {
		return err
	}

	success = true
	return nil
}

func (this *etcColonRepositoryHandles) open(rw bool) (_ *openedEtcColonRepositoryHandles, rErr error) {
	success := false

	var result openedEtcColonRepositoryHandles
	var err error
	defer common.DoOnFailureIgnore(&success, result.close)

	if result.passwd, err = this.passwd.openFile(rw); err != nil {
		return nil, err
	}
	if result.group, err = this.group.openFile(rw); err != nil {
		return nil, err
	}
	if result.shadow, err = this.shadow.openFile(rw); err != nil {
		return nil, err
	}

	if rw {
		directories := this.getDirectories()
		result.lockFiles = make([]*os.File, len(directories))
		var i int
		for dir := range directories {
			fn := filepath.Join(dir, ".pwd.lock")
			if result.lockFiles[i], err = this.openFile(fn, true, false); err != nil {
				return nil, err
			}
			i++
		}
	}

	success = true
	return &result, nil
}

func (this *etcColonRepositoryHandles) openFile(fn string, rw bool, isCreateRetry bool) (*os.File, error) {
	fm := os.O_RDONLY
	lm := syscall.LOCK_SH
	if rw || isCreateRetry {
		fm = os.O_RDWR | os.O_CREATE
		lm = syscall.LOCK_EX
	}
	success := false

	result, err := os.OpenFile(fn, fm, 0600)
	if err != nil {
		if os.IsNotExist(err) && !isCreateRetry && this.owner.getCreateFilesIfAbsent() {
			_ = os.MkdirAll(filepath.Dir(fn), 0700)
			return this.openFile(fn, rw, true)
		}
		return nil, fmt.Errorf("cannot open %q: %w", fn, err)
	}
	defer common.DoOnFailureIgnore(&success, result.Close)

	if err := this.lockFile(result, lm); err != nil {
		return nil, err
	}
	success = true
	return result, nil
}

func (this *etcColonRepositoryHandles) lockFile(which *os.File, how int) error {
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

func (this *etcColonRepositoryHandles) close() (rErr error) {
	defer common.KeepError(&rErr, this.passwd.close)
	defer common.KeepError(&rErr, this.group.close)
	defer common.KeepError(&rErr, this.shadow.close)

	return nil
}

func (this *etcColonRepositoryHandles) getDirectories() map[string]struct{} {
	buf := make(map[string]struct{}, 1)
	buf[filepath.Dir(this.passwd.fn)] = struct{}{}
	buf[filepath.Dir(this.group.fn)] = struct{}{}
	buf[filepath.Dir(this.shadow.fn)] = struct{}{}
	return buf
}

func (this *etcColonRepositoryHandles) matchesFilename(name string) (bool, error) {
	var err error
	if name, err = filepath.Abs(name); err != nil {
		return false, err
	}

	if this.passwd.fn == name || this.passwd.tempFn == name {
		return true, nil
	}
	if this.group.fn == name || this.shadow.tempFn == name {
		return true, nil
	}
	if this.shadow.fn == name || this.shadow.tempFn == name {
		return true, nil
	}

	return false, nil
}

type openedEtcColonRepositoryHandles struct {
	lockFiles []*os.File

	passwd *openedEtcColonRepositoryHandle[etcPasswdEntry, *etcPasswdEntry]
	group  *openedEtcColonRepositoryHandle[etcGroupEntry, *etcGroupEntry]
	shadow *openedEtcColonRepositoryHandle[etcShadowEntry, *etcShadowEntry]
}

func (this *openedEtcColonRepositoryHandles) load() error {
	if err := this.passwd.load(); err != nil {
		return err
	}
	if err := this.group.load(); err != nil {
		return err
	}
	if err := this.shadow.load(); err != nil {
		return err
	}

	return nil
}

func (this *openedEtcColonRepositoryHandles) save() error {
	if err := this.passwd.save(); err != nil {
		return err
	}
	if err := this.group.save(); err != nil {
		return err
	}
	if err := this.shadow.save(); err != nil {
		return err
	}

	return nil
}

func (this *openedEtcColonRepositoryHandles) close() (rErr error) {
	defer common.KeepError(&rErr, this.passwd.close)
	defer common.KeepError(&rErr, this.group.close)
	defer common.KeepError(&rErr, this.shadow.close)
	for _, f := range this.lockFiles {
		defer common.KeepError(&rErr, f.Close)
	}

	return nil
}
