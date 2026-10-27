//go:build unix && !darwin

package user

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"syscall"
	"time"
)

const maximumPasswordPolicyFile = 16 << 20

// CheckPasswordAccount bypasses the debounced watcher without publishing into
// its cache. Files are bounded, read-only and locked nonblockingly; absence or
// contention never creates a file or starts a detached locking goroutine.
func (this *EtcColonRepository) CheckPasswordAccount(ctx context.Context, name string, id Id, policy PasswordAccountPolicy) (current *User, resultErr error) {
	this.mutex.RLock()
	defer this.mutex.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if this.watcher == nil || this.handles.passwd.fn == "" {
		return nil, ErrPasswordAccountPolicyUnavailable
	}
	snapshot := &EtcColonRepository{
		PasswdFilename: this.handles.passwd.fn,
		GroupFilename:  this.handles.group.fn,
		ShadowFilename: this.handles.shadow.fn,
		AllowBadName:   this.AllowBadName,
		AllowBadLine:   this.AllowBadLine,
	}
	if err := snapshot.handles.init(snapshot); err != nil {
		return nil, ErrPasswordAccountPolicyUnavailable
	}
	var files []*passwordPolicyFile
	defer func() {
		for _, file := range files {
			resultErr = errors.Join(resultErr, file.Close())
		}
		if resultErr != nil {
			current = nil
		}
	}()
	for _, path := range []string{snapshot.handles.passwd.fn, snapshot.handles.group.fn, snapshot.handles.shadow.fn} {
		file, err := openPasswordPolicyFile(path)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	if err := readPasswordPolicyEntries(ctx, files[0], &snapshot.handles.passwd); err != nil {
		return nil, err
	}
	if err := readPasswordPolicyEntries(ctx, files[1], &snapshot.handles.group); err != nil {
		return nil, err
	}
	if err := readPasswordPolicyEntries(ctx, files[2], &snapshot.handles.shadow); err != nil {
		return nil, err
	}
	// A map's last-wins behavior cannot resolve an ambiguous native identity or
	// hide a malformed second entry for the account being resumed.
	passwdCount, shadowCount := 0, 0
	for _, value := range snapshot.handles.passwd.entries {
		if value.entry != nil {
			entry := value.entry
			if string(entry.name) == name || Id(entry.uid) == id {
				if string(entry.name) != name || Id(entry.uid) != id {
					return nil, ErrPasswordAccountPolicyDenied
				}
				passwdCount++
			}
		} else if passwordPolicyLineNames(value.rawLine, name) {
			return nil, ErrPasswordAccountPolicyDenied
		}
	}
	for _, value := range snapshot.handles.shadow.entries {
		if value.entry != nil && string(value.entry.name) == name {
			shadowCount++
		} else if value.entry == nil && passwordPolicyLineNames(value.rawLine, name) {
			return nil, ErrPasswordAccountPolicyDenied
		}
	}
	if passwdCount != 1 || shadowCount > 1 {
		return nil, ErrPasswordAccountPolicyDenied
	}
	snapshot.rebuildIndexes()
	ref := snapshot.nameToUser[name]
	if ref == nil || !passwordPolicyRefEligible(ref, policy, time.Now()) {
		return nil, ErrPasswordAccountPolicyDenied
	}
	current, resultErr = snapshot.refToUser(ctx, ref)
	if resultErr != nil {
		return nil, resultErr
	}
	for _, file := range files {
		if err := file.validate(); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return current, nil
}

func passwordPolicyLineNames(line []byte, name string) bool {
	first, _, _ := bytes.Cut(line, []byte(":"))
	return string(first) == name
}

func passwordPolicyRefEligible(ref *etcPasswdRef, policy PasswordAccountPolicy, now time.Time) bool {
	if shadow := ref.etcShadowEntry; shadow != nil {
		value := shadow.password
		if len(value) == 0 || value[0] == '!' || value[0] == '*' || shadow.lastChangedAtInDays == 0 {
			return false
		}
		// Widen before arithmetic; malicious/invalid uint32 fields must not wrap
		// an expiry deadline back into a supposedly usable account state.
		today := now.Unix() / (24 * 60 * 60)
		changed := uint64(shadow.lastChangedAtInDays)
		if today < 0 || changed > uint64(today) {
			return false
		}
		passwordExpires := changed + uint64(shadow.maximumAgeInDays)
		if passwordExpires <= uint64(today) || shadow.hasExpire && uint64(shadow.expireAtTsInDays) <= uint64(today) {
			return false
		}
		return !shadow.hasInactiveAge || passwordExpires+uint64(shadow.inactiveAgeInDays) > uint64(today)
	}
	value := ref.etcPasswdEntry.password
	if bytes.Equal(value, []byte("x")) || len(value) > 0 && (value[0] == '!' || value[0] == '*') {
		return false
	}
	return len(value) > 0 || policy.AllowEmpty
}

type passwordPolicyFile struct {
	*os.File
	path   string
	before os.FileInfo
}

func openPasswordPolicyFile(path string) (*passwordPolicyFile, error) {
	before, err := os.Stat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > maximumPasswordPolicyFile {
		return nil, ErrPasswordAccountPolicyUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrPasswordAccountPolicyUnavailable
	}
	result := &passwordPolicyFile{file, path, before}
	if syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB) != nil || result.validate() != nil {
		_ = file.Close()
		return nil, ErrPasswordAccountPolicyUnavailable
	}
	return result, nil
}

func (this *passwordPolicyFile) validate() error {
	opened, err := this.Stat()
	if err != nil {
		return ErrPasswordAccountPolicyUnavailable
	}
	current, err := os.Stat(this.path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(this.before, opened) || !os.SameFile(opened, current) || this.before.Size() != opened.Size() || this.before.Mode() != opened.Mode() || !this.before.ModTime().Equal(opened.ModTime()) || opened.Size() != current.Size() || opened.Mode() != current.Mode() || !opened.ModTime().Equal(current.ModTime()) {
		return ErrPasswordAccountPolicyUnavailable
	}
	return nil
}

type passwordPolicySource struct{ io.Reader }

func (passwordPolicySource) Name() string { return "native account policy" }

func readPasswordPolicyEntries[T any, PT etcColonEntryValue[T]](ctx context.Context, file *passwordPolicyFile, handle *etcColonRepositoryHandle[T, PT]) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	reader := &io.LimitedReader{R: file, N: maximumPasswordPolicyFile + 1}
	if err := handle.entries.decode(handle.numberOfColons, handle.owner.owner.getAllowBadName(), handle.owner.owner.getAllowBadLine(), passwordPolicySource{reader}); err != nil || reader.N == 0 {
		return ErrPasswordAccountPolicyUnavailable
	}
	return ctx.Err()
}
