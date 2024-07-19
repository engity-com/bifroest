//go:build unix && !android

package user

import (
	"errors"
	"fmt"
	"github.com/engity-com/yasshd/pkg/sys"
	"io"
)

const (
	etcPasswdFn = "/etc/passwd"
)

var (
	shadowedPassword = []byte("x")

	errEtcPasswdEmptyUid       = errors.New("empty UID")
	errEtcPasswdIllegalUid     = errors.New("illegal UID")
	errEtcPasswdEmptyGid       = errors.New("empty GID")
	errEtcPasswdIllegalGid     = errors.New("illegal GID")
	errEtcPasswdTooLongHomeDir = errors.New("home directory is longer than 255 characters")
	errEtcPasswdIllegalHomeDir = errors.New("illegal home directory")
	errEtcPasswdTooLongShell   = errors.New("shell is longer than 255 characters")
	errEtcPasswdIllegalShell   = errors.New("illegal shell")
)

type etcPasswdEntry struct {
	name     []byte
	password []byte
	uid      uint32
	gid      uint32
	geocs    []byte
	homeDir  []byte
	shell    []byte
}

func (this *etcPasswdEntry) validate(allowBadName bool) error {
	if err := validateUserName(this.name, allowBadName); err != nil {
		return err
	}
	if err := validateGeocs(this.geocs); err != nil {
		return err
	}
	if err := validateColonFilePathColumn(this.homeDir, errEtcPasswdTooLongHomeDir, errEtcPasswdIllegalHomeDir); err != nil {
		return err
	}
	if err := validateColonFilePathColumn(this.shell, errEtcPasswdTooLongShell, errEtcPasswdIllegalShell); err != nil {
		return err
	}
	return nil
}

func (this *etcPasswdEntry) setLine(line [][]byte, allowBadName bool) error {
	var err error
	this.name = line[0]
	this.password = line[1]
	if this.uid, _, err = parseUint32Column(line, 2, errEtcPasswdEmptyUid, errEtcPasswdIllegalUid); err != nil {
		return err
	}
	if this.gid, _, err = parseUint32Column(line, 3, errEtcPasswdEmptyGid, errEtcPasswdIllegalGid); err != nil {
		return err
	}
	this.geocs = line[4]
	this.homeDir = line[5]
	this.shell = line[6]

	if err := this.validate(allowBadName); err != nil {
		return err
	}

	return nil
}

func decodeEtcPasswd(allowBadName bool, consumer codecConsumer[*etcPasswdEntry]) (rErr error) {
	f, err := sys.OpenAndLockFileForRead(etcPasswdFn)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", etcPasswdFn, err)
	}
	defer func() {
		if err := f.Close(); err != nil && rErr == nil {
			rErr = err
		}
	}()

	return decodeEtcPasswdOf(etcPasswdFn, f, allowBadName, consumer)
}

func decodeEtcPasswdOf(fn string, r io.Reader, allowBadName bool, consumer codecConsumer[*etcPasswdEntry]) error {
	var entry etcPasswdEntry
	return parseColonFile(fn, r, 7, func(line [][]byte) error {
		if err := entry.setLine(line, allowBadName); err != nil {
			return err
		}

		return consumer(&entry)
	})
}
