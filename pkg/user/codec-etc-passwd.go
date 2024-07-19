//go:build unix && !android

package user

import (
	"errors"
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
	errEtcPasswdEmptyHomeDir   = errors.New("empty home directory")
	errEtcPasswdTooLongHomeDir = errors.New("home directory is longer than 255 characters")
	errEtcPasswdIllegalHomeDir = errors.New("illegal home directory")
	errEtcPasswdEmptyShell     = errors.New("empty shell")
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
	if err := validateColonFilePathColumn(this.homeDir, errEtcPasswdEmptyHomeDir, errEtcPasswdTooLongHomeDir, errEtcPasswdIllegalHomeDir); err != nil {
		return err
	}
	if err := validateColonFilePathColumn(this.shell, errEtcPasswdEmptyShell, errEtcPasswdTooLongShell, errEtcPasswdIllegalShell); err != nil {
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
	return decodeEtcPasswdFromFile(etcPasswdFn, allowBadName, consumer)
}

func decodeEtcPasswdFromFile(fn string, allowBadName bool, consumer codecConsumer[*etcPasswdEntry]) (rErr error) {
	return decodeColonLinesFromFile(fn, allowBadName, consumer, decodeEtcPasswdFromReader)
}

func decodeEtcPasswdFromReader(fn string, r io.Reader, allowBadName bool, consumer codecConsumer[*etcPasswdEntry]) error {
	return decodeColonLinesFromReader(fn, r, allowBadName, 7, consumer)
}
