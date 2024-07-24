//go:build unix && !android

package user

import (
	"errors"
	"strconv"
)

const (
	etcPasswdFn     = "/etc/passwd"
	etcPasswdColons = 7
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

func (this *etcPasswdEntry) encodeLine(allowBadName bool) ([][]byte, error) {
	if err := this.validate(allowBadName); err != nil {
		return nil, err
	}

	line := make([][]byte, 7)
	line[0] = this.name
	line[1] = this.password
	line[2] = []byte(strconv.FormatUint(uint64(this.uid), 10))
	line[3] = []byte(strconv.FormatUint(uint64(this.gid), 10))
	line[4] = this.geocs
	line[5] = this.homeDir
	line[6] = this.shell

	return line, nil

}
