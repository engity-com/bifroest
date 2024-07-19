//go:build unix && !android

package user

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/engity-com/yasshd/pkg/sys"
	"io"
)

const (
	etcGroupFn = "/etc/group"
)

var (
	colonCommaFileSeparator = []byte(",")
	errEtcGroupEmptyGid     = errors.New("empty GID")
	errEtcGroupIllegalGid   = errors.New("illegal GID")
)

type etcGroupEntry struct {
	name      []byte
	password  []byte
	gid       uint32
	userNames [][]byte
}

func (this *etcGroupEntry) validate(allowBadName bool) error {
	if err := validateGroupName(this.name, allowBadName); err != nil {
		return err
	}
	for _, un := range this.userNames {
		if err := validateUserName(un, allowBadName); err != nil {
			return err
		}
	}
	return nil
}

func (this *etcGroupEntry) setLine(line [][]byte, allowBadName bool) error {
	var err error
	this.name = line[0]
	this.password = line[1]
	if this.gid, _, err = parseUint32Column(line, 2, errEtcGroupEmptyGid, errEtcGroupIllegalGid); err != nil {
		return err
	}
	this.userNames = bytes.Split(line[3], colonCommaFileSeparator)

	if err := this.validate(allowBadName); err != nil {
		return err
	}

	return nil
}

func decodeEtcGroup(allowBadName bool, consumer codecConsumer[*etcGroupEntry]) (rErr error) {
	f, err := sys.OpenAndLockFileForRead(etcGroupFn)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", etcGroupFn, err)
	}
	defer func() {
		if err := f.Close(); err != nil && rErr == nil {
			rErr = err
		}
	}()

	return decodeEtcGroupOf(etcGroupFn, f, allowBadName, consumer)
}

func decodeEtcGroupOf(fn string, r io.Reader, allowBadName bool, consumer codecConsumer[*etcGroupEntry]) error {
	var entry etcGroupEntry
	return parseColonFile(fn, r, 4, func(line [][]byte) error {
		if err := entry.setLine(line, allowBadName); err != nil {
			return err
		}

		return consumer(&entry)
	})
}
