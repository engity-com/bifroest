//go:build unix && !android

package user

import (
	"bytes"
	"errors"
	"strconv"
)

const (
	etcGroupFn     = "/etc/group"
	etcGroupColons = 4
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
	if len(line[3]) > 0 {
		this.userNames = bytes.Split(line[3], colonCommaFileSeparator)
	} else {
		this.userNames = nil
	}

	if err := this.validate(allowBadName); err != nil {
		return err
	}

	return nil
}

func (this *etcGroupEntry) encodeLine(allowBadName bool) ([][]byte, error) {
	if err := this.validate(allowBadName); err != nil {
		return nil, err
	}

	line := make([][]byte, 4)
	line[0] = this.name
	line[1] = this.password
	line[2] = []byte(strconv.FormatUint(uint64(this.gid), 10))
	line[3] = bytes.Join(this.userNames, colonCommaFileSeparator)

	return line, nil
}
