//go:build unix

package user

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
)

const (
	etcGroupColons = 4
)

var (
	DefaultEtcGroup = "/etc/group"

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

func (this *etcGroupEntry) decode(line [][]byte, allowBadName bool) error {
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

func (this *etcGroupEntry) encode(allowBadName bool) ([][]byte, error) {
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

func (this *etcGroupEntry) addUniqueUserName(username []byte) {
	if slices.ContainsFunc(this.userNames, func(candidate []byte) bool {
		return bytes.Equal(candidate, username)
	}) {
		// Already contained. No need to add again...
		return
	}
	this.userNames = append(this.userNames, username)
}

func (this *etcGroupEntry) removeUserName(username []byte) {
	this.userNames = slices.DeleteFunc(this.userNames, func(candidate []byte) bool {
		return bytes.Equal(candidate, username)
	})
}

type etcGroupRef struct {
	*etcGroupEntry
}

func (this *GroupRequirement) toEtcGroupRef(idGenerator func() (GroupId, error)) (*etcGroupRef, error) {
	entry := etcGroupEntry{
		nil,
		[]byte("x"),
		0,
		nil,
	}
	if v := this.Gid; v != nil {
		entry.gid = uint32(*v)
	} else if v, err := idGenerator(); err != nil {
		return nil, err
	} else {
		entry.gid = uint32(v)
	}

	if v := this.Name; v != "" {
		entry.name = []byte(v)
	} else {
		entry.name = []byte(fmt.Sprintf("g%d", entry.gid))
	}

	return &etcGroupRef{&entry}, nil
}

func (this *GroupRequirement) updateEtcGroupRef(ref *etcGroupRef) error {
	if v := this.Gid; v != nil {
		ref.etcGroupEntry.gid = uint32(*v)
	}

	if v := this.Name; v != "" {
		ref.etcGroupEntry.name = []byte(v)
	}

	return nil
}

type nameToEtcGroupRef map[string]*etcGroupRef
type idToEtcGroupRef map[GroupId]*etcGroupRef
type nameToEtcGroupRefs map[string][]*etcGroupRef
