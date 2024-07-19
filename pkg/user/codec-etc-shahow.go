//go:build unix && !android

package user

import (
	"errors"
	"fmt"
	"github.com/engity-com/yasshd/pkg/sys"
	"io"
)

const (
	etcShadowFn = "/etc/shadow"
)

var (
	errEtcShadowEmptyLastChangedAt   = errors.New("empty last changed at")
	errEtcShadowIllegalLastChangedAt = errors.New("illegal last changed at")
	errEtcShadowIllegalMinimumAge    = errors.New("illegal minimum age")
	errEtcShadowEmptyMaximumAge      = errors.New("empty maximum age")
	errEtcShadowIllegalMaximumAge    = errors.New("illegal maximum age")
	errEtcShadowIllegalWarnAge       = errors.New("illegal warn age")
	errEtcShadowIllegalInactiveAge   = errors.New("illegal inactive age")
	errEtcShadowIllegalExpireAt      = errors.New("illegal expire at")
)

type etcShadowEntry struct {
	name              []byte //0
	password          []byte //1
	lastChangedTs     uint64 //2
	minimumAgeInDays  uint32 //3
	maximumAgeInDays  uint32 //4
	warnAgeInDays     uint32 //5
	hasWarnAge        bool   //5
	inactiveAgeInDays uint32 //6
	hasInactiveAge    bool   //6
	expireAtTs        uint64 //7
	hasExpire         bool   //7
}

func (this *etcShadowEntry) validate(allowBadName bool) error {
	if err := validateGroupName(this.name, allowBadName); err != nil {
		return err
	}
	return nil
}

func (this *etcShadowEntry) setLine(line [][]byte, allowBadName bool) error {
	var err error
	this.name = line[0]
	this.password = line[1]
	if this.lastChangedTs, _, err = parseUint64Column(line, 2, errEtcShadowEmptyLastChangedAt, errEtcShadowIllegalLastChangedAt); err != nil {
		return err
	}
	if this.minimumAgeInDays, _, err = parseUint32Column(line, 3, nil, errEtcShadowIllegalMinimumAge); err != nil {
		return err
	}
	if this.maximumAgeInDays, _, err = parseUint32Column(line, 4, errEtcShadowEmptyMaximumAge, errEtcShadowIllegalMaximumAge); err != nil {
		return err
	}
	if this.warnAgeInDays, this.hasWarnAge, err = parseUint32Column(line, 5, nil, errEtcShadowIllegalWarnAge); err != nil {
		return err
	}
	if this.inactiveAgeInDays, this.hasInactiveAge, err = parseUint32Column(line, 6, nil, errEtcShadowIllegalInactiveAge); err != nil {
		return err
	}
	if this.expireAtTs, this.hasExpire, err = parseUint64Column(line, 7, nil, errEtcShadowIllegalExpireAt); err != nil {
		return err
	}

	if err := this.validate(allowBadName); err != nil {
		return err
	}

	return nil
}

func decodeEtcShadow(allowBadName bool, consumer codecConsumer[*etcShadowEntry]) (rErr error) {
	f, err := sys.OpenAndLockFileForRead(etcShadowFn)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", etcShadowFn, err)
	}
	defer func() {
		if err := f.Close(); err != nil && rErr == nil {
			rErr = err
		}
	}()

	return decodeEtcShadowOf(etcShadowFn, f, allowBadName, consumer)
}

func decodeEtcShadowOf(fn string, r io.Reader, allowBadName bool, consumer codecConsumer[*etcShadowEntry]) error {
	var entry etcShadowEntry
	return parseColonFile(fn, r, 8, func(line [][]byte) error {
		if err := entry.setLine(line, allowBadName); err != nil {
			return err
		}

		return consumer(&entry)
	})
}
