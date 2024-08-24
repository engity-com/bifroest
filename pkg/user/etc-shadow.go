//go:build unix

package user

import (
	"bytes"
	"errors"
	"strconv"
	"time"

	"github.com/engity-com/bifroest/pkg/crypto/unix/password"
)

const (
	etcShadowColons = 9
)

var (
	DefaultEtcShadow = "/etc/shadow"

	errEtcShadowEmptyPassword        = errors.New("empty password")
	errEtcShadowEmptyLastChangedAt   = errors.New("empty last changed at")
	errEtcShadowIllegalLastChangedAt = errors.New("illegal last changed at")
	errEtcShadowIllegalMinimumAge    = errors.New("illegal minimum age")
	errEtcShadowEmptyMaximumAge      = errors.New("empty maximum age")
	errEtcShadowIllegalMaximumAge    = errors.New("illegal maximum age")
	errEtcShadowIllegalWarnAge       = errors.New("illegal warn age")
	errEtcShadowIllegalInactiveAge   = errors.New("illegal inactive age")
	errEtcShadowIllegalExpireAt      = errors.New("illegal expire at")
	errEtcShadowIllegalUnused        = errors.New("illegal unused (9)")

	nonStarPassword              = []byte{'*'}
	nonExclamationPassword       = []byte{'!'}
	nonDoubleExclamationPassword = []byte{'!', '!'}
)

type etcShadowEntry struct {
	name                []byte //0
	password            []byte //1
	lastChangedAtInDays uint32 //2
	minimumAgeInDays    uint32 //3
	maximumAgeInDays    uint32 //4
	warnAgeInDays       uint32 //5
	hasWarnAge          bool   //5
	inactiveAgeInDays   uint32 //6
	hasInactiveAge      bool   //6
	expireAtTsInDays    uint32 //7
	hasExpire           bool   //7
}

func (this *etcShadowEntry) validatePassword(pass string) (bool, error) {
	if len(this.password) == 0 ||
		bytes.Equal(this.password, nonStarPassword) ||
		bytes.Equal(this.password, nonExclamationPassword) ||
		bytes.Equal(this.password, nonDoubleExclamationPassword) {
		return false, nil
	}

	ok, err := password.Validate(pass, this.password)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, err
	}

	today := uint32(time.Now().Unix() / 60 / 60 / 24)

	if this.hasInactiveAge {
		expireAt := this.maximumAgeInDays + this.lastChangedAtInDays + this.inactiveAgeInDays
		if expireAt <= today {
			return false, nil
		}
	}

	if this.hasExpire {
		if this.expireAtTsInDays <= today {
			return false, nil
		}
	}

	return true, nil
}

func (this *etcShadowEntry) validate(allowBadName bool) error {
	if err := validateUserName(this.name, allowBadName); err != nil {
		return err
	}
	if len(this.password) == 0 {
		return errEtcShadowEmptyPassword
	}
	return nil
}

func (this *etcShadowEntry) decode(line [][]byte, allowBadName bool) error {
	var err error
	this.name = line[0]
	this.password = line[1]
	if this.lastChangedAtInDays, _, err = parseUint32Column(line, 2, errEtcShadowEmptyLastChangedAt, errEtcShadowIllegalLastChangedAt); err != nil {
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
	if this.expireAtTsInDays, this.hasExpire, err = parseUint32Column(line, 7, nil, errEtcShadowIllegalExpireAt); err != nil {
		return err
	}
	if len(line[8]) != 0 {
		return errEtcShadowIllegalUnused
	}

	if err := this.validate(allowBadName); err != nil {
		return err
	}

	return nil
}

func (this *etcShadowEntry) encode(allowBadName bool) ([][]byte, error) {
	if err := this.validate(allowBadName); err != nil {
		return nil, err
	}

	line := make([][]byte, 9)
	line[0] = this.name
	line[1] = this.password
	line[2] = []byte(strconv.FormatUint(uint64(this.lastChangedAtInDays), 10))
	line[3] = []byte(strconv.FormatUint(uint64(this.minimumAgeInDays), 10))
	line[4] = []byte(strconv.FormatUint(uint64(this.maximumAgeInDays), 10))
	if this.hasWarnAge {
		line[5] = []byte(strconv.FormatUint(uint64(this.warnAgeInDays), 10))
	} else {
		line[5] = []byte{}
	}
	if this.hasInactiveAge {
		line[6] = []byte(strconv.FormatUint(uint64(this.inactiveAgeInDays), 10))
	} else {
		line[6] = []byte{}
	}
	if this.hasExpire {
		line[7] = []byte(strconv.FormatUint(uint64(this.expireAtTsInDays), 10))
	} else {
		line[7] = []byte{}
	}
	line[8] = []byte{}

	return line, nil
}

func (this *etcShadowEntry) String() string {
	if this == nil {
		return ""
	}
	return string(this.name)
}
