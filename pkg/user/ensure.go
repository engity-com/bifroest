//go:build unix

package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrUserDoesNotFulfilRequirement indicates that a User does not
	// meet the provided Requirement.
	ErrUserDoesNotFulfilRequirement = errors.New("user does not fulfill requirement")

	// ErrGroupDoesNotFulfilRequirement indicates that a Group does not
	// meet the provided GroupRequirement.
	ErrGroupDoesNotFulfilRequirement = errors.New("group does not fulfill requirement")
)

// Ensurer ensures that a User or Group meets the provided requirements.
type Ensurer interface {
	// Ensure ensures that User exists for the given Requirement.
	//
	// If the User does not exist and EnsureOpts.CreateAllowed is false,
	// ErrNoSuchUser will be returned as error.
	//
	// If the User does exist but does not match the Requirement and
	// EnsureOpts.ModifyAllowed is false,  ErrUserDoesNotFulfilRequirement
	// will be returned as error.
	Ensure(context.Context, *Requirement, *EnsureOpts) (*User, EnsureResult, error)

	// EnsureGroup ensures that Group exists for the given GroupRequirement.
	//
	// If the Group does not exist and EnsureOpts.CreateAllowed is false,
	// ErrNoSuchUser will be returned as error.
	//
	// If the Group does exist but does not match the GroupRequirement and
	// EnsureOpts.ModifyAllowed is false, ErrGroupDoesNotFulfilRequirement
	// will be returned as error.
	EnsureGroup(context.Context, *GroupRequirement, *EnsureOpts) (*Group, EnsureResult, error)
}

// EnsureOpts adds some more hints what should happen when
// Ensurer.Ensure or Ensurer.EnsureGroup is used.
type EnsureOpts struct {
	// CreateAllowed defines that a User or Group can be created if not
	// already present. Default: true
	CreateAllowed *bool

	// ModifyAllowed defines that a User or Group can be modified if it
	// does not meet the provided requirement. Default: true
	ModifyAllowed *bool

	// HomeDir defines if the home directory of the User should be
	// touched or not (does not affect Group). This will create
	// the home directory upon the user is created and move it once
	// the home directory of an existing user is changing.
	// Default: true
	HomeDir *bool

	// OnHomeDirExist defines what should happen if the destination of the
	// home directory (on creation and move) already exist.
	// Default: EnsureOnHomeDirExistOverwrite
	OnHomeDirExist EnsureOnHomeDirExist
}

func (this *EnsureOpts) IsCreateAllowed() bool {
	if this != nil {
		if v := this.CreateAllowed; v != nil {
			return *v
		}
	}
	return true
}

func (this *EnsureOpts) IsModifyAllowed() bool {
	if this != nil {
		if v := this.ModifyAllowed; v != nil {
			return *v
		}
	}
	return true
}

func (this *EnsureOpts) IsHomeDir() bool {
	if this != nil {
		if v := this.HomeDir; v != nil {
			return *v
		}
	}
	return true
}

func (this *EnsureOpts) GetOnHomeDirExist() EnsureOnHomeDirExist {
	if this != nil {
		if v := this.OnHomeDirExist; v != EnsureOnHomeDirExistUnknown {
			return v
		}
	}
	return EnsureOnHomeDirExistOverwrite
}

type EnsureOnHomeDirExist uint8

const (
	EnsureOnHomeDirExistUnknown EnsureOnHomeDirExist = iota
	EnsureOnHomeDirExistFail
	EnsureOnHomeDirExistTakeover
	EnsureOnHomeDirExistOverwrite
)

func (this EnsureOnHomeDirExist) IsZero() bool {
	return this == EnsureOnHomeDirExistUnknown
}

func (this EnsureOnHomeDirExist) MarshalText() (text []byte, err error) {
	switch this {
	case EnsureOnHomeDirExistUnknown:
		return []byte("unknown"), nil
	case EnsureOnHomeDirExistFail:
		return []byte("fail"), nil
	case EnsureOnHomeDirExistTakeover:
		return []byte("takeover"), nil
	case EnsureOnHomeDirExistOverwrite:
		return []byte("overwrite"), nil
	default:
		return nil, fmt.Errorf("unknown ensure on home dir exists: %d", this)
	}
}

func (this EnsureOnHomeDirExist) String() string {
	v, err := this.MarshalText()
	if err != nil {
		return fmt.Sprintf("unknown-ensure-on-home-dir-exists-%d", this)
	}
	return string(v)
}

func (this *EnsureOnHomeDirExist) UnmarshalText(text []byte) error {
	var buf EnsureOnHomeDirExist
	switch strings.ToLower(string(text)) {
	case "unknown", "":
		buf = EnsureOnHomeDirExistUnknown
	case "fail":
		buf = EnsureOnHomeDirExistFail
	case "takeover":
		buf = EnsureOnHomeDirExistTakeover
	case "overwrite", "override":
		buf = EnsureOnHomeDirExistOverwrite
	default:
		return fmt.Errorf("unknown ensure on home dir exists: %s", string(text))
	}
	*this = buf
	return nil
}

func (this *EnsureOnHomeDirExist) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this EnsureOnHomeDirExist) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this EnsureOnHomeDirExist) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case string:
		return string(this) == v
	case *string:
		return string(this) == *v
	case EnsureOnHomeDirExist:
		return this.isEqualTo(&v)
	case *EnsureOnHomeDirExist:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this EnsureOnHomeDirExist) isEqualTo(other *EnsureOnHomeDirExist) bool {
	return this == *other
}

func (this EnsureOnHomeDirExist) Clone() EnsureOnHomeDirExist {
	return this
}

type EnsureResult uint8

const (
	EnsureResultUnknown EnsureResult = iota
	EnsureResultError
	EnsureResultUnchanged
	EnsureResultModified
	EnsureResultCreated
)
