package user

import "errors"

var (
	// ErrUserDoesNotFulfilRequirement indicates that a User does not
	// meet the provided Requirement.
	ErrUserDoesNotFulfilRequirement = errors.New("user does not fulfil requirement")

	// ErrGroupDoesNotFulfilRequirement indicates that a Group does not
	// meet the provided GroupRequirement.
	ErrGroupDoesNotFulfilRequirement = errors.New("group does not fulfil requirement")
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
	Ensure(*Requirement, *EnsureOpts) (*User, EnsureResult, error)

	// EnsureGroup ensures that Group exists for the given GroupRequirement.
	//
	// If the Group does not exist and EnsureOpts.CreateAllowed is false,
	// ErrNoSuchUser will be returned as error.
	//
	// If the Group does exist but does not match the GroupRequirement and
	// EnsureOpts.ModifyAllowed is false, ErrGroupDoesNotFulfilRequirement
	// will be returned as error.
	EnsureGroup(*GroupRequirement, *EnsureOpts) (*Group, EnsureResult, error)
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
}

// Clone create a copy of the current instance.
func (this EnsureOpts) Clone() EnsureOpts {
	var ca *bool
	if v := this.CreateAllowed; v != nil {
		nv := *v
		ca = &nv
	}
	var ma *bool
	if v := this.ModifyAllowed; v != nil {
		nv := *v
		ma = &nv
	}
	var hd *bool
	if v := this.HomeDir; v != nil {
		nv := *v
		hd = &nv
	}
	return EnsureOpts{
		ca,
		ma,
		hd,
	}
}

// OrDefaults create a copy of this instance where all
// nil fields are populated with its default values.
func (this *EnsureOpts) OrDefaults() EnsureOpts {
	var result EnsureOpts
	if v := this; v != nil {
		result = v.Clone()
	}
	if v := result.CreateAllowed; v == nil {
		nv := true
		result.CreateAllowed = &nv
	}
	if v := result.ModifyAllowed; v == nil {
		nv := true
		result.ModifyAllowed = &nv
	}
	if v := result.HomeDir; v == nil {
		nv := true
		result.HomeDir = &nv
	}
	return result
}

type EnsureResult uint8

const (
	EnsureResultUnknown EnsureResult = iota
	EnsureResultError
	EnsureResultUnchanged
	EnsureResultModified
	EnsureResultCreated
)
