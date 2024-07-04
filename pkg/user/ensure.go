package user

import (
	"github.com/engity/pam-oidc/pkg/execution"
)

var DefaultEnsurer Ensurer = &ExecutionBasedEnsurer{
	Executor: execution.Default,
}

type Ensurer interface {
	Ensure(*Requirement, *EnsureOpts) (*User, error)
	EnsureGroup(*GroupRequirement, *EnsureOpts) (*Group, error)
}

type EnsureOpts struct {
	CreateAllowed *bool
	ModifyAllowed *bool
}

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
	return EnsureOpts{
		ca,
		ma,
	}
}

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
	return result
}
