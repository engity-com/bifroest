package user

import "github.com/engity/pam-oidc/pkg/execution"

var DefaultEnsurer Ensurer = &ExecutionBasedEnsurer{
	Executor: execution.Default,
}

type Ensurer interface {
	Ensure(*Requirement) (*User, error)
	EnsureGroup(requirement *GroupRequirement) (*Group, error)
}
