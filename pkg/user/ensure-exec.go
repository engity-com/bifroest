package user

import "github.com/engity/pam-oidc/pkg/execution"

type ExecutionBasedEnsurer struct {
	Executor execution.Executor
}
