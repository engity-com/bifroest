package user

import (
	"github.com/engity/pam-oidc/pkg/sys"
)

type ExecutionBasedEnsurer struct {
	Executor sys.Executor
}
