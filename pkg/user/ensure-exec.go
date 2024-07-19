package user

import (
	"github.com/engity-com/yasshd/pkg/sys"
)

type ExecutionBasedEnsurer struct {
	Executor      sys.Executor
	AllowBadNames bool
}
