package user

import (
	"github.com/engity-com/bifroest/pkg/sys"
)

type ExecutionBasedEnsurer struct {
	Executor      sys.Executor
	AllowBadNames bool
}
