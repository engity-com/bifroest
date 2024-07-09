package sys

import (
	"fmt"
)

var DefaultExecutor Executor = &StandardExecutor{
	UsingSudo: true,
}

type Executor interface {
	Execute(program string, args ...string) error
}

type Error struct {
	ExitCode int
	Stderr   []byte
}

func (this *Error) Error() string {
	return fmt.Sprintf("exitcode %d: %s", this.ExitCode, string(this.Stderr))
}
