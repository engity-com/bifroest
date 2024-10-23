//go:build unix

package sys

import (
	"os"

	"golang.org/x/sys/unix"

	"github.com/engity-com/bifroest/pkg/errors"
)

func isClosedError(err error) bool {
	var sce = &os.SyscallError{}
	if errors.As(err, &sce) && sce.Err != nil {
		switch sce.Err {
		case unix.EPIPE:
			return true
		}
	}
	return false
}
