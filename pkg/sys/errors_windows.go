//go:build windows

package sys

import (
	"os"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
)

func isClosedError(err error) bool {
	if errors.Is(err, winio.ErrFileClosed) {
		return true
	}
	var sce = &os.SyscallError{}
	if errors.As(err, &sce) && sce.Err != nil {
		switch //goland:noinspection GoDirectComparisonOfErrors
		sce.Err {
		case windows.WSAECONNRESET, windows.WSAECONNABORTED:
			return true
		}
	}

	return false

}
