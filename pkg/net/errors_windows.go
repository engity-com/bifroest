//go:build windows

package net

import (
	"os"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
)

func isClosedError(err error) bool {
	var sce *os.SyscallError
	if errors.As(err, &sce) && sce.Err != nil {
		switch sce.Err {
		case windows.WSAECONNRESET, windows.WSAECONNABORTED:
			return true
		}
	}

	return false

}
