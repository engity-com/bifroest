package net

import (
	"io"
	"net"

	"github.com/engity-com/bifroest/pkg/errors"
)

func IsClosedError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF) {
		return true
	}

	if isClosedError(err) {
		return true
	}

	var noe *net.OpError
	if errors.As(err, &noe) && noe.Err != nil {
		switch noe.Err.Error() {
		case "use of closed network connection":
			return true
		}
	}

	return false
}
