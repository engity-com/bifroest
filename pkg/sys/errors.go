package sys

import (
	"errors"
	"io"
	gonet "net"
	"os"
)

func IsNotExist(err error) bool {
	var pe *os.PathError
	return errors.As(err, &pe) && os.IsNotExist(pe)
}

func IsClosedError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF) || errors.Is(err, gonet.ErrClosed) {
		return true
	}

	if isClosedError(err) {
		return true
	}

	var noe *gonet.OpError
	if errors.As(err, &noe) && noe.Err != nil {
		switch noe.Err.Error() {
		case "use of closed network connection":
			return true
		}
	}

	return false
}
