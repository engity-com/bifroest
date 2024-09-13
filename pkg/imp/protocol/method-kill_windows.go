//go:build windows

package protocol

import (
	"os"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

func (this *Server) kill(pid int, signal sys.Signal) error {
	p, err := os.FindProcess(pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return nil
	}
	if err != nil {
		return err
	}
	return p.Signal(signal.Native())
}
