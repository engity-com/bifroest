//go:build unix

package protocol

import (
	"os"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

func (this *imp) kill(pid int, signal sys.Signal) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := p.Signal(signal.Native()); errors.Is(err, os.ErrProcessDone) {
		return ErrNoSuchProcess
	} else if err != nil {
		return err
	}
	return nil
}
