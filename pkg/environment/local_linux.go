package environment

import (
	log "github.com/echocat/slf4g"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/gliderlabs/ssh"
	"os"
	"os/exec"
	"syscall"
)

func (this *local) configureCmd(_ *exec.Cmd) {}

func (this *local) configureCmdForPty(cmd *exec.Cmd, pty, tty *os.File) error {
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setctty = true

	if err := syscall.SetNonblock(int(pty.Fd()), true); err != nil {
		return err
	}
	if err := syscall.SetNonblock(int(tty.Fd()), true); err != nil {
		return err
	}
	return nil
}

func (this *local) getPathEnv() string {
	if v := os.Getenv("PATH"); v != "" {
		return v
	}
	return "/bin;/usr/bin"
}

func (this *local) signal(cmd *exec.Cmd, logger log.Logger, signal ssh.Signal) {
	var sig sys.Signal
	if err := sig.Set(string(signal)); err != nil {
		sig = sys.SIGKILL
	}

	if err := cmd.Process.Signal(sig.Native()); errors.Is(err, os.ErrProcessDone) {
		// Ignored.
	} else if err != nil {
		logger.WithError(err).
			With("pid", cmd.Process.Pid).
			With("signal", sig).
			Warn("cannot send signal to process")
	}
}
