//go:build windows

package environment

import (
	"context"
	"os"
	"os/exec"
	"syscall"

	log "github.com/echocat/slf4g"
	"github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/user"
)

type local struct {
	repository            *LocalRepository
	session               session.Session
	user                  *user.User
	portForwardingAllowed bool
	shell                 string
}

func (this *LocalRepository) new(u *user.User, sess session.Session, portForwardingAllowed bool, lt *localToken) *local {
	return &local{
		this,
		sess,
		u,
		portForwardingAllowed,
		lt.User.Shell,
	}
}

func (this *local) configureShellCmd(_ Task, cmd *exec.Cmd) error {
	shell, err := exec.LookPath(this.shell)
	if err != nil {
		return errors.Config.Newf("configured shell %q cannot be resolved: %w", this.shell, err)
	}

	cmd.Path = shell
	cmd.Args = []string{shell}
	return nil
}

func (this *local) configureEnvBefore(_ *sys.EnvVars) {}

func (this *local) configureEnvMid(_ *sys.EnvVars) {}

func (this *local) configureCmd(_ *exec.Cmd) {
	//cmd.SysProcAttr.NoInheritHandles = true
}

func (this *local) configureCmdForPty(_ *exec.Cmd, pty, tty *os.File) error {
	if err := syscall.SetNonblock(syscall.Handle(int(pty.Fd())), true); err != nil {
		return err
	}
	if err := syscall.SetNonblock(syscall.Handle(int(tty.Fd())), true); err != nil {
		return err
	}
	return nil
}

func (this *local) getPathEnv() string {
	if v := os.Getenv("PATH"); v != "" {
		return v
	}
	return `C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem`
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

func (this *local) dispose(_ context.Context) (bool, error) {
	return true, nil
}
