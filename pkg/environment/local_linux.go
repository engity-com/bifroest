//go:build linux

package environment

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	log "github.com/echocat/slf4g"
	"github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/user"
)

type local struct {
	repository                 *LocalRepository
	session                    session.Session
	user                       *user.User
	portForwardingAllowed      bool
	deleteUserOnDispose        bool
	deleteUserHomeDirOnDispose bool
	killUserProcessesOnDispose bool
}

func (this *LocalRepository) new(u *user.User, sess session.Session, portForwardingAllowed bool, lt *localToken) *local {
	return &local{
		this,
		sess,
		u,
		portForwardingAllowed,
		lt.User.DeleteOnDispose,
		lt.User.DeleteHomeDirOnDispose,
		lt.User.KillProcessesOnDispose,
	}
}

func (this *local) configureShellCmd(t Task, cmd *exec.Cmd) error {
	if rc := t.SshSession().RawCommand(); len(rc) > 0 {
		cmd.Args = []string{filepath.Base(this.user.Shell), "-c", rc}
	} else {
		cmd.Args = []string{"-" + filepath.Base(this.user.Shell)}
	}
	return nil
}

func (this *local) configureEnvBefore(ev *sys.EnvVars) {
	if v, ok := os.LookupEnv("TZ"); ok {
		ev.Set("TZ", v)
	}
}

func (this *local) configureEnvMid(ev *sys.EnvVars) {
	ev.Set(
		"HOME", this.user.HomeDir,
		"USER", this.user.Name,
		"LOGNAME", this.user.Name,
		"SHELL", this.user.Shell,
	)
}

func (this *local) configureCmd(cmd *exec.Cmd) {
	creds := this.user.ToCredentials()
	cmd.SysProcAttr.Credential = &creds
}

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

func (this *local) dispose(ctx context.Context) (bool, error) {
	fail := func(err error) (bool, error) {
		return false, err
	}

	disposed := false
	if this.deleteUserOnDispose {
		if err := this.repository.userRepository.DeleteById(ctx, this.user.Uid, &user.DeleteOpts{
			HomeDir:       common.P(this.deleteUserHomeDirOnDispose),
			KillProcesses: common.P(this.killUserProcessesOnDispose),
		}); errors.Is(err, user.ErrNoSuchUser) {
			// Ok, continue....
		} else if err != nil {
			return fail(err)
		} else {
			disposed = true
		}
	}

	return disposed, nil
}
