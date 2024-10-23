//go:build windows

package environment

import (
	"context"
	"os"
	"os/exec"
	"syscall"

	log "github.com/echocat/slf4g"
	glssh "github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

type local struct {
	repository            *LocalRepository
	session               session.Session
	portForwardingAllowed bool
}

func (this *LocalRepository) new(sess session.Session, portForwardingAllowed bool) *local {
	return &local{
		this,
		sess,
		portForwardingAllowed,
	}
}

func (this *local) createCmdAndEnv(t Task) (*exec.Cmd, *sys.EnvVars, error) {
	dir, err := this.repository.conf.Directory.Render(t)
	if err != nil {
		return nil, nil, errors.Config.Newf("cannot evaluate environment's directory: %w", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, nil, errors.Config.Newf("cannot evaluate environment's directory (%q): %w", dir, err)
	}
	if !fi.IsDir() {
		return nil, nil, errors.Config.Newf("environment's directory (%q) isn't a directory", dir)
	}

	cmd := exec.Cmd{
		Dir:         dir,
		SysProcAttr: &syscall.SysProcAttr{},
	}

	ev := sys.EnvVars{
		"PATH": this.getPathEnv(),
	}
	if v, ok := os.LookupEnv("TZ"); ok {
		ev.Set("TZ", v)
	}
	ev.AddAllOf(t.Authorization().EnvVars())
	ev.Add(t.SshSession().Environ()...)

	return &cmd, &ev, nil
}

func (this *local) configureShellCmd(t Task, cmd *exec.Cmd) error {
	var argSource *template.Strings
	var argName string

	rc := t.SshSession().RawCommand()
	if len(rc) > 0 {
		argSource = &this.repository.conf.ExecCommandPrefix
		argName = "execCommandPrefix"
	} else {
		argSource = &this.repository.conf.ShellCommand
		argName = "shellCommand"
	}

	args, err := this.evaluateCommand(t, argName, argSource)
	if err != nil {
		return err
	}

	cmd.Path = args[0]
	cmd.Args = append(args, rc)

	return nil
}

func (this *local) evaluateCommand(t Task, name string, tmpl *template.Strings) ([]string, error) {
	args, err := tmpl.Render(t)
	if err != nil {
		return nil, errors.Config.Newf("cannot evaluate environment's %s: %w", name, err)
	}
	if len(args) < 1 {
		args = []string{configuration.DefaultShell}
	}

	args[0], err = exec.LookPath(args[0])
	if err != nil {
		return nil, errors.Config.Newf("cannot evaluate environment's %s executable (%q): %w", name, args[0], err)
	}

	return args, nil
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

func (this *local) signal(cmd *exec.Cmd, logger log.Logger, signal glssh.Signal) {
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
