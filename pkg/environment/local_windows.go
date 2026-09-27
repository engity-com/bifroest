//go:build windows

package environment

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	log "github.com/echocat/slf4g"
	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

const localTargetOs = sys.OsWindows

func (this *local) newAgentNamedPipe() (net.NamedPipe, error) {
	return net.NewNamedPipeForSid("ssh-agent", this.user.SID)
}

type local struct {
	repository            *LocalRepository
	session               session.Session
	user                  windowsLocalAccount
	portForwardingAllowed bool
}

func (this *local) reverseTCPUnprivilegedUser() bool { return false }

func (this *LocalRepository) new(user windowsLocalAccount, sess session.Session, portForwardingAllowed bool) *local {
	return &local{
		repository:            this,
		session:               sess,
		user:                  user,
		portForwardingAllowed: portForwardingAllowed,
	}
}

func (this *local) createCmdAndEnv(t Task) (*exec.Cmd, *sys.EnvVars, func(), error) {
	token, release, err := this.user.logon()
	if err != nil {
		return nil, nil, nil, errors.System.Newf("cannot log on as local account %q: %w", this.user.Name, err)
	}
	fail := func(err error) (*exec.Cmd, *sys.EnvVars, func(), error) {
		release()
		return nil, nil, nil, err
	}
	home, err := token.GetUserProfileDirectory()
	if err != nil {
		return fail(errors.System.Newf("cannot resolve local account's profile directory: %w", err))
	}
	dir := home
	if !this.repository.conf.Directory.IsZero() {
		dir, err = this.repository.conf.Directory.Render(t)
		if err != nil {
			return fail(errors.Config.Newf("cannot evaluate environment's directory: %w", err))
		}
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fail(errors.Config.Newf("cannot evaluate environment's directory (%q): %w", dir, err))
	}
	if !fi.IsDir() {
		return fail(errors.Config.Newf("environment's directory (%q) isn't a directory", dir))
	}

	cmd := exec.Cmd{
		Dir:         dir,
		SysProcAttr: &syscall.SysProcAttr{Token: syscall.Token(token)},
	}

	base, err := token.Environ(false)
	if err != nil {
		return fail(errors.System.Newf("cannot get local account's environment: %w", err))
	}
	ev := sys.EnvVars{}
	for _, entry := range base {
		if !strings.HasPrefix(entry, "=") {
			addEnvironmentEntries(&ev, localTargetOs, []string{entry})
		}
	}
	if !hasWindowsPath(ev) {
		ev.SetCanonical("PATH", this.getPathEnv())
	}
	if v, ok := os.LookupEnv("TZ"); ok {
		ev.SetCanonical("TZ", v)
	}
	if err := applyTaskEnvironment(&ev, localTargetOs, t); err != nil {
		return fail(err)
	}
	host, err := os.Hostname()
	if err != nil {
		return fail(err)
	}
	setReservedEnvironment(&ev, localTargetOs,
		"USERNAME", this.user.Name,
		"USERDOMAIN", host,
		"USERPROFILE", home,
		"HOMEDRIVE", filepath.VolumeName(home),
		"HOMEPATH", strings.TrimPrefix(home, filepath.VolumeName(home)),
	)

	return &cmd, &ev, release, nil
}

func hasWindowsPath(env sys.EnvVars) bool {
	for name := range env {
		if strings.EqualFold(name, "PATH") {
			return true
		}
	}
	return false
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

func (this *local) signal(cmd *exec.Cmd, logger log.Logger, signal essh.Signal) {
	err := signalProcessFromSsh(signal, func(sig sys.Signal) error {
		return cmd.Process.Signal(sig.Native())
	})
	if errors.Is(err, os.ErrProcessDone) {
		// Ignored.
	} else if err != nil {
		logger.WithError(err).
			With("pid", cmd.Process.Pid).
			With("signal", signal).
			Warn("cannot send signal to process")
	}
}

func (this *local) dispose(_ context.Context) (bool, error) {
	return true, nil
}
