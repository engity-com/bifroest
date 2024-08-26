//go:build unix

package environment

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	"github.com/gliderlabs/ssh"
	"github.com/kardianos/osext"

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

func (this *local) Session() session.Session {
	return this.session
}

func (this *local) Banner(req Request) (io.ReadCloser, error) {
	b, err := this.repository.conf.Banner.Render(req)
	if err != nil {
		return nil, err
	}

	return io.NopCloser(strings.NewReader(b)), nil
}

func (this *local) Run(t Task) (exitCode int, rErr error) {
	l := t.Logger()
	sshSess := t.SshSession()

	cmd := exec.Cmd{
		Dir:         this.user.HomeDir,
		SysProcAttr: &syscall.SysProcAttr{},
	}

	ev := sys.EnvVars{
		"PATH": this.getPathEnv(),
	}

	switch t.TaskType() {
	case TaskTypeShell:
		if err := this.configureShellCmd(t, &cmd); err != nil {
			return -1, err
		}
	case TaskTypeSftp:
		efn, err := osext.Executable()
		if err != nil {
			return -1, fmt.Errorf("cannot resolve the location of the server's executable location: %w", err)
		}
		cmd.Path = efn
		cmd.Args = []string{efn, "sftp-server"}
	default:
		return -1, fmt.Errorf("illegal task type: %v", t.TaskType())
	}

	if v, ok := os.LookupEnv("TZ"); ok {
		ev.Set("TZ", v)
	}
	ev.AddAllOf(t.Authorization().EnvVars())
	ev.Add(sshSess.Environ()...)
	ev.Set(
		"HOME", this.user.HomeDir,
		"USER", this.user.Name,
		"LOGNAME", this.user.Name,
		"SHELL", this.user.Shell,
	)

	if ssh.AgentRequested(sshSess) {
		l, err := ssh.NewAgentListener()
		if err != nil {
			return -1, fmt.Errorf("cannot listen to agent: %w", err)
		}
		defer common.IgnoreCloseError(l)
		go ssh.ForwardAgentConnections(l, sshSess)
		cmd.Env = append(cmd.Env, "SSH_AUTH_SOCK"+l.Addr().String())
	}

	// TODO! Global configuration with environment
	// tODO! If not exist ~/.hushlogin display /etc/motd

	cmd.Stdin = sshSess
	cmd.Stdout = sshSess
	if t.TaskType() == TaskTypeSftp {
		cmd.Stderr = &log.LoggingWriter{
			Logger:         l,
			LevelExtractor: level.FixedLevelExtractor(level.Error),
		}
	} else {
		cmd.Stderr = sshSess.Stderr()
	}
	this.configureCmd(&cmd)

	var fPty, fTty *os.File
	if ptyReq, winCh, isPty := sshSess.Pty(); isPty {
		var err error
		fPty, fTty, err = pty.Open()
		if err != nil {
			return -1, fmt.Errorf("cannot allocate pty: %w", err)
		}
		defer common.IgnoreCloseError(fPty)
		defer common.IgnoreCloseError(fTty)
		ev.Set("TERM", ptyReq.Term)
		if err := this.configureCmdForPty(&cmd, fPty, fTty); err != nil {
			return -1, fmt.Errorf("cannot configure cmd for pty: %w", err)
		}
		cmd.Stderr = fTty
		cmd.Stdout = fTty
		cmd.Stdin = fTty

		go func() {
			for {
				win, ok := <-winCh
				if !ok {
					return
				}
				size := pty.Winsize{Rows: uint16(win.Height), Cols: uint16(win.Width)}
				if err := pty.Setsize(fPty, &size); err != nil {
					l.WithError(err).Warn("cannot set winsize; ignoring")
				}
			}
		}()
	}
	cmd.Env = ev.Strings()

	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("cannot start process %v: %w", cmd.Args, err)
	}
	l.With("pid", cmd.Process.Pid).
		Debug("user's process started")

	type doneT struct {
		exitCode int
		err      error
	}
	signals := make(chan ssh.Signal, 1)
	processDone := make(chan doneT, 1)
	copyDone := make(chan error, 2)
	var activeRoutines sync.WaitGroup
	defer func() {
		go func() {
			activeRoutines.Wait()
			defer close(signals)
			defer close(copyDone)
			defer close(processDone)
		}()
	}()

	if fPty != nil {
		doCopy := func(from io.Reader, to io.Writer, name string) {
			defer activeRoutines.Done()
			if _, err := io.Copy(to, from); this.isRelevantError(err) {
				copyDone <- err
			} else {
				copyDone <- nil
			}
			l.Tracef("finished copy %s", name)
		}
		activeRoutines.Add(1)
		go doCopy(fPty, sshSess, "pty -> ssh")
		activeRoutines.Add(1)
		go doCopy(sshSess, fPty, "ssh -> pty")
	}

	activeRoutines.Add(1)
	go func() {
		defer activeRoutines.Done()
		if state, err := cmd.Process.Wait(); err != nil {
			processDone <- doneT{-1, err}
		} else {
			processDone <- doneT{state.ExitCode(), nil}
		}
		l.Trace("finished process")
	}()

	sshSess.Signals(signals)
	defer this.kill(&cmd, l)
	for {
		select {
		case s, ok := <-signals:
			if ok {
				this.signal(&cmd, l, s)
			}
		case <-t.Context().Done():
			if err := t.Context().Err(); err != nil && rErr == nil {
				rErr = err
			}
			return -2, rErr
		case status, ok := <-processDone:
			if ok {
				if status.err != nil && rErr == nil {
					rErr = status.err
				}
				return status.exitCode, rErr
			}
		case err, ok := <-copyDone:
			if ok && err != nil && rErr == nil {
				rErr = err
				return -1, rErr
			}
		}
	}
}

func (this *local) Dispose(ctx context.Context) (bool, error) {
	fail := func(err error) (bool, error) {
		return false, errors.Newf(errors.System, "cannot dispose environment: %w", err)
	}

	disposed, err := this.dispose(ctx)
	if err != nil {
		return fail(err)
	}

	sess := this.session
	if sess != nil {
		if err := sess.SetEnvironmentToken(ctx, nil); err != nil {
			return fail(err)
		}
	}

	return disposed, nil
}

func (this *local) isRelevantError(err error) bool {
	return err != nil && !errors.Is(err, syscall.EIO) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)
}

func (this *local) kill(cmd *exec.Cmd, logger log.Logger) {
	// TODO! We should consider the whole tree...
	if err := cmd.Process.Kill(); errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.EINVAL) {
		// Ok, great.
	} else if err != nil {
		logger.WithError(err).
			With("pid", cmd.Process.Pid).
			Warn("cannot kill process")
	}
}

func (this *local) IsPortForwardingAllowed(_ string, _ uint32) (bool, error) {
	return this.portForwardingAllowed, nil
}

func (this *local) NewDestinationConnection(ctx context.Context, host string, port uint32) (io.ReadWriteCloser, error) {
	if !this.portForwardingAllowed {
		return nil, errors.Newf(errors.Permission, "portforwarning not allowed")
	}

	dest := net.JoinHostPort(host, strconv.FormatInt(int64(port), 10))
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", dest)
}

func (this *local) configureShellCmd(t Task, cmd *exec.Cmd) error {
	if rc := t.SshSession().RawCommand(); len(rc) > 0 {
		cmd.Args = []string{filepath.Base(this.user.Shell), "-c", rc}
	} else {
		cmd.Args = []string{"-" + filepath.Base(this.user.Shell)}
	}
	return nil
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
