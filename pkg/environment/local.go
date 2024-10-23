package environment

import (
	"context"
	"io"
	gonet "net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	glssh "github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/ssh"
	"github.com/engity-com/bifroest/pkg/sys"
)

func (this *local) Banner(req Request) (io.ReadCloser, error) {
	b, err := this.repository.conf.Banner.Render(req)
	if err != nil {
		return nil, err
	}

	return io.NopCloser(strings.NewReader(b)), nil
}

func (this *local) Run(t Task) (exitCode int, rErr error) {
	fail := func(err error) (int, error) {
		return -1, err
	}
	failf := func(msg string, args ...any) (int, error) {
		return fail(errors.System.Newf(msg, args...))
	}

	l := t.Connection().Logger()
	sshSess := t.SshSession()

	auth := t.Authorization()
	sess := auth.FindSession()
	if sess == nil {
		return failf("authorization without session is not supported to run docker environment")
	}

	cmd, ev, err := this.createCmdAndEnv(t)
	if err != nil {
		return fail(err)
	}

	ev.Set(session.EnvName, sess.Id().String())

	switch t.TaskType() {
	case TaskTypeShell:
		if err := this.configureShellCmd(t, cmd); err != nil {
			return fail(err)
		}
	case TaskTypeSftp:
		efn, err := os.Executable()
		if err != nil {
			return failf("cannot resolve the location of the server's executable location: %w", err)
		}
		cmd.Path = efn
		cmd.Args = []string{efn, "sftp-server"}
	default:
		return failf("illegal task type: %v", t.TaskType())
	}

	if ssh.AgentRequested(sshSess) {
		ln, err := net.NewNamedPipe("ssh-agent")
		if err != nil {
			return failf("cannot listen to agent: %w", err)
		}
		defer common.IgnoreCloseError(ln)
		go ssh.ForwardAgentConnections(ln, l, sshSess)
		ev.Set(ssh.AuthSockEnvName, ln.Path())
	}

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

	var fPty, fTty *os.File
	if ptyReq, winCh, isPty := sshSess.Pty(); isPty {
		var err error
		fPty, fTty, err = pty.Open()
		if err != nil {
			return failf("cannot allocate pty: %w", err)
		}
		defer common.IgnoreCloseError(fPty)
		defer common.IgnoreCloseError(fTty)
		ev.Set("TERM", ptyReq.Term)
		if err := this.configureCmdForPty(cmd, fPty, fTty); err != nil {
			return failf("cannot configure cmd for pty: %w", err)
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
		return failf("cannot start process %v: %w", cmd.Args, err)
	}
	l.With("pid", cmd.Process.Pid).
		Debug("user's process started")

	type doneT struct {
		exitCode int
		err      error
	}
	signals := make(chan glssh.Signal, 1)
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
	defer this.kill(cmd, l)
	for {
		select {
		case s, ok := <-signals:
			if ok {
				this.signal(cmd, l, s)
			}
		case <-t.Context().Done():
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

func (this *local) Dispose(ctx context.Context) (_ bool, rErr error) {
	fail := func(err error) (bool, error) {
		return false, errors.Newf(errors.System, "cannot dispose environment: %w", err)
	}

	defer common.KeepCloseError(&rErr, this)

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

func (this *local) Close() error {
	return nil
}

func (this *local) isRelevantError(err error) bool {
	return err != nil && !errors.Is(err, syscall.EIO) && !sys.IsClosedError(err)
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

func (this *local) IsPortForwardingAllowed(net.HostPort) (bool, error) {
	return this.portForwardingAllowed, nil
}

func (this *local) NewDestinationConnection(ctx context.Context, dest net.HostPort) (io.ReadWriteCloser, error) {
	if !this.portForwardingAllowed {
		return nil, errors.Newf(errors.Permission, "portforwarning not allowed")
	}

	var dialer gonet.Dialer
	return dialer.DialContext(ctx, "tcp", dest.String())
}
