package environment

import (
	"context"
	"io"
	gonet "net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/authorization"
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
	if _, _, isPty := sshSess.Pty(); isPty && t.TaskType() == TaskTypeSftp {
		return fail(ErrSubsystemNotAllowed)
	}

	auth := t.Authorization()
	sess := auth.FindSession()
	if sess == nil {
		return failf("authorization without session is not supported to run docker environment")
	}

	cmd, ev, release, err := this.createCmdAndEnv(t)
	if err != nil {
		return fail(err)
	}
	defer release()

	setReservedEnvironment(ev, localTargetOs, session.EnvName, sess.Id().String())

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

	if ssh.AgentRequested(sshSess) && authorization.IsAgentForwardingAllowed(auth) {
		ln, err := this.newAgentNamedPipe()
		if err != nil {
			return failf("cannot listen to agent: %w", err)
		}
		defer common.IgnoreCloseError(ln)
		go ssh.ForwardAgentConnections(ln, l, sshSess)
		setReservedEnvironment(ev, localTargetOs, ssh.AuthSockEnvName, ln.Path())
	}
	if ptyReq, _, isPty := sshSess.Pty(); isPty && localTargetOs == sys.OsWindows {
		setReservedEnvironment(ev, localTargetOs, "TERM", ptyReq.Term)
		cmd.Env = ev.Strings()
		return this.runConPTY(t, cmd)
	}

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
	var winCh <-chan essh.Window
	if ptyReq, windows, isPty := sshSess.Pty(); isPty {
		winCh = windows
		var err error
		fPty, fTty, err = pty.Open()
		if err != nil {
			return failf("cannot allocate pty: %w", err)
		}
		defer common.IgnoreCloseError(fPty)
		defer common.IgnoreCloseError(fTty)
		setReservedEnvironment(ev, localTargetOs, "TERM", ptyReq.Term)
		initialSize := pty.Winsize{Rows: uint16(ptyReq.Window.Height), Cols: uint16(ptyReq.Window.Width)}
		if err := pty.Setsize(fPty, &initialSize); err != nil {
			return failf("cannot set initial pty size: %w", err)
		}
		if err := this.configureCmdForPty(cmd, fPty, fTty); err != nil {
			return failf("cannot configure cmd for pty: %w", err)
		}
		cmd.Stderr = fTty
		cmd.Stdout = fTty
		cmd.Stdin = fTty

	}
	if winCh != nil {
		resizeCtx, cancelResize := context.WithCancel(t.Context())
		resizeDone := make(chan struct{})
		go func() {
			defer close(resizeDone)
			for {
				select {
				case <-resizeCtx.Done():
					return
				case win, ok := <-winCh:
					if !ok {
						return
					}
					size := pty.Winsize{Rows: uint16(win.Height), Cols: uint16(win.Width)}
					if err := pty.Setsize(fPty, &size); err != nil {
						l.WithError(err).Warn("cannot set winsize; ignoring")
					}
				}
			}
		}()
		defer func() {
			cancelResize()
			<-resizeDone
		}()
	}
	cmd.Env = ev.Strings()
	var stdin io.WriteCloser
	if fPty == nil {
		// A detached child may inherit stdout/stderr after the shell exits.
		cmd.WaitDelay = 2 * time.Second
		stdin, err = cmd.StdinPipe()
		if err != nil {
			return failf("cannot open process stdin: %w", err)
		}
	}

	if err := cmd.Start(); err != nil {
		if stdin != nil {
			_ = stdin.Close()
		}
		return failf("cannot start process %v: %w", cmd.Args, err)
	}
	if stdin != nil {
		go func() {
			defer stdin.Close()
			_, _ = io.Copy(stdin, sshSess)
		}()
	}
	l.With("pid", cmd.Process.Pid).
		Debug("user's process started")

	type doneT struct {
		exitCode int
		err      error
	}
	signals := make(chan essh.Signal, 1)
	processDone := make(chan doneT, 1)
	waitFinished := make(chan struct{})
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
		defer close(waitFinished)
		if err := cmd.Wait(); err != nil {
			var exit *exec.ExitError
			if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Success() {
				l.WithError(err).Warn("stopped waiting for output pipes after the process exited")
				processDone <- doneT{0, nil}
			} else if errors.As(err, &exit) {
				processDone <- doneT{exit.ExitCode(), nil}
			} else {
				processDone <- doneT{-1, err}
			}
		} else {
			processDone <- doneT{0, nil}
		}
		l.Trace("finished process")
	}()

	sshSess.Signals(signals)
	defer sshSess.Signals(nil)
	defer func() {
		if t.Context().Err() != nil {
			_ = sshSess.Close()
		}
		this.kill(cmd, l)
		<-waitFinished
	}()
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
	if sess != nil && !this.deferred {
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

func (this *local) ListenReverseTCP(ctx context.Context, host string, port uint16) (gonet.Listener, error) {
	if !this.portForwardingAllowed {
		return nil, errors.Newf(errors.Permission, "port forwarding not allowed")
	}
	if port > 0 && port < 1024 && this.reverseTCPUnprivilegedUser() {
		return nil, errors.Newf(errors.Permission, "privileged reverse TCP port %d not allowed for unprivileged user", port)
	}

	// An omitted SSH bind host is loopback; only an explicit * requests a wildcard bind.
	switch host {
	case "":
		host = "localhost"
	case "*":
		host = ""
	}

	var config gonet.ListenConfig
	return config.Listen(ctx, "tcp", gonet.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)))
}
