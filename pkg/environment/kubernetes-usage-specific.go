package environment

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	log "github.com/echocat/slf4g"
	essh "github.com/engity-com/ssh-server-go"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/execution"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/ssh"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	kubernetesExecutionExitTimeout    = 5 * time.Second
	kubernetesExecutionCleanupTimeout = 5 * time.Second
	kubernetesExecutionCleanupStart   = 3 * time.Second
	kubernetesExecutionCleanupGrace   = time.Second
	kubernetesExecutionCleanupForce   = time.Second
)

func (this *kubernetes) Banner(req Request) (io.ReadCloser, error) {
	b, err := this.repository.conf.Banner.Render(req)
	if err != nil {
		return nil, err
	}

	return io.NopCloser(strings.NewReader(b)), nil
}

func (this *kubernetes) Run(t Task) (exitCode int, rErr error) {
	fail := func(err error) (int, error) {
		return -1, err
	}
	failf := func(msg string, args ...any) (int, error) {
		return fail(errors.System.Newf(msg, args...))
	}

	auth := t.Authorization()
	sess := auth.FindSession()
	if sess == nil {
		return failf("authorization without session is not supported to run kubernetes environment")
	}
	sshSess := t.SshSession()
	l := t.Connection().Logger()
	executionId, err := execution.NewId()
	if err != nil {
		return failf("cannot create execution ID: %w", err)
	}

	clientSet, err := this.repository.client.ClientSet()
	if err != nil {
		return fail(err)
	}

	req := clientSet.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(this.namespace).
		Name(this.name).
		SubResource("exec")

	opts := v1.PodExecOptions{
		Container: "bifroest",
		Stdin:     true,
		Stdout:    true,
		Stderr:    true,
	}

	streamOpts := remotecommand.StreamOptions{
		Stdin:  sshSess,
		Stdout: sshSess,
		Stderr: sshSess.Stderr(),
	}
	var releaseTerminalStdinEOF *io.PipeWriter

	ev := sys.EnvVars{}
	ev.AddAllOf(this.environ)
	if v, ok := os.LookupEnv("TZ"); ok {
		ev.Set("TZ", v)
	}
	ev.AddAllOf(t.Authorization().EnvVars())
	ev.Add(t.SshSession().Environ()...)
	setReservedEnvironment(&ev, this.repository.conf.Os,
		session.EnvName, sess.Id().String(),
		connection.EnvName, t.Connection().Id().String(),
		execution.EnvName, executionId.String(),
	)

	var path string
	var command []string
	switch t.TaskType() {
	case TaskTypeShell:
		if v := sshSess.RawCommand(); len(v) > 0 {
			command = append(this.execCommand, v)
		} else {
			command = slices.Clone(this.shellCommand)
		}
	case TaskTypeSftp:
		command = slices.Clone(this.sftpCommand)
	default:
		return failf("illegal task type: %v", t.TaskType())
	}

	path = command[0]
	if this.repository.conf.Os == sys.OsLinux {
		command[0] = filepath.Base(command[0])
		if t.TaskType() == TaskTypeShell {
			command[0] = "-" + command[0]
		}
	}

	if ssh.AgentRequested(sshSess) && authorization.IsAgentForwardingAllowed(auth) {
		user := this.user
		if user == "" {
			user = "0"
		}
		var ln net.NamedPipe
		var err error
		if this.repository.conf.Os == sys.OsLinux {
			ln, err = this.impSession.InitiateNamedPipeForUser(t.Context(), t.Connection().Id(), "ssh-agent", user, this.group)
		} else {
			ln, err = this.impSession.InitiateNamedPipe(t.Context(), t.Connection().Id(), "ssh-agent")
		}
		var re errors.RemoteError
		if errors.As(err, &re) {
			l.WithError(err).Warn("it was not possible to initiate named pipe for agent; agent deactivated")
		} else if err != nil {
			return fail(err)
		} else {
			defer common.IgnoreCloseError(ln)
			go ssh.ForwardAgentConnections(ln, l, sshSess)
			ev.Set(ssh.AuthSockEnvName, ln.Path())
		}
	}

	if ptyReq, winCh, isPty := sshSess.Pty(); isPty {
		ev.Set("TERM", ptyReq.Term)
		opts.TTY = true
		opts.Stderr = false
		streamOpts.Tty = true
		streamOpts.Stderr = nil
		streamOpts.TerminalSizeQueue = &terminalQueueSizeFromSsh{
			initial: &remotecommand.TerminalSize{Width: uint16(ptyReq.Window.Width), Height: uint16(ptyReq.Window.Height)},
			changes: winCh,
		}
		terminalStdinEOF, releaseEOF := io.Pipe()
		releaseTerminalStdinEOF = releaseEOF
		streamOpts.Stdin = io.MultiReader(sshSess, terminalStdinEOF)
	}

	opts.Command = []string{sys.BifroestBinaryFileLocation(this.repository.conf.Os), "exec",
		"-c", t.Connection().Id().String(),
		"--executionId", executionId.String(),
		"-p", path,
		"-x",
	}
	if v := this.directory; len(v) > 0 {
		opts.Command = append(opts.Command, "-d", v)
	}
	for k, v := range ev {
		opts.Command = append(opts.Command, "-e"+k+"="+v)
	}
	switch this.repository.conf.Os {
	case sys.OsLinux:
		if v := this.user; len(v) > 0 {
			opts.Command = append(opts.Command, "-u", v)
		}
		if v := this.group; len(v) > 0 {
			opts.Command = append(opts.Command, "-g", v)
		}
	default:
		// No additional stuff...
	}

	opts.Command = append(opts.Command, "--")
	opts.Command = append(opts.Command, command...)

	req.VersionedParams(&opts, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(this.repository.client.RestConfig(), "POST", req.URL())
	if err != nil {
		return fail(err)
	}

	signals := make(chan essh.Signal, 1)
	streamDone := make(chan error, 1)
	var activeRoutines sync.WaitGroup
	defer func() {
		go func() {
			activeRoutines.Wait()
			close(signals)
			close(streamDone)
		}()
	}()

	activeRoutines.Add(1)
	go func() {
		defer activeRoutines.Done()
		cErr := exec.StreamWithContext(t.Context(), streamOpts)
		if releaseTerminalStdinEOF != nil {
			_ = releaseTerminalStdinEOF.Close()
		}
		if this.isRelevantError(cErr) {
			streamDone <- cErr
		} else {
			streamDone <- nil
		}
		l.Trace("streaming finished")
	}()

	finish := func() (int, error) {
		return waitForKubernetesExecutionExitCode(t.Context(), executionId, kubernetesExecutionExitTimeout, func(ctx context.Context, executionId execution.Id) (int, error) {
			return this.impSession.GetExecutionExitCode(ctx, t.Connection().Id(), executionId)
		})
	}

	sshSess.Signals(signals)
	defer sshSess.Signals(nil)
	for {
		select {
		case s, ok := <-signals:
			if ok {
				this.signal(t.Context(), l, t.Connection().Id(), executionId, s)
			}
		case <-t.Context().Done():
			this.signalDetached(l, t.Connection().Id(), executionId)

			return -2, rErr
		case err, ok := <-streamDone:
			_ = sshSess.CloseWrite()

			if ok && err != nil && rErr == nil {
				this.signalDetached(l, t.Connection().Id(), executionId)
				return -1, err
			}
			if rErr == nil {
				if ec, err := finish(); err != nil {
					this.signalDetached(l, t.Connection().Id(), executionId)
					return -1, err
				} else if ec >= 0 {
					cleanupCompletedExecution(l, executionId, func(ctx context.Context) error {
						return this.impSession.KillExecution(ctx, t.Connection().Id(), executionId, 0, sys.SIGKILL)
					})
					return ec, nil
				}
			}
		}
	}
}

func waitForKubernetesExecutionExitCode(ctx context.Context, executionId execution.Id, timeout time.Duration, get func(context.Context, execution.Id) (int, error)) (int, error) {
	deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	var lastErr error
	for {
		exitCode, err := get(deadlineCtx, executionId)
		if err == nil {
			return exitCode, nil
		}
		if !errors.Is(err, connection.ErrNotFound) && !isRetryableTransportError(err) {
			return -1, err
		}
		lastErr = err
		select {
		case <-deadlineCtx.Done():
			if ctx.Err() != nil {
				return -1, ctx.Err()
			}
			if errors.Is(lastErr, connection.ErrNotFound) {
				return -1, errors.System.Newf("timed out after %s waiting for execution %v exit code", timeout, executionId)
			}
			return -1, errors.System.Newf("cannot retrieve execution %v exit code after %s: %w", executionId, timeout, lastErr)
		case <-poll.C:
		}
	}
}

type terminalQueueSizeFromSsh struct {
	initial *remotecommand.TerminalSize
	changes <-chan essh.Window
}

func (this *terminalQueueSizeFromSsh) Next() *remotecommand.TerminalSize {
	if this.initial != nil {
		result := this.initial
		this.initial = nil
		return result
	}
	win, ok := <-this.changes
	if !ok {
		return nil
	}
	return &remotecommand.TerminalSize{
		Width:  uint16(win.Width),
		Height: uint16(win.Height),
	}
}

func (this *kubernetes) signalDetached(logger log.Logger, connectionId connection.Id, executionId execution.Id) {
	go func() {
		gracefulSignal := sys.SIGINT
		if this.repository.conf.Os == sys.OsWindows {
			gracefulSignal = sys.SIGTERM
		}
		ctx, cancel := context.WithTimeout(context.Background(), kubernetesExecutionCleanupTimeout)
		defer cancel()
		gracefulErr, forceErr := cleanupKubernetesExecution(ctx, kubernetesExecutionCleanupStart, kubernetesExecutionCleanupGrace, kubernetesExecutionCleanupForce, gracefulSignal, func(ctx context.Context, signal sys.Signal) error {
			return this.impSession.KillExecution(ctx, connectionId, executionId, 0, signal)
		})
		if gracefulErr != nil && !errors.Is(gracefulErr, context.DeadlineExceeded) {
			logger.WithError(gracefulErr).With("executionId", executionId).Warn("cannot interrupt execution during cleanup")
		}
		if forceErr != nil && !errors.Is(forceErr, context.DeadlineExceeded) {
			logger.WithError(forceErr).With("executionId", executionId).Warn("cannot terminate execution during cleanup")
		}
	}()
}

func cleanupKubernetesExecution(ctx context.Context, gracefulTimeout, gracePeriod, forceTimeout time.Duration, gracefulSignal sys.Signal, signal func(context.Context, sys.Signal) error) (gracefulErr, forceErr error) {
	gracefulCtx, cancelGraceful := context.WithTimeout(ctx, gracefulTimeout)
	gracefulErr = retryExecutionSignal(gracefulCtx, func(ctx context.Context) error {
		return signal(ctx, gracefulSignal)
	})
	cancelGraceful()

	grace := time.NewTimer(gracePeriod)
	defer grace.Stop()
	select {
	case <-ctx.Done():
		return gracefulErr, ctx.Err()
	case <-grace.C:
	}

	forceCtx, cancelForce := context.WithTimeout(ctx, forceTimeout)
	defer cancelForce()
	forceErr = retryExecutionSignal(forceCtx, func(ctx context.Context) error {
		return signal(ctx, sys.SIGKILL)
	})
	return gracefulErr, forceErr
}

func retryExecutionSignal(ctx context.Context, signal func(context.Context) error) error {
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	for {
		err := signal(ctx)
		if err == nil {
			return nil
		}
		if err.Error() != imp.ErrNoSuchProcess.Error() && !isRetryableTransportError(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-poll.C:
		}
	}
}

func (this *kubernetes) signal(ctx context.Context, logger log.Logger, connectionId connection.Id, executionId execution.Id, sshSignal essh.Signal) {
	signal, err := signalFromSsh(sshSignal)
	if err != nil {
		logger.WithError(err).
			With("signal", sshSignal).
			Warn("cannot send unknown signal to process")
		return
	}

	if err := this.impSession.KillExecution(ctx, connectionId, executionId, 0, signal); (err != nil && err.Error() == imp.ErrNoSuchProcess.Error()) || errors.Is(err, context.DeadlineExceeded) {
		// Ok.
	} else if err != nil {
		logger.WithError(err).
			With("signal", signal).
			Warn("cannot send signal to process")
	}
}

func (this *kubernetes) IsPortForwardingAllowed(_ net.HostPort) (bool, error) {
	return this.portForwardingAllowed, nil
}

func (this *kubernetes) NewDestinationConnection(ctx context.Context, dest net.HostPort) (io.ReadWriteCloser, error) {
	if !this.portForwardingAllowed {
		return nil, errors.Newf(errors.Permission, "portforwarning not allowed")
	}

	connId, err := connection.NewId()
	if err != nil {
		return nil, err
	}

	return this.impSession.InitiateTcpForward(ctx, connId, dest)
}
