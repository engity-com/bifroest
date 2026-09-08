package environment

import (
	"context"
	"io"
	gonet "net"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/stdcopy"
	log "github.com/echocat/slf4g"
	essh "github.com/engity-com/ssh-server-go"

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
	dockerAttachTimeout        = 30 * time.Second
	dockerExecutionExitTimeout = 5 * time.Second
	dockerExecutionCleanupTime = 5 * time.Second
	dockerWrapperPath          = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

var dockerWrapperEnvironment = []string{
	"PATH=" + dockerWrapperPath,
	"GCONV_PATH=",
	"GLIBC_TUNABLES=",
	"LD_AUDIT=",
	"LD_DEBUG_OUTPUT=",
	"LD_LIBRARY_PATH=",
	"LD_PRELOAD=",
	"LD_PROFILE=",
	"LOCPATH=",
	"MALLOC_TRACE=",
}

func attachDockerExecWithTimeout(ctx context.Context, timeout time.Duration, attach func(context.Context) (types.HijackedResponse, error)) (types.HijackedResponse, error) {
	attachCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	return attach(attachCtx)
}

func (this *docker) Banner(req Request) (io.ReadCloser, error) {
	b, err := this.repository.conf.Banner.Render(req)
	if err != nil {
		return nil, err
	}

	return io.NopCloser(strings.NewReader(b)), nil
}

func (this *docker) Run(t Task) (exitCode int, rErr error) {
	fail := func(err error) (int, error) {
		return -1, err
	}
	failf := func(msg string, args ...any) (int, error) {
		return fail(errors.System.Newf(msg, args...))
	}

	apiClient := this.repository.apiClient
	defer common.IgnoreCloseError(apiClient)

	auth := t.Authorization()
	sess := auth.FindSession()
	if sess == nil {
		return failf("authorization without session is not supported to run docker environment")
	}
	sshSess := t.SshSession()
	l := t.Connection().Logger()
	executionId, err := execution.NewId()
	if err != nil {
		return failf("cannot create execution ID: %w", err)
	}

	opts := container.ExecOptions{
		User:         this.user,
		WorkingDir:   this.directory,
		AttachStdin:  true,
		AttachStderr: true,
		AttachStdout: true,
	}

	ev := sys.EnvVars{}
	if v, ok := os.LookupEnv("TZ"); ok {
		ev.Set("TZ", v)
	}
	ev.AddAllOf(t.Authorization().EnvVars())
	ev.Add(t.SshSession().Environ()...)
	setReservedEnvironment(&ev, this.repository.hostOs,
		session.EnvName, sess.Id().String(),
		connection.EnvName, t.Connection().Id().String(),
		execution.EnvName, executionId.String(),
	)

	switch t.TaskType() {
	case TaskTypeShell:
		if v := sshSess.RawCommand(); len(v) > 0 {
			opts.Cmd = append(this.execCommand, v)
		} else {
			opts.Cmd = slices.Clone(this.shellCommand)
		}
	case TaskTypeSftp:
		opts.Cmd = slices.Clone(this.sftpCommand)
	default:
		return failf("illegal task type: %v", t.TaskType())
	}

	if ssh.AgentRequested(sshSess) && authorization.IsAgentForwardingAllowed(auth) {
		user, group, _ := strings.Cut(this.user, ":")
		if user == "" {
			user = "0"
		}
		var ln net.NamedPipe
		var err error
		if this.repository.hostOs == sys.OsLinux {
			ln, err = this.impSession.InitiateNamedPipeForUser(t.Context(), t.Connection().Id(), "ssh-agent", user, group)
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

	var winCh <-chan essh.Window
	if ptyReq, windows, isPty := sshSess.Pty(); isPty {
		winCh = windows
		ev.Set("TERM", ptyReq.Term)
		opts.Tty = true
		opts.ConsoleSize = &[2]uint{uint(ptyReq.Window.Height), uint(ptyReq.Window.Width)}
	}
	usesExecWrapper := this.repository.hostOs == sys.OsLinux || this.repository.hostOs == sys.OsWindows
	if opts.Env, err = dockerExecEnvironment(usesExecWrapper, this.repository.hostOs, ev); err != nil {
		return failf("cannot encode target environment: %w", err)
	}
	if usesExecWrapper {
		command := opts.Cmd
		if len(command) == 0 {
			return failf("cannot execute empty command")
		}
		opts.Cmd = []string{
			sys.BifroestBinaryFileLocation(this.repository.hostOs), "exec",
			"-c", t.Connection().Id().String(),
			"--executionId", executionId.String(),
			"-p", command[0],
			"-x",
		}
		if this.directory != "" {
			opts.Cmd = append(opts.Cmd, "-d", this.directory)
		}
		if user, group, _ := strings.Cut(this.user, ":"); this.repository.hostOs == sys.OsLinux && user != "" {
			opts.Cmd = append(opts.Cmd, "-u", user)
			if group != "" {
				opts.Cmd = append(opts.Cmd, "-g", group)
			}
		}
		opts.Cmd = append(opts.Cmd, "--")
		opts.Cmd = append(opts.Cmd, command...)
		if this.repository.hostOs == sys.OsLinux {
			opts.User = ""
			opts.WorkingDir = ""
		}
	}

	e, err := apiClient.ContainerExecCreate(t.Context(), this.containerId, opts)
	if err != nil {
		return failf("cannot execute command: %w", err)
	}
	execId := e.ID
	cleanupExecution := func() {
		scheduleDockerExecutionCleanup(l, executionId, func(ctx context.Context) error {
			return this.impSession.KillExecution(ctx, t.Connection().Id(), executionId, 0, sys.SIGKILL)
		})
	}

	ea, err := attachDockerExecWithTimeout(t.Context(), dockerAttachTimeout, func(ctx context.Context) (types.HijackedResponse, error) {
		return apiClient.ContainerExecAttach(ctx, execId, container.ExecAttachOptions{
			Tty:         opts.Tty,
			ConsoleSize: opts.ConsoleSize,
		})
	})
	if err != nil {
		cleanupExecution()
		return failf("cannot attach to execution #%v: %w", execId, err)
	}
	if opts.ConsoleSize != nil {
		if err := apiClient.ContainerExecResize(t.Context(), execId, container.ResizeOptions{
			Height: opts.ConsoleSize[0],
			Width:  opts.ConsoleSize[1],
		}); err != nil && t.Context().Err() == nil {
			l.WithError(err).Warn("cannot set initial window size; ignoring")
		}
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
					if err := apiClient.ContainerExecResize(resizeCtx, execId, container.ResizeOptions{
						Height: uint(win.Height),
						Width:  uint(win.Width),
					}); err != nil && resizeCtx.Err() == nil {
						l.WithError(err).Warn("cannot set window size; ignoring")
					}
				}
			}
		}()
		defer func() {
			cancelResize()
			<-resizeDone
		}()
	}

	signals := make(chan essh.Signal, 1)
	outputDone := make(chan error, 1)
	inputDone := make(chan error, 1)
	var activeRoutines sync.WaitGroup
	defer func() {
		go func() {
			activeRoutines.Wait()
			close(signals)
		}()
	}()

	activeRoutines.Add(1)
	go func() {
		defer activeRoutines.Done()
		var cErr error
		if opts.Tty {
			_, cErr = io.Copy(sshSess, ea.Reader)
		} else {
			_, cErr = stdcopy.StdCopy(sshSess, sshSess.Stderr(), ea.Reader)
		}
		if this.isRelevantError(cErr) {
			outputDone <- cErr
		} else {
			outputDone <- nil
		}
		l.Trace("finished copy output")
	}()
	activeRoutines.Add(1)
	go func() {
		defer activeRoutines.Done()
		_, err := io.Copy(ea.Conn, sshSess)
		_ = ea.CloseWrite()
		if this.isRelevantError(err) {
			inputDone <- err
		} else {
			inputDone <- nil
		}
		l.Trace("finished copy input")
	}()

	finish := func(ctx context.Context) (int, error) {
		ei, iErr := apiClient.ContainerExecInspect(ctx, execId)
		if iErr != nil {
			return failf("cannot inspect execution #%s: %w", execId, iErr)
		}
		if ei.Running {
			return -1, nil
		}
		if usesExecWrapper {
			exitCode, err := this.impSession.GetExecutionExitCode(ctx, t.Connection().Id(), executionId)
			if errors.Is(err, connection.ErrNotFound) {
				return -1, nil
			}
			if err != nil {
				return failf("cannot retrieve execution #%s exit code: %w", execId, err)
			}
			return exitCode, nil
		}
		return ei.ExitCode, nil
	}
	signalExec := func(ctx context.Context, sshSignal essh.Signal) {
		this.signal(ctx, l, t.Connection().Id(), executionId, sshSignal)
	}
	sshSess.Signals(signals)
	defer sshSess.Signals(nil)
	for {
		select {
		case s, ok := <-signals:
			if ok {
				signalExec(t.Context(), s)
			}
		case <-t.Context().Done():
			cleanupExecution()
			ea.Close()
			_ = ea.CloseWrite()

			return -2, rErr
		case err := <-inputDone:
			inputDone = nil
			if err != nil {
				cleanupExecution()
				ea.Close()
				return -1, err
			}
		case err := <-outputDone:
			outputDone = nil
			ea.Close()
			if err != nil {
				cleanupExecution()
				return -1, err
			}
			finishCtx, cancelFinish := context.WithTimeout(t.Context(), dockerExecutionExitTimeout)
			defer cancelFinish()
			poll := time.NewTicker(100 * time.Millisecond)
			defer poll.Stop()
			for {
				if ec, err := finish(finishCtx); err != nil {
					if finishCtx.Err() != nil {
						cleanupExecution()
						if t.Context().Err() == nil {
							return failf("cannot retrieve execution #%s exit code after %s: %w", execId, dockerExecutionExitTimeout, err)
						}
						return -2, rErr
					}
					if !isRetryableDockerExecutionResultError(err) {
						cleanupExecution()
						return -1, err
					}
				} else if ec >= 0 {
					cleanupCompletedExecution(l, executionId, func(ctx context.Context) error {
						return this.impSession.KillExecution(ctx, t.Connection().Id(), executionId, 0, sys.SIGKILL)
					})
					return ec, nil
				}
				select {
				case <-finishCtx.Done():
					cleanupExecution()
					if t.Context().Err() == nil {
						return failf("timed out after %s waiting for execution #%s exit code", dockerExecutionExitTimeout, execId)
					}
					return -2, rErr
				case <-poll.C:
				}
			}
		}
	}
}

func cleanupCompletedExecution(logger log.Logger, executionId execution.Id, kill func(context.Context) error) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := kill(ctx); err != nil && err.Error() != imp.ErrNoSuchProcess.Error() && !errors.Is(err, context.DeadlineExceeded) {
			logger.WithError(err).With("executionId", executionId).Warn("cannot verify completed execution cleanup")
		}
	}()
}

func isRetryableDockerExecutionResultError(err error) bool {
	return errdefs.IsUnavailable(err) || errdefs.IsSystem(err) || isRetryableTransportError(err)
}

func isRetryableTransportError(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE) || sys.IsClosedError(err) {
		return true
	}
	var networkError gonet.Error
	return errors.As(err, &networkError) && (networkError.Timeout() || networkError.Temporary())
}

func dockerExecEnvironment(usesExecWrapper bool, hostOs sys.Os, environment sys.EnvVars) ([]string, error) {
	if !usesExecWrapper {
		return environment.Strings(), nil
	}
	encoded, err := execution.EncodeTargetEnvironment(environment)
	if err != nil {
		return nil, err
	}
	targetEnvironment := execution.TargetEnvironmentEnvName + "=" + encoded
	if usesExecWrapper && hostOs == sys.OsLinux {
		return append(slices.Clone(dockerWrapperEnvironment), targetEnvironment), nil
	}
	return []string{targetEnvironment}, nil
}

func scheduleDockerExecutionCleanup(logger log.Logger, executionId execution.Id, kill func(context.Context) error) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), dockerExecutionCleanupTime)
		defer cancel()
		poll := time.NewTicker(100 * time.Millisecond)
		defer poll.Stop()
		for {
			err := kill(ctx)
			if err == nil {
				return
			}
			if err.Error() != imp.ErrNoSuchProcess.Error() && !isRetryableTransportError(err) && !errors.Is(err, context.DeadlineExceeded) {
				logger.WithError(err).
					With("executionId", executionId).
					Warn("cannot clean up execution")
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-poll.C:
			}
		}
	}()
}

func (this *docker) signal(ctx context.Context, logger log.Logger, connectionId connection.Id, executionId execution.Id, sshSignal essh.Signal) {
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

func (this *docker) IsPortForwardingAllowed(_ net.HostPort) (bool, error) {
	return this.portForwardingAllowed, nil
}

func (this *docker) NewDestinationConnection(ctx context.Context, dest net.HostPort) (io.ReadWriteCloser, error) {
	if !this.portForwardingAllowed {
		return nil, errors.Newf(errors.Permission, "portforwarning not allowed")
	}

	connId, err := connection.NewId()
	if err != nil {
		return nil, err
	}

	return this.impSession.InitiateTcpForward(ctx, connId, dest)
}
