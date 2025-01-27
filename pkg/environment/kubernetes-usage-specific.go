package environment

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	log "github.com/echocat/slf4g"
	glssh "github.com/gliderlabs/ssh"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/ssh"
	"github.com/engity-com/bifroest/pkg/sys"
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

	ev := sys.EnvVars{}
	ev.AddAllOf(this.environ)
	if v, ok := os.LookupEnv("TZ"); ok {
		ev.Set("TZ", v)
	}
	ev.AddAllOf(t.Authorization().EnvVars())
	ev.Add(t.SshSession().Environ()...)
	ev.Set(session.EnvName, sess.Id().String())

	var path string
	var command []string
	switch t.TaskType() {
	case TaskTypeShell:
		if v := sshSess.Command(); len(v) > 0 {
			command = append(this.execCommand, v...)
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

	if ssh.AgentRequested(sshSess) {
		ln, err := this.impSession.InitiateNamedPipe(t.Context(), t.Connection().Id(), "ssh-agent")
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
		streamOpts.Tty = true
		streamOpts.TerminalSizeQueue = &terminalQueueSizeFromSsh{winCh}
	}

	opts.Command = []string{sys.BifroestBinaryFileLocation(this.repository.conf.Os), "exec",
		"-c", t.Connection().Id().String(),
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

	signals := make(chan glssh.Signal, 1)
	streamDone := make(chan error, 1)
	var activeRoutines sync.WaitGroup
	defer func() {
		go func() {
			activeRoutines.Wait()
			defer close(signals)
			defer close(streamDone)
		}()
	}()

	activeRoutines.Add(1)
	go func() {
		defer activeRoutines.Done()
		cErr := exec.StreamWithContext(t.Context(), streamOpts)
		if this.isRelevantError(cErr) {
			streamDone <- cErr
		} else {
			streamDone <- nil
		}
		l.Trace("streaming finished")
	}()

	finish := func() (int, error) {
		exitCode, err := this.impSession.GetConnectionExitCode(t.Context(), t.Connection().Id())
		if errors.Is(err, connection.ErrNotFound) {
			l.Debug("it was not possible to find an exitCode for the current connection; will treat it as 0")
			exitCode = 0
		} else if err != nil {
			l.WithError(err).Warn("it was not possible to retrieve the exitCode for the current connection; will treat it as 1")
			exitCode = 1
		}
		return exitCode, nil
	}

	sshSess.Signals(signals)
	for {
		select {
		case s, ok := <-signals:
			if ok {
				this.signal(t.Context(), l, t.Connection(), s)
			}
		case <-t.Context().Done():
			return -2, rErr
		case err, ok := <-streamDone:
			_ = sshSess.CloseWrite()
			if ok && err != nil && rErr == nil {
				return -1, err
			}
			if rErr == nil {
				if ec, err := finish(); err != nil {
					return -1, err
				} else if ec >= 0 {
					return ec, nil
				}
			}
		}
	}
}

type terminalQueueSizeFromSsh struct {
	c <-chan glssh.Window
}

func (this *terminalQueueSizeFromSsh) Next() *remotecommand.TerminalSize {
	win, ok := <-this.c
	if !ok {
		return nil
	}
	return &remotecommand.TerminalSize{
		Width:  uint16(win.Width),
		Height: uint16(win.Height),
	}
}

func (this *kubernetes) signal(ctx context.Context, logger log.Logger, conn connection.Connection, sshSignal glssh.Signal) {
	var signal sys.Signal
	if err := signal.Set(string(sshSignal)); err != nil {
		signal = sys.SIGKILL
	}

	if err := this.impSession.Kill(ctx, conn.Id(), 0, signal); errors.Is(err, imp.ErrNoSuchProcess) {
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
