package environment

import (
	"context"
	"errors"
	"fmt"
	"io"
	gonet "net"
	"strings"
	"sync"

	essh "github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/execution"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	bssh "github.com/engity-com/bifroest/pkg/ssh"
	"github.com/engity-com/bifroest/pkg/sys"
)

type sshEnvironment struct {
	repository *SshRepository
	connection connection.Connection
	lifetime   context.Context
	session    session.Session
	settings   *sshResolvedSettings
}

func (this *sshEnvironment) Banner(req Request) (io.ReadCloser, error) {
	banner, err := this.repository.conf.Banner.Render(req)
	if err != nil {
		return nil, err
	}
	if banner == "" {
		return nil, nil
	}
	return io.NopCloser(strings.NewReader(banner)), nil
}

func (this *sshEnvironment) Run(task Task) (int, error) {
	transport, err := this.repository.transportFor(this, task.Context())
	if err != nil {
		return -1, err
	}
	environment, err := this.environmentFor(task)
	if err != nil {
		return -1, err
	}
	if err := transport.acquireChannel(task.Context()); err != nil {
		return -1, err
	}
	type result struct {
		code int
		err  error
	}
	completed := make(chan result, 1)
	go func() {
		defer transport.releaseChannel()
		var code int
		var err error
		switch task.TaskType() {
		case TaskTypeShell:
			code, err = this.runShell(task, transport, environment)
		case TaskTypeSftp:
			code, err = this.runSftp(task, transport, environment)
		default:
			code, err = -1, fmt.Errorf("illegal task type: %v", task.TaskType())
		}
		completed <- result{code, err}
	}()
	select {
	case actual := <-completed:
		return actual.code, actual.err
	case <-task.Context().Done():
		return -1, task.Context().Err()
	}
}

func (this *sshEnvironment) environmentFor(task Task) (sys.EnvVars, error) {
	result := sys.EnvVars{}
	targetOs := this.repository.conf.Os
	if err := applyTaskEnvironment(&result, targetOs, task); err != nil {
		return nil, err
	}
	executionId, err := execution.NewId()
	if err != nil {
		return nil, fmt.Errorf("cannot create execution ID: %w", err)
	}
	setReservedEnvironment(&result, targetOs,
		session.EnvName, this.session.Id().String(),
		connection.EnvName, this.connection.Id().String(),
		execution.EnvName, executionId.String(),
	)
	return result, nil
}

type sshRequestSender interface {
	SendRequest(string, bool, []byte) (bool, error)
}

func sendSshEnvironment(channel sshRequestSender, environment sys.EnvVars) error {
	type environmentRequest struct {
		Name  string
		Value string
	}
	for key, value := range environment {
		if _, err := channel.SendRequest("env", false, gossh.Marshal(&environmentRequest{key, value})); err != nil {
			return fmt.Errorf("cannot send SSH environment variable %s: %w", key, err)
		}
	}
	return nil
}

func (this *sshEnvironment) runShell(task Task, transport *sshTransport, environment sys.EnvVars) (int, error) {
	target, err := this.openTargetSession(task.Context(), transport)
	if err != nil {
		return -1, fmt.Errorf("cannot open SSH target session: %w", err)
	}
	defer func() { _ = target.Close() }()
	targetDone := make(chan struct{})
	defer close(targetDone)
	go func() {
		select {
		case <-task.Context().Done():
			_ = target.Close()
		case <-targetDone:
		}
	}()

	sshSession := task.SshSession()
	target.Stdin = sshSession
	target.Stdout = sshSession
	target.Stderr = sshSession.Stderr()
	if err := sendSshEnvironment(target, environment); err != nil {
		return -1, err
	}

	runContext, cancel := context.WithCancel(task.Context())
	var workers sync.WaitGroup
	defer func() {
		cancel()
		workers.Wait()
	}()

	if pty, windows, ok := sshSession.Pty(); ok {
		if err := requestTargetPty(target, pty); err != nil {
			return -1, fmt.Errorf("cannot request SSH target PTY: %w", err)
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-runContext.Done():
					return
				case window, ok := <-windows:
					if !ok {
						return
					}
					if err := sendTargetWindowChange(target, window); err != nil {
						this.connection.Logger().WithError(err).Warn("cannot forward SSH target window change")
						return
					}
				}
			}
		}()
	}

	if bssh.AgentRequested(sshSession) && authorization.IsAgentForwardingAllowed(task.Authorization()) {
		if err := transport.ensureAgent(task, this.lifetime); err != nil {
			return -1, fmt.Errorf("cannot forward SSH agent to target: %w", err)
		}
		if err := agent.RequestAgentForwarding(target); err != nil {
			return -1, fmt.Errorf("cannot request SSH agent forwarding at target: %w", err)
		}
	}

	signals := make(chan essh.Signal, 16)
	sshSession.Signals(signals)
	defer sshSession.Signals(nil)
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			select {
			case <-runContext.Done():
				return
			case signal, ok := <-signals:
				if !ok {
					return
				}
				if err := target.Signal(gossh.Signal(signal)); err != nil {
					this.connection.Logger().WithError(err).With("signal", signal).Warn("cannot forward SSH target signal")
				}
			}
		}
	}()

	if command := sshSession.RawCommand(); command != "" {
		err = target.Start(command)
	} else {
		err = target.Shell()
	}
	if err != nil {
		if contextErr := task.Context().Err(); contextErr != nil {
			return -1, contextErr
		}
		return -1, fmt.Errorf("cannot start SSH target session: %w", err)
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- target.Wait()
	}()
	select {
	case err = <-waitDone:
	case <-task.Context().Done():
		_ = target.Close()
		err = <-waitDone
	}
	cancel()
	var exitError *gossh.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitStatus(), nil
	}
	if err != nil {
		return -1, fmt.Errorf("SSH target session failed: %w", err)
	}
	return 0, nil
}

func (this *sshEnvironment) openTargetSession(ctx context.Context, transport *sshTransport) (*gossh.Session, error) {
	type result struct {
		session *gossh.Session
		err     error
	}
	completed := make(chan result, 1)
	go func() {
		session, err := transport.client.NewSession()
		completed <- result{session, err}
	}()
	select {
	case actual := <-completed:
		if actual.err != nil {
			this.invalidateTransportAfterOpenError(transport, actual.err)
		}
		return actual.session, actual.err
	case <-ctx.Done():
		actual := <-completed
		if actual.session != nil {
			_ = actual.session.Close()
		}
		return nil, ctx.Err()
	}
}

func requestTargetPty(target sshRequestSender, pty essh.Pty) error {
	var modes []byte
	for key, value := range pty.TerminalModes {
		modes = append(modes, gossh.Marshal(&struct {
			Key byte
			Val uint32
		}{key, value})...)
	}
	modes = append(modes, 0)
	payload := struct {
		Term         string
		Columns      uint32
		Rows         uint32
		WidthPixels  uint32
		HeightPixels uint32
		Modelist     string
	}{
		Term:         pty.Term,
		Columns:      uint32(pty.Window.Width),
		Rows:         uint32(pty.Window.Height),
		WidthPixels:  uint32(pty.Window.WidthPixels),
		HeightPixels: uint32(pty.Window.HeightPixels),
		Modelist:     string(modes),
	}
	accepted, err := target.SendRequest("pty-req", true, gossh.Marshal(&payload))
	if err != nil {
		return err
	}
	if !accepted {
		return fmt.Errorf("SSH target rejected PTY request")
	}
	return nil
}

func sendTargetWindowChange(target sshRequestSender, window essh.Window) error {
	payload := struct {
		Columns      uint32
		Rows         uint32
		WidthPixels  uint32
		HeightPixels uint32
	}{
		Columns:      uint32(window.Width),
		Rows:         uint32(window.Height),
		WidthPixels:  uint32(window.WidthPixels),
		HeightPixels: uint32(window.HeightPixels),
	}
	_, err := target.SendRequest("window-change", false, gossh.Marshal(&payload))
	return err
}

func (this *sshEnvironment) runSftp(task Task, transport *sshTransport, environment sys.EnvVars) (int, error) {
	channel, requests, err := this.openTargetChannel(task.Context(), transport, "session", nil)
	if err != nil {
		return -1, fmt.Errorf("cannot open SSH target SFTP channel: %w", err)
	}
	defer func() { _ = channel.Close() }()
	channelDone := make(chan struct{})
	defer close(channelDone)
	go func() {
		select {
		case <-task.Context().Done():
			_ = channel.Close()
		case <-channelDone:
		}
	}()
	if err := sendSshEnvironment(channel, environment); err != nil {
		return -1, err
	}
	type subsystemRequest struct{ Subsystem string }
	accepted, err := channel.SendRequest("subsystem", true, gossh.Marshal(&subsystemRequest{"sftp"}))
	if err != nil {
		if contextErr := task.Context().Err(); contextErr != nil {
			return -1, contextErr
		}
		return -1, fmt.Errorf("cannot request SSH target SFTP subsystem: %w", err)
	}
	if !accepted {
		return -1, fmt.Errorf("SSH target rejected SFTP subsystem")
	}

	exitStatus := make(chan struct {
		status int
		err    error
	}, 1)
	requestsDone := make(chan struct{})
	go func() {
		defer close(requestsDone)
		status, err := collectSftpExitStatus(requests)
		exitStatus <- struct {
			status int
			err    error
		}{status, err}
	}()
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		_, _ = io.Copy(task.SshSession().Stderr(), channel.Stderr())
	}()
	copyDone := make(chan error, 1)
	go func() {
		copyDone <- essh.FullDuplexCopy(task.Context(), task.SshSession(), channel, nil)
	}()
	select {
	case err = <-copyDone:
	case <-task.Context().Done():
		_ = channel.Close()
		err = <-copyDone
	}
	_ = channel.Close()
	<-requestsDone
	<-stderrDone
	if contextErr := task.Context().Err(); contextErr != nil {
		return -1, contextErr
	}
	if err != nil && task.Context().Err() != nil {
		return -1, task.Context().Err()
	}
	if err != nil {
		return -1, fmt.Errorf("SSH target SFTP stream failed: %w", err)
	}
	status := <-exitStatus
	if status.err != nil {
		return -1, status.err
	}
	return status.status, nil
}

func collectSftpExitStatus(requests <-chan *gossh.Request) (int, error) {
	result := -1
	received := false
	var resultErr error
	for request := range requests {
		switch request.Type {
		case "exit-status":
			var payload struct{ Status uint32 }
			if err := gossh.Unmarshal(request.Payload, &payload); err != nil {
				resultErr = fmt.Errorf("cannot decode SSH target SFTP exit status: %w", err)
			} else {
				result = int(payload.Status)
				received = true
			}
		case "exit-signal":
			resultErr = fmt.Errorf("SSH target SFTP subsystem exited by signal")
		}
		if request.WantReply {
			_ = request.Reply(false, nil)
		}
	}
	if !received && resultErr == nil {
		resultErr = fmt.Errorf("SSH target SFTP subsystem did not report an exit status")
	}
	return result, resultErr
}

func (this *sshEnvironment) openTargetChannel(ctx context.Context, transport *sshTransport, channelType string, data []byte) (gossh.Channel, <-chan *gossh.Request, error) {
	type result struct {
		channel  gossh.Channel
		requests <-chan *gossh.Request
		err      error
	}
	completed := make(chan result, 1)
	go func() {
		channel, requests, err := transport.client.OpenChannel(channelType, data)
		completed <- result{channel, requests, err}
	}()
	select {
	case actual := <-completed:
		if actual.err != nil {
			this.invalidateTransportAfterOpenError(transport, actual.err)
		}
		return actual.channel, actual.requests, actual.err
	case <-ctx.Done():
		actual := <-completed
		if actual.channel != nil {
			_ = actual.channel.Close()
		}
		return nil, nil, ctx.Err()
	}
}

func (this *sshEnvironment) invalidateTransportAfterOpenError(transport *sshTransport, err error) {
	var rejection *gossh.OpenChannelError
	if !errors.As(err, &rejection) {
		this.repository.removeTransport(this.connection.Id(), transport)
	}
}

func (this *sshEnvironment) IsPortForwardingAllowed(bnet.HostPort) (bool, error) {
	return this.settings.forwardAllowed, nil
}

func (*sshEnvironment) IsReversePortForwardingAllowed(bnet.HostPort) (bool, error) {
	return false, nil
}

func (this *sshEnvironment) NewDestinationConnection(ctx context.Context, destination bnet.HostPort) (io.ReadWriteCloser, error) {
	transport, err := this.repository.transportFor(this, ctx)
	if err != nil {
		return nil, err
	}
	if err := transport.acquireChannel(ctx); err != nil {
		return nil, err
	}
	type result struct {
		connection gonet.Conn
		err        error
	}
	completed := make(chan result, 1)
	go func() {
		connection, err := transport.client.Dial("tcp", destination.String())
		completed <- result{connection, err}
	}()
	select {
	case actual := <-completed:
		if actual.err != nil {
			transport.releaseChannel()
			this.invalidateTransportAfterOpenError(transport, actual.err)
			return nil, fmt.Errorf("cannot open SSH target connection to %s: %w", destination, actual.err)
		}
		return &sshDestinationConnection{Conn: actual.connection, release: transport.releaseChannel}, nil
	case <-ctx.Done():
		go func() {
			defer transport.releaseChannel()
			actual := <-completed
			if actual.connection != nil {
				_ = actual.connection.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

type sshDestinationConnection struct {
	gonet.Conn
	releaseOnce sync.Once
	release     func()
}

func (this *sshDestinationConnection) Close() error {
	err := this.Conn.Close()
	this.releaseOnce.Do(this.release)
	return err
}

func (this *sshDestinationConnection) CloseWrite() error {
	if connection, ok := this.Conn.(interface{ CloseWrite() error }); ok {
		return connection.CloseWrite()
	}
	return fmt.Errorf("SSH target connection does not support closing its write side")
}

func (this *sshEnvironment) Dispose(context.Context) (bool, error) { return false, nil }

func (this *sshEnvironment) Close() error { return nil }

type sshAgentBridge struct {
	listener bnet.NamedPipe
	conn     io.Closer
}

func (this *sshAgentBridge) Close() error {
	if this == nil {
		return nil
	}
	err := this.conn.Close()
	if closeErr := this.listener.Close(); err == nil {
		err = closeErr
	}
	return err
}

type sshLifetimeSession struct {
	essh.Session
	context essh.Context
}

func (this *sshLifetimeSession) Context() essh.Context { return this.context }

func (this *sshTransport) ensureAgent(task Task, lifetimeContext context.Context) error {
	this.agentMu.Lock()
	defer this.agentMu.Unlock()
	if this.agent != nil {
		return nil
	}
	// OpenSSH agent channels are connection-scoped. Phase 1 intentionally shares
	// one source agent across all allowed sessions on this source connection.
	lifetime, ok := lifetimeContext.(essh.Context)
	if !ok {
		return fmt.Errorf("connection lifetime does not provide an SSH context")
	}
	listener, err := bnet.NewNamedPipe("ssh-agent")
	if err != nil {
		return err
	}
	go bssh.ForwardAgentConnections(listener, task.Connection().Logger(), &sshLifetimeSession{task.SshSession(), lifetime})
	conn, err := bnet.ConnectToNamedPipe(lifetimeContext, listener.Path())
	if err != nil {
		_ = listener.Close()
		return err
	}
	if err := this.forwardToAgent(agent.NewClient(conn)); err != nil {
		_ = conn.Close()
		_ = listener.Close()
		return err
	}
	this.agent = &sshAgentBridge{listener: listener, conn: conn}
	return nil
}

func (this *sshTransport) forwardToAgent(keyring agent.Agent) error {
	channels := this.client.HandleChannelOpen("auth-agent@openssh.com")
	if channels == nil {
		return fmt.Errorf("SSH agent channel handler is already registered")
	}
	go func() {
		for pending := range channels {
			if !this.tryAcquireChannel() {
				_ = pending.Reject(gossh.ResourceShortage, "too many open SSH target channels")
				continue
			}
			channel, requests, err := pending.Accept()
			if err != nil {
				this.releaseChannel()
				continue
			}
			go gossh.DiscardRequests(requests)
			go func() {
				_, _ = io.Copy(io.Discard, channel.Stderr())
			}()
			go func() {
				defer this.releaseChannel()
				_ = agent.ServeAgent(keyring, channel)
				_ = channel.Close()
			}()
		}
	}()
	return nil
}
