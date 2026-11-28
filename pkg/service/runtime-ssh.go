package service

import (
	"context"
	"fmt"
	"net"
	"sync"

	essh "github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"
)

// The process servers stay immutable, including their Serve-scoped protection
// budgets. Only ConnCallback selects current; all subsequent callbacks use the
// admitted connection, never the latest configuration or a copied server.
func (this *service) sshService(ctx context.Context) *service {
	if ctx != nil {
		if conn, _ := ctx.Value(connectionCtxKey).(*connection); conn != nil {
			return conn.service
		}
	}
	return this // Errors before ConnCallback have no generation-specific work.
}

func (this *runtimeResources) generationService(generation *runtimeGeneration) (*service, error) {
	// The caller must hold a generation lease throughout lookup and use.
	if generation == this.owner.generation {
		return this.owner, nil
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	for svc := range this.views {
		if svc.generation == generation {
			return svc, nil
		}
	}
	return nil, fmt.Errorf("admitted runtime generation has no provider view")
}

func (this *service) handlerLifecycle() *connectionLifecycle {
	if this.resources != nil {
		return this.resources.handlers
	}
	return this.connectionLifecycle
}

// Retiring the initial providers must not stop process-wide handler admission.
// Conversely, shutdown must also wait for handlers using later generations.
func (this *service) registerConnectionHandler() (func(), bool) {
	release, ok := this.connectionLifecycle.register()
	if !ok {
		return nil, false
	}
	if process := this.handlerLifecycle(); process != this.connectionLifecycle {
		releaseProcess, ok := process.register()
		if !ok {
			release()
			return nil, false
		}
		releaseGeneration := release
		release = sync.OnceFunc(func() { releaseGeneration(); releaseProcess() })
	}
	return release, true
}

func (this *service) admitSshConnection(ctx essh.Context, orig net.Conn) (net.Conn, error) {
	var selection *runtimeAdmission
	if this.runtime != nil {
		selected, release, err := this.runtime.selectCurrent()
		if err != nil {
			return nil, err
		}
		defer release()
		selection = selected
	}
	return this.admitSelectedSshConnection(ctx, orig, selection)
}

func (this *service) admitSelectedSshConnection(ctx essh.Context, orig net.Conn, selection *runtimeAdmission) (net.Conn, error) {
	owner := this
	if selection != nil {
		if this.resources != nil {
			var err error
			owner, err = this.resources.generationService(selection.generation)
			if err != nil {
				return nil, err
			}
		} else if owner.generation != selection.generation {
			return nil, fmt.Errorf("SSH runtime dispatch requires prepared provider views")
		}
	}
	wrapped, err := owner.onNewConnConnection(ctx, orig)
	if err != nil || wrapped == nil {
		return wrapped, err
	}
	conn := this.connection(ctx)
	releaseRuntime := func() {}
	if this.runtime != nil {
		releaseRuntime, err = this.runtime.admitSelected(selection, conn)
		if err != nil {
			if releaseRuntime != nil {
				releaseRuntime()
			}
			_ = conn.Close()
			_ = owner.onConnectionFailed(ctx, orig, err)
			return nil, err
		}
	}
	releaseHandler, ok := owner.registerConnectionHandler()
	if !ok {
		releaseRuntime()
		_ = conn.Close()
		_ = owner.onConnectionFailed(ctx, orig, context.Canceled)
		return nil, context.Canceled
	}
	admission := &sshConnectionAdmission{conn: conn}
	admission.release = sync.OnceFunc(func() { releaseHandler(); releaseRuntime() })
	conn.sshAdmission = admission
	ctx.SetValue(connectionLifecycleCtxKey, admission.finish)
	// Serve can exit between ConnCallback and ServerConfigCallback without a
	// failure callback (e.g. shutdown loses updateConnection). Cancellation may
	// release only this provisional admission, never a running handshake/handler.
	admission.mutex.Lock()
	admission.stop = context.AfterFunc(ctx, admission.abandon)
	admission.mutex.Unlock()
	return wrapped, nil
}

type sshConnectionAdmission struct {
	conn    *connection
	mutex   sync.Mutex
	claimed bool
	ended   bool
	stop    func() bool
	release func()
}

func (this *sshConnectionAdmission) claim() error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.ended || this.claimed {
		return context.Canceled
	}
	this.claimed = true
	return this.conn.context.Err()
}

func (this *sshConnectionAdmission) abandon() {
	this.mutex.Lock()
	if this.claimed || this.ended {
		this.mutex.Unlock()
		return
	}
	this.ended = true
	this.mutex.Unlock()
	_ = this.conn.Close()
	_ = this.conn.service.onConnectionFailed(this.conn.context, this.conn, this.conn.context.Err())
}

func (this *sshConnectionAdmission) finish() {
	this.mutex.Lock()
	this.ended = true
	stop := this.stop
	this.mutex.Unlock()
	if stop != nil {
		stop()
	}
	this.release()
}

func (this *service) dispatchSshConfig(ctx essh.Context, conn net.Conn, target *gossh.ServerConfig) error {
	wrapped := this.connection(ctx)
	if wrapped == nil || wrapped.sshAdmission == nil {
		return fmt.Errorf("SSH configuration requires a runtime admission")
	}
	if err := wrapped.sshAdmission.claim(); err != nil {
		return err
	}
	return wrapped.service.createNewServerConfig(ctx, conn, target)
}

func (this *service) dispatchSshFailure(ctx essh.Context, conn net.Conn, err error) error {
	if wrapped := this.connection(ctx); wrapped != nil && wrapped.sshAdmission != nil {
		admission := wrapped.sshAdmission
		admission.mutex.Lock()
		if admission.ended {
			admission.mutex.Unlock()
			return nil // Provisional cancellation already performed cleanup.
		}
		admission.claimed = true // Exclude provisional cleanup during this callback.
		admission.mutex.Unlock()
	}
	return this.sshService(ctx).onConnectionFailed(ctx, conn, err)
}

func (this *service) configureSshDispatch(server *essh.Server) {
	server.ConnCallback = this.admitSshConnection
	server.ServerConfigCallback = this.dispatchSshConfig
	server.ConnectionFailedCallback = this.dispatchSshFailure
	server.DisconnectCallback = func(ctx essh.Context, conn net.Conn) error {
		return this.sshService(ctx).onDisconnected(ctx, conn)
	}
	server.Handler = func(sess essh.Session) error {
		return this.sshService(sess.Context()).handleSshShellSession(sess)
	}
	server.PtyCallback = func(ctx essh.Context, sess essh.Session, pty essh.Pty) (bool, error) {
		return this.sshService(ctx).onPtyRequest(ctx, sess, pty)
	}
	server.SessionRequestCallback = func(sess essh.Session, kind string) (bool, error) {
		return this.sshService(sess.Context()).onSessionRequest(sess, kind)
	}
	server.ReversePortForwardingCallback = func(ctx essh.Context, conn gossh.ConnMetadata, host string, port uint32) (bool, error) {
		return this.sshService(ctx).onReversePortForwardingRequested(ctx, conn, host, port)
	}
	server.PublicKeyHandler = func(ctx essh.Context, conn gossh.ConnMetadata, key essh.PublicKey) (bool, error) {
		return this.sshService(ctx).handlePublicKey(ctx, conn, key)
	}
	server.PasswordHandler = func(ctx essh.Context, conn gossh.ConnMetadata, password string) (bool, error) {
		return this.sshService(ctx).handlePassword(ctx, conn, password)
	}
	server.KeyboardInteractiveHandler = func(ctx essh.Context, conn gossh.ConnMetadata, challenge gossh.KeyboardInteractiveChallenge) (bool, error) {
		return this.sshService(ctx).handleKeyboardInteractiveChallenge(ctx, conn, challenge)
	}
	server.BannerHandler = func(ctx essh.Context, conn gossh.ConnMetadata) (string, error) {
		return this.sshService(ctx).handleBanner(ctx, conn)
	}
	server.AgentForwardingCallback = func(ctx essh.Context, sess essh.Session) (bool, error) {
		return this.sshService(ctx).onAgentForwardingRequested(ctx, sess)
	}
	forward := func(response essh.RequestResponseWriter, request *essh.Request) error {
		return this.sshService(request.Context()).forwardHandler.HandleSSHRequest(response, request)
	}
	server.RequestHandlers = map[string]essh.RequestHandler{
		"keepalive@openssh.com": func(response essh.RequestResponseWriter, _ *essh.Request) error { return response.Accept(nil) },
		"tcpip-forward":         forward,
		"cancel-tcpip-forward":  forward,
	}
	server.ChannelHandlers = map[string]essh.ChannelHandler{
		"session": func(srv *essh.Server, conn *gossh.ServerConn, channel gossh.NewChannel, ctx essh.Context) error {
			return this.sshService(ctx).handleNewSshSession(srv, conn, channel, ctx)
		},
		"direct-tcpip": func(srv *essh.Server, conn *gossh.ServerConn, channel gossh.NewChannel, ctx essh.Context) error {
			return this.sshService(ctx).handleNewDirectTcpIp(srv, conn, channel, ctx)
		},
	}
	subsystem := func(sess essh.Session, reply essh.SubsystemReply) error {
		return this.sshService(sess.Context()).handleSshSubsystemSession(sess, reply)
	}
	server.DeferredSubsystemHandlers = map[string]essh.DeferredSubsystemHandler{"sftp": subsystem, "default": subsystem}
}
