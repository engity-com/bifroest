package service

import (
	"context"
	"errors"
	"fmt"
	log "github.com/echocat/slf4g"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/gliderlabs/ssh"
	gssh "golang.org/x/crypto/ssh"
	"io"
	"net"
	"sync"
)

var (
	loggerCtxKey        = struct{ uint64 }{83439637}
	authorizationCtxKey = struct{ uint64 }{10282643}
)

type Service struct {
	Configuration configuration.Configuration

	Logger log.Logger
}

func (this *Service) Run() error {
	svc, err := this.prepare()
	if err != nil {
		return err
	}

	lns := make([]struct {
		ln   net.Listener
		addr common.NetAddress
	}, len(this.Configuration.Ssh.Addresses))
	defer func() {
		// Close all opened listeners
		for _, ln := range lns {
			if ln.ln != nil {
				_ = ln.ln.Close()
			}
		}
	}()
	for i, addr := range this.Configuration.Ssh.Addresses {
		ln, err := addr.Listen()
		if err != nil {
			return fmt.Errorf("cannot listen to %v: %w", addr, err)
		}
		lns[i].addr = addr
		lns[i].ln = ln
	}

	var wg sync.WaitGroup
	for _, ln := range lns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l := log.With("address", ln.addr)

			l.Info("listening...")
			if err := svc.server.Serve(ln.ln); err != nil {
				l.WithError(err).Fatal("cannot serve")
			}
		}()
	}

	wg.Wait()

	return nil
}

func (this *Service) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetRootLogger()
}

func (this *Service) prepare() (svc *service, err error) {
	fail := func(err error) (*service, error) {
		return nil, fmt.Errorf("cannot prepare service: %w", err)
	}

	ctx := context.Background()
	svc = &service{Service: this}

	if svc.authorization, err = authorization.NewFacade(ctx, &this.Configuration.Flows); err != nil {
		return fail(err)
	}
	if svc.environment, err = environment.NewFacade(ctx, &this.Configuration.Flows); err != nil {
		return fail(err)
	}
	if err := this.prepareServer(ctx, svc); err != nil {
		return fail(err)
	}

	return svc, nil
}

func (this *Service) prepareServer(_ context.Context, svc *service) (err error) {
	fail := func(err error) error {
		return err
	}

	forwardHandler := &ssh.ForwardedTCPHandler{}

	svc.server.IdleTimeout = this.Configuration.Ssh.IdleTimeout.Native()
	svc.server.MaxTimeout = this.Configuration.Ssh.MaxTimeout.Native()
	svc.server.ServerConfigCallback = svc.createNewServerConfig
	svc.server.ConnCallback = svc.onNewConnConnection
	svc.server.Handler = svc.handleShellSession
	svc.server.LocalPortForwardingCallback = svc.onLocalPortForwardingRequested
	svc.server.ReversePortForwardingCallback = svc.onReversePortForwardingRequested
	svc.server.PublicKeyHandler = svc.handlePublicKey
	svc.server.PasswordHandler = svc.handlePassword
	svc.server.KeyboardInteractiveHandler = svc.handleKeyboardInteractiveChallenge
	svc.server.BannerHandler = svc.handleBanner
	svc.server.RequestHandlers = map[string]ssh.RequestHandler{
		"tcpip-forward":        forwardHandler.HandleSSHRequest,
		"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
	}
	svc.server.ChannelHandlers = map[string]ssh.ChannelHandler{
		"session": svc.handleNewSession,
	}
	svc.server.SubsystemHandlers = map[string]ssh.SubsystemHandler{
		"sftp": svc.handleSftpSession,
	}
	if svc.server.HostSigners, err = this.loadHostSigners(); err != nil {
		return fail(err)
	}

	return nil
}

func (this *Service) loadHostSigners() ([]ssh.Signer, error) {
	kc := &this.Configuration.Ssh.Keys
	result := make([]ssh.Signer, len(kc.HostKeys))
	for i, fn := range kc.HostKeys {
		pk, err := crypto.EnsureKeyFile(fn, &crypto.KeyRequirement{
			Type: crypto.KeyTypeEd25519,
		}, nil)
		if err != nil {
			return nil, fmt.Errorf("cannot ensure host key: %w", err)
		}

		if ok, err := kc.KeyAllowed(pk); err != nil {
			return nil, fmt.Errorf("cannot check if host key %q is allowed or not: %w", fn, err)
		} else if !ok {
			return nil, fmt.Errorf("cannot check if host key %q is not allowed by restrictions: %w", fn, err)
		}

		signer, err := gssh.NewSignerFromKey(pk)
		if err != nil {
			return nil, fmt.Errorf("cannot convert host key %q: %w", fn, err)
		}
		result[i] = signer
	}
	return result, nil
}

type service struct {
	*Service

	authorization authorization.Authorizer
	environment   environment.Environment
	server        ssh.Server
}

func (this *service) logger(ctx ssh.Context) log.Logger {
	if v, ok := ctx.Value(loggerCtxKey).(log.Logger); ok {
		return v
	}
	return this.Service.logger()
}

func (this *service) setLogger(ctx ssh.Context, logger log.Logger) {
	ctx.SetValue(loggerCtxKey, logger)
}

func (this *service) onNewConnConnection(ctx ssh.Context, conn net.Conn) net.Conn {
	logger := log.
		With("remote", conn.RemoteAddr())
	logger.Debug("new connection started")
	this.setLogger(ctx, logger)

	return conn
}

func (this *service) onLocalPortForwardingRequested(ctx ssh.Context, destinationHost string, destinationPort uint32) bool {
	l := this.logger(ctx).
		With("host", destinationHost).
		With("port", destinationPort)

	l.Debug("local port forwarding request was accepted")
	return true // TODO! Handle port forwarding
}

func (this *service) onReversePortForwardingRequested(ctx ssh.Context, bindHost string, bindPort uint32) bool {
	l := this.logger(ctx).
		With("host", bindHost).
		With("port", bindPort)

	l.Debug("reverse port forwarding request was accepted")
	return true // TODO! Handle port forwarding
}

func (this *service) isSilentError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	return false
}

func (this *service) handlePublicKey(ctx ssh.Context, key ssh.PublicKey) bool {
	l := this.logger(ctx).
		With("key", key.Type()+":"+gssh.FingerprintLegacyMD5(key))

	keyTypeAllowed, err := this.Configuration.Ssh.Keys.KeyAllowed(key)
	if err != nil {
		l.WithError(err).
			Error("cannot check key type")
		return false
	}
	if !keyTypeAllowed {
		l.Debug("public key type forbidden")
		return false
	}

	auth, err := this.authorization.AuthorizePublicKey(&publicKeyAuthorizeRequest{
		authorizeRequest: authorizeRequest{
			service: this,
			remote:  remote{ctx},
		},
		publicKey: key,
	})
	if err != nil {
		if !this.isSilentError(err) {
			l.WithError(err).Warn("was not able to resolve public key authorization request; treat as rejected")
		}
		return false
	}
	if !auth.IsAuthorized() {
		l.Debug("public key rejected")
		return false
	}

	ctx.SetValue(authorizationCtxKey, auth)

	l.Debug("public key accepted")
	return true
}

func (this *service) handlePassword(ctx ssh.Context, password string) bool {
	l := this.logger(ctx)

	auth, err := this.authorization.AuthorizePassword(&passwordAuthorizeRequest{
		authorizeRequest: authorizeRequest{
			service: this,
			remote:  remote{ctx},
		},
		password: password,
	})
	if err != nil {
		if !this.isSilentError(err) {
			l.WithError(err).Warn("was not able to resolve password authorization request; treat as rejected")
		}
		return false
	}
	if !auth.IsAuthorized() {
		l.Debug("password rejected")
		return false
	}

	ctx.SetValue(authorizationCtxKey, auth)

	l.Debug("password accepted")
	return true
}

func (this *service) handleKeyboardInteractiveChallenge(ctx ssh.Context, challenger gssh.KeyboardInteractiveChallenge) bool {
	l := this.logger(ctx)

	auth, err := this.authorization.AuthorizeInteractive(&interactiveAuthorizeRequest{
		authorizeRequest: authorizeRequest{
			service: this,
			remote:  remote{ctx},
		},
		challenger: challenger,
	})
	if err != nil {
		if !this.isSilentError(err) {
			l.WithError(err).Warn("was not able to resolve interactive authorization request; treat as rejected")
		}
		return false
	}
	if !auth.IsAuthorized() {
		l.Debug("interactive rejected")
		return false
	}

	ctx.SetValue(authorizationCtxKey, auth)

	l.Debug("interactive accepted")
	return true
}

func (this *service) handleBanner(ctx ssh.Context) string {
	l := this.logger(ctx).
		With("remoteUser", ctx.User()).
		With("sessionId", ctx.SessionID())
	this.setLogger(ctx, l)

	if b, err := this.Configuration.Ssh.Banner.Render(&BannerContext{ctx}); err != nil {
		log.WithError(err).Warn("cannot retrieve banner; showing none")
		return ""
	} else {
		return b
	}
}

type BannerContext struct {
	Context ssh.Context
}

func (this *service) handleNewSession(srv *ssh.Server, conn *gssh.ServerConn, newChan gssh.NewChannel, ctx ssh.Context) {
	ssh.DefaultSessionHandler(srv, conn, newChan, ctx)
}

func (this *service) createNewServerConfig(ctx ssh.Context) *gssh.ServerConfig {
	return &gssh.ServerConfig{
		ServerVersion: "SSH-2.0-engity-bifroest",
		MaxAuthTries:  int(this.Configuration.Ssh.MaxAuthTries),
	}
}

func (this *service) handleShellSession(sess ssh.Session) {
	l := this.logger(sess.Context())

	l.With("remote", sess.RemoteAddr()).
		With("type", "shell").
		With("env", sess.Environ()).
		With("command", sess.Command()).
		Info("new remote session")

	this.executeSession(sess, environment.TaskTypeShell, l)
}

func (this *service) handleSftpSession(sess ssh.Session) {
	l := this.logger(sess.Context())

	l.With("remote", sess.RemoteAddr()).
		With("type", "sftp").
		With("env", sess.Environ()).
		With("command", sess.Command()).
		Info("new remote session")

	this.executeSession(sess, environment.TaskTypeSftp, l)
}

func (this *service) executeSession(sess ssh.Session, taskType environment.TaskType, l log.Logger) {
	defer func() { l.Info("session ended") }()

	auth := sess.Context().Value(authorizationCtxKey).(authorization.Authorization)
	if auth == nil {
		l.Error("no authorization resolved, but it should")
		_ = sess.Exit(91)
		return
	}

	req := environmentRequest{
		service:       this,
		remote:        &remote{sess.Context()},
		authorization: auth,
	}

	if len(sess.RawCommand()) == 0 && taskType == environment.TaskTypeShell {
		banner, err := this.environment.Banner(&req)
		if err != nil {
			l.WithError(err).Error("cannot retrieve banner")
			_ = sess.Exit(92)
			return
		}
		if banner != nil {
			defer common.IgnoreCloseError(banner)
			if _, err := io.Copy(sess, banner); err != nil {
				l.WithError(err).Error("cannot print banner")
				_ = sess.Exit(92)
			}
		}
	}

	t := environmentTask{
		environmentRequest: req,
		session:            sess,
		taskType:           taskType,
	}
	if err := this.environment.Run(&t); err != nil {
		l.WithError(err).Error("run of environment failed")
		_ = sess.Exit(93)
		return
	}

	_ = sess.Exit(0)
}
