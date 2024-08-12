package service

import (
	"context"
	"fmt"
	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/fields"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/errors"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/gliderlabs/ssh"
	gssh "golang.org/x/crypto/ssh"
	"io"
	"net"
	"sync"
	"time"
)

var (
	loggerCtxKey        = struct{ uint64 }{83439637}
	authorizationCtxKey = struct{ uint64 }{10282643}
	sessionCtxKey       = struct{ uint64 }{60219034}
	handshakeKeysCtxKey = struct{ uint64 }{30072498}
)

type Service struct {
	Configuration configuration.Configuration

	Logger log.Logger
}

func (this *Service) isProblematicError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	return true
}

func (this *Service) Run(ctx context.Context) (rErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	svc, err := this.prepare()
	if err != nil {
		return err
	}
	defer common.KeepCloseError(&rErr, svc)

	lns := make([]struct {
		ln   net.Listener
		addr bnet.NetAddress
	}, len(this.Configuration.Ssh.Addresses))
	var lnMutex sync.Mutex
	closeLns := func() {
		lnMutex.Lock()
		defer lnMutex.Unlock()

		for _, ln := range lns {
			if ln.ln != nil {
				defer func(target *net.Listener) {
					*target = nil
				}(&ln.ln)
				if err := ln.ln.Close(); this.isProblematicError(err) && rErr == nil {
					rErr = err
				}
			}
		}
	}
	defer closeLns()

	for i, addr := range this.Configuration.Ssh.Addresses {
		ln, err := addr.Listen()
		if err != nil {
			return fmt.Errorf("cannot listen to %v: %w", addr, err)
		}
		lns[i].addr = addr
		lns[i].ln = ln
	}

	done := make(chan error, len(lns))
	var wg sync.WaitGroup
	for _, ln := range lns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l := this.logger().With("address", ln.addr)

			l.Info("listening...")
			if err := svc.server.Serve(ln.ln); this.isProblematicError(err) {
				l.WithError(err).Error("listening... FAILED!")
				done <- err
				return
			}
			l.Info("listening... DONE!")
			done <- nil
		}()
	}

	go func() {
		for {
			select {
			case err, ok := <-done:
				if !ok {
					return
				}
				if this.isProblematicError(err) && rErr == nil {
					rErr = err
				}
				closeLns()
			case <-ctx.Done():
				if err := ctx.Err(); this.isProblematicError(err) && rErr == nil {
					rErr = err
				}
				closeLns()
			}
		}
	}()
	wg.Wait()

	close(done)

	return
}

func (this *Service) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("service")
}

func (this *Service) prepare() (svc *service, err error) {
	fail := func(err error) (*service, error) {
		return nil, fmt.Errorf("cannot prepare service: %w", err)
	}

	ctx := context.Background()
	svc = &service{Service: this}

	if svc.sessions, err = session.NewRepositoryFacade(ctx, &this.Configuration.Session); err != nil {
		return fail(err)
	}
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

	sessions      session.CloseableRepository
	authorization authorization.CloseableAuthorizer
	environment   environment.CloseableEnvironment
	server        ssh.Server
}

func serviceDoWithContext[C any, T any](ctx ssh.Context, ctxKey any, converter func(C) T, or T) T {
	if v, ok := ctx.Value(ctxKey).(C); ok {
		return converter(v)
	}
	return or
}

func serviceDoWithContextLazy[C any, T any](ctx ssh.Context, ctxKey any, converter func(C) T, or T) fields.Lazy {
	return fields.LazyFunc(func() any {
		return serviceDoWithContext[C, T](ctx, ctxKey, converter, or)
	})
}

func serviceDoWithContextOrFieldExcludeErrLazy[C any, T any](ctx ssh.Context, ctxKey any, converter func(C) (T, error)) fields.Lazy {
	return serviceDoWithContextLazy[C, any](ctx, ctxKey, func(c C) any {
		v, err := converter(c)
		if err != nil {
			return fields.Exclude
		}
		return v
	}, fields.Exclude)
}

func serviceDoWithContextOrFieldExcludeLazy[C any, T any](ctx ssh.Context, ctxKey any, converter func(C) T) fields.Lazy {
	return serviceDoWithContextLazy[C, any](ctx, ctxKey, func(c C) any {
		return converter(c)
	}, fields.Exclude)
}

func (this *service) logger(ctx ssh.Context) log.Logger {
	var result log.Logger
	if v, ok := ctx.Value(loggerCtxKey).(log.Logger); ok {
		result = v
	} else {
		result = this.Service.logger()
	}
	result.With("remoteUser", fields.LazyFunc(func() any { return ctx.User() }))
	result.With("remote", fields.LazyFunc(func() any { return ctx.RemoteAddr() }))
	result.With("ssh", fields.LazyFunc(func() any { return ctx.SessionID() }))
	result.With("session", serviceDoWithContextOrFieldExcludeErrLazy[session.Session, session.Info](ctx, sessionCtxKey, session.Session.Info))
	result.With("flow", serviceDoWithContextOrFieldExcludeLazy[authorization.Authorization, configuration.FlowName](ctx, authorizationCtxKey, authorization.Authorization.Flow))

	return result
}

func (this *service) setLogger(ctx ssh.Context, logger log.Logger) {
	ctx.SetValue(loggerCtxKey, logger)
}

func (this *service) onNewConnConnection(ctx ssh.Context, conn net.Conn) net.Conn {
	logger := this.logger(ctx)
	logger.Debug("new connection started")
	this.setLogger(ctx, logger)

	return conn
}

func (this *service) onLocalPortForwardingRequested(ctx ssh.Context, destinationHost string, destinationPort uint32) bool {
	l := this.logger(ctx).
		With("host", destinationHost).
		With("port", destinationPort)

	l.Debug("local port forwarding currently not supported")
	return false // TODO! Handle port forwarding
}

func (this *service) onReversePortForwardingRequested(ctx ssh.Context, bindHost string, bindPort uint32) bool {
	l := this.logger(ctx).
		With("host", bindHost).
		With("port", bindPort)

	l.Debug("reverse port forwarding currently not supported")
	return false // TODO! Handle port forwarding
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

	this.registerHandshakePublicKey(ctx, key)

	authReq := authorizeRequest{
		service: this,
		remote:  remote{ctx},
	}

	var auth authorization.Authorization
	sess, err := this.sessions.FindByPublicKey(key, func(candidate session.Session) (bool, error) {
		info, err := candidate.Info()
		if err != nil {
			return false, err
		}
		vu, err := info.ValidUntil()
		if err != nil {
			return false, err
		}
		return time.Now().Before(vu), nil //TODO! More checks?
	})
	if errors.Is(err, session.ErrNoSuchSession) {
		// Ok, just continue...
	} else if err != nil {
		l.WithError(err).
			Error("cannot check for existing session")
		return false
	} else {
		auth, err = this.authorization.AuthorizeSession(&sessionAuthorizeRequest{authReq, sess})
		if err != nil {
			if eErr, ok := errors.IsError(err); ok && eErr.Type == errors.TypeUser {
				l.WithError(err).Debug("session based authorization failed by user; continue with regular...")
			} else {
				if !this.isSilentError(err) {
					l.WithError(err).Warn("was not able to resolve public key authorization request; treat as rejected")
				}
				return false
			}
		} else if auth.IsAuthorized() {
			ctx.SetValue(sessionCtxKey, sess)
		}
	}

	if auth == nil || !auth.IsAuthorized() {
		auth, err = this.authorization.AuthorizePublicKey(&publicKeyAuthorizeRequest{authReq, key})
		if err != nil {
			if eErr, ok := errors.IsError(err); ok && eErr.Type == errors.TypeUser {
				l.WithError(err).Debug("public key failed by user")
				return false
			}
			if !this.isSilentError(err) {
				l.WithError(err).Warn("was not able to resolve public key authorization request; treat as rejected")
			}
			return false
		}
	}

	if auth == nil || !auth.IsAuthorized() {
		l.Debug("public key rejected")
		return false
	}

	ctx.SetValue(authorizationCtxKey, auth)
	// We've authorized via the public key we do not store them.
	ctx.SetValue(handshakeKeysCtxKey, nil)

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
		if eErr, ok := errors.IsError(err); ok && eErr.Type == errors.TypeUser {
			l.WithError(err).Debug("password failed by user")
			return false
		}
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
		if eErr, ok := errors.IsError(err); ok && eErr.Type == errors.TypeUser {
			l.WithError(err).Debug("interactive failed by user")
			return false
		}
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
	l := this.logger(ctx)
	this.setLogger(ctx, l)

	if b, err := this.Configuration.Ssh.Banner.Render(&BannerContext{ctx}); err != nil {
		l.WithError(err).Warn("cannot retrieve banner; showing none")
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

	l.With("type", "shell").
		With("env", sess.Environ()).
		With("command", sess.Command()).
		Info("new remote session")

	this.executeSession(sess, environment.TaskTypeShell, l)
}

func (this *service) handleSftpSession(sess ssh.Session) {
	l := this.logger(sess.Context())

	l.With("type", "sftp").
		With("env", sess.Environ()).
		With("command", sess.Command()).
		Info("new remote session")

	this.executeSession(sess, environment.TaskTypeSftp, l)
}

func (this *service) executeSession(sshSess ssh.Session, taskType environment.TaskType, l log.Logger) {
	defer func() { l.Info("session ended") }()

	ctx := sshSess.Context()
	auth, _ := ctx.Value(authorizationCtxKey).(authorization.Authorization)
	if auth == nil {
		l.Error("no authorization resolved, but it should")
		_ = sshSess.Exit(91)
		return
	}

	sess, _ := ctx.Value(sessionCtxKey).(session.Session)
	if sess == nil {
		at, err := auth.MarshalToken()
		if err != nil {
			l.WithError(err).Error("cannot marshal authorization token")
			_ = sshSess.Exit(92)
		}
		sess, err = this.sessions.Create(auth.Flow(), auth.Remote(), at)
		if err != nil {
			l.WithError(err).Error("cannot create session")
			_ = sshSess.Exit(92)
			return
		} else {
			ctx.SetValue(sessionCtxKey, sess)
		}
	}

	req := environmentRequest{
		service:       this,
		remote:        &remote{ctx},
		authorization: auth,
		session:       sess,
	}

	if sess != nil {
		pubs := this.handshakePublicKeys(ctx)
		if len(pubs) > 0 {
			if err := sess.AddPublicKey(pubs[0]); err != nil {
				l.WithError(err).Error("cannot add public key to session")
				_ = sshSess.Exit(92)
				return
			}
			if v := this.Configuration.Ssh.Keys.RememberMeNotification; !v.IsZero() {
				buf, err := v.Render(&rememberMeNotificationContext{auth, sess, pubs[0]})
				if err != nil {
					l.WithError(err).Error("cannot render remember me notification")
					_ = sshSess.Exit(92)
					return
				}
				_, _ = io.WriteString(sshSess, buf)
			}
		}

		if err := sess.NotifyLastAccess(req.remote, session.StateAuthorized); err != nil {
			l.WithError(err).Error("cannot update session sate")
			_ = sshSess.Exit(92)
			return
		}
	}

	if len(sshSess.RawCommand()) == 0 && taskType == environment.TaskTypeShell {
		banner, err := this.environment.Banner(&req)
		if err != nil {
			l.WithError(err).Error("cannot retrieve banner")
			_ = sshSess.Exit(92)
			return
		}
		if banner != nil {
			defer common.IgnoreCloseError(banner)
			if _, err := io.Copy(sshSess, banner); err != nil {
				l.WithError(err).Error("cannot print banner")
				_ = sshSess.Exit(92)
			}
		}
	}

	t := environmentTask{
		environmentRequest: req,
		sshSession:         sshSess,
		taskType:           taskType,
	}
	if err := this.environment.Run(&t); err != nil {
		l.WithError(err).Error("run of environment failed")
		_ = sshSess.Exit(93)
		return
	}

	_ = sshSess.Exit(0)
}

func (this *service) registerHandshakePublicKey(ctx ssh.Context, pub ssh.PublicKey) {
	keys, _ := ctx.Value(handshakeKeysCtxKey).([]ssh.PublicKey)
	if uint8(len(keys)) < this.Configuration.Ssh.Keys.MaxKeysDuringHandshake {
		keys = append(keys, pub)
		ctx.SetValue(handshakeKeysCtxKey, keys)
	}
}

func (this *service) handshakePublicKeys(ctx ssh.Context) []ssh.PublicKey {
	keys, _ := ctx.Value(handshakeKeysCtxKey).([]ssh.PublicKey)
	return keys
}

func (this *service) Close() (rErr error) {
	defer common.KeepCloseError(&rErr, this.sessions)
	defer common.KeepCloseError(&rErr, this.authorization)
	defer common.KeepCloseError(&rErr, this.environment)
	return nil
}
