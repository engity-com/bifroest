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
	loggerCtxKey         = struct{ uint64 }{83439637}
	authorizationCtxKey  = struct{ uint64 }{10282643}
	sessionCtxKey        = struct{ uint64 }{60219034}
	handshakeKeysCtxKey  = struct{ uint64 }{30072498}
	usedSessionKeyCtxKey = struct{ uint64 }{54185733}
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

	svc.server.IdleTimeout = 0 // handled by service's connection
	svc.server.MaxTimeout = 0  // handled by service's connection
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

func withLazyContextOrFieldExclude[C any](ctx ssh.Context, ctxKey any) fields.Lazy {
	return fields.LazyFunc(func() any {
		if v, ok := ctx.Value(ctxKey).(C); ok {
			return v
		}
		return fields.Exclude
	})
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
	if v, ok := ctx.Value(loggerCtxKey).(log.Logger); ok {
		return v
	}
	return this.Service.logger()
}

func (this *service) onNewConnConnection(ctx ssh.Context, orig net.Conn) net.Conn {
	logger := this.Service.logger().WithAll(map[string]any{
		"local":      withLazyContextOrFieldExclude[net.Addr](ctx, ssh.ContextKeyLocalAddr),
		"remoteUser": withLazyContextOrFieldExclude[string](ctx, ssh.ContextKeyUser),
		"remote":     withLazyContextOrFieldExclude[net.Addr](ctx, ssh.ContextKeyRemoteAddr),
		"ssh":        withLazyContextOrFieldExclude[string](ctx, ssh.ContextKeySessionID),
		"session":    serviceDoWithContextOrFieldExcludeErrLazy[session.Session, session.Info](ctx, sessionCtxKey, session.Session.Info),
		"flow":       serviceDoWithContextOrFieldExcludeLazy[authorization.Authorization, configuration.FlowName](ctx, authorizationCtxKey, authorization.Authorization.Flow),
	})

	wrapped, err := this.newConnection(orig, ctx, logger)
	if err != nil {
		logger.WithError(err).Error("cannot create wrap new connection")
		return nil
	}

	logger.Debug("new connection started")
	ctx.SetValue(loggerCtxKey, logger)

	return wrapped
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
			ctx.SetValue(usedSessionKeyCtxKey, key)
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
	// We've authorized via the regular public key we do not store them.
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

func (this *service) createNewServerConfig(ssh.Context) *gssh.ServerConfig {
	return &gssh.ServerConfig{
		ServerVersion: "SSH-2.0-engity-bifroest",
		MaxAuthTries:  int(this.Configuration.Ssh.MaxAuthTries),
	}
}

func (this *service) handleShellSession(sess ssh.Session) {
	this.uncheckedExecuteSession(sess, environment.TaskTypeShell)
}

func (this *service) handleSftpSession(sess ssh.Session) {
	this.uncheckedExecuteSession(sess, environment.TaskTypeSftp)
}

func (this *service) uncheckedExecuteSession(sshSess ssh.Session, taskType environment.TaskType) {
	l := this.logger(sshSess.Context())

	handled := false
	defer func() {
		if !handled {
			l.Fatal("session ended unhandled; maybe there might be previous errors in the logs")
		}
	}()

	l.With("type", taskType).
		With("env", sshSess.Environ()).
		With("command", sshSess.Command()).
		Info("new remote session")

	if exitCode, err := this.executeSession(sshSess, taskType); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			l.Info("session ended unexpectedly; maybe timeout")
			if exitCode < 0 {
				exitCode = 61
			}
			_ = sshSess.Exit(exitCode)
			handled = true
			return
		}
		le := l.WithError(err)
		switch err.Type {
		case errors.TypeUser:
			le.Warn("cannot execute session")
			if exitCode < 0 {
				exitCode = 62
			}
			_ = sshSess.Exit(exitCode)
			handled = true
		default:
			le.Error("cannot execute session")
			if exitCode < 0 {
				exitCode = 63
			}
			_ = sshSess.Exit(exitCode)
			handled = true
		}
	} else {
		l.With("exitCode", exitCode).
			Info("session ended")
		_ = sshSess.Exit(exitCode)
		handled = true
	}
}

func (this *service) executeSession(sshSess ssh.Session, taskType environment.TaskType) (int, *errors.Error) {
	fail := func(err *errors.Error) (int, *errors.Error) {
		return -1, err
	}
	failf := func(t errors.Type, msg string, args ...any) (int, *errors.Error) {
		return fail(errors.Newf(t, msg, args...))
	}

	auth, sess, err := this.resolveAuthorizationAndSession(sshSess)
	if err != nil {
		return fail(err)
	}

	if err := this.showRememberMe(sshSess, auth, sess); err != nil {
		return fail(err)
	}

	req := environmentRequest{
		service:       this,
		remote:        &remote{sshSess.Context()},
		authorization: auth,
		session:       sess,
	}

	if len(sshSess.RawCommand()) == 0 && taskType == environment.TaskTypeShell {
		banner, err := this.environment.Banner(&req)
		if err != nil {
			return failf(errors.TypeSystem, "cannot render banner: %w", err)
		}
		if banner != nil {
			defer common.IgnoreCloseError(banner)
			if _, err := io.Copy(sshSess, banner); err != nil {
				return failf(errors.TypeSystem, "cannot print banner: %w", err)
			}
		}
	}

	t := environmentTask{
		environmentRequest: req,
		sshSession:         sshSess,
		taskType:           taskType,
	}
	if exitCode, err := this.environment.Run(&t); err != nil {
		return failf(errors.TypeSystem, "run of environment failed: %w", err)
	} else {
		return exitCode, nil
	}
}

func (this *service) resolveAuthorizationAndSession(sshSess ssh.Session) (authorization.Authorization, session.Session, *errors.Error) {
	failf := func(t errors.Type, msg string, args ...any) (authorization.Authorization, session.Session, *errors.Error) {
		return nil, nil, errors.Newf(t, msg, args...)
	}

	ctx := sshSess.Context()
	auth, _ := ctx.Value(authorizationCtxKey).(authorization.Authorization)
	if auth == nil {
		return failf(errors.TypeSystem, "no authorization resolved, but it should")
	}

	sess, _ := ctx.Value(sessionCtxKey).(session.Session)
	notificationState := session.StateUnchanged
	if sess == nil {
		at, err := auth.MarshalToken()
		if err != nil {
			return failf(errors.TypeSystem, "cannot marshal the authorization token: %w", err)
		}
		sess, err = this.sessions.Create(auth.Flow(), auth.Remote(), at)
		if err != nil {
			return failf(errors.TypeSystem, "cannot create a new session for given authorization token: %w", err)
		}
		ctx.SetValue(sessionCtxKey, sess)

		if pubs, _ := ctx.Value(handshakeKeysCtxKey).([]ssh.PublicKey); len(pubs) > 0 {
			if err := sess.AddPublicKey(pubs[0]); err != nil {
				return failf(errors.TypeSystem, "cannot add public key to session: %w", err)
			}
		}
		notificationState = session.StateAuthorized
	}
	if err := sess.NotifyLastAccess(&remote{ctx}, notificationState); err != nil {
		return failf(errors.TypeSystem, "cannot update session sate: %w", err)
	}
	return auth, sess, nil
}

func (this *service) showRememberMe(sshSess ssh.Session, auth authorization.Authorization, sess session.Session) *errors.Error {
	ctx := sshSess.Context()

	if v := this.Configuration.Ssh.Keys.RememberMeNotification; !v.IsZero() {
		var pub ssh.PublicKey
		isNew := false
		if pubs, _ := ctx.Value(handshakeKeysCtxKey).([]ssh.PublicKey); len(pubs) > 0 {
			pub = pubs[0]
			isNew = true
		} else {
			pub, _ = ctx.Value(usedSessionKeyCtxKey).(ssh.PublicKey)
		}
		if pub != nil {
			buf, err := v.Render(&rememberMeNotificationContext{auth, rememberMeNotificationContextSession{sess, isNew}, pub})
			if err != nil {
				return errors.Newf(errors.TypeSystem, "cannot render remember me notification: %w", err)
			}
			if len(buf) > 0 {
				if _, err := io.WriteString(sshSess, buf); err != nil {
					return errors.Newf(errors.TypeSystem, "cannot send remember me notification: %w", err)
				}
			}
		}
	}
	return nil
}

func (this *service) registerHandshakePublicKey(ctx ssh.Context, pub ssh.PublicKey) {
	keys, _ := ctx.Value(handshakeKeysCtxKey).([]ssh.PublicKey)
	if uint8(len(keys)) < this.Configuration.Ssh.Keys.MaxKeysDuringHandshake {
		keys = append(keys, pub)
		ctx.SetValue(handshakeKeysCtxKey, keys)
	}
}

func (this *service) Close() (rErr error) {
	defer common.KeepCloseError(&rErr, this.sessions)
	defer common.KeepCloseError(&rErr, this.authorization)
	defer common.KeepCloseError(&rErr, this.environment)
	return nil
}
