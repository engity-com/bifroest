package service

import (
	essh "github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

func (this *service) handlePublicKey(ctx essh.Context, _ gossh.ConnMetadata, key essh.PublicKey) (bool, error) {
	conn := this.connection(ctx)
	if conn == nil {
		return false, nil
	}
	l := conn.logger.
		With("key", key.Type()+":"+gossh.FingerprintLegacyMD5(key))

	keyTypeAllowed, err := this.Configuration.Ssh.Keys.KeyAllowed(key)
	if err != nil {
		return false, errors.Newf(errors.System, "cannot check key type: %w", err)
	}
	if !keyTypeAllowed {
		l.Debug("public key type forbidden")
		return false, nil
	}

	if _, ok := ctx.Value(handshakeKeyCtxKey).(essh.PublicKey); !ok {
		ctx.SetValue(handshakeKeyCtxKey, key)
	}

	authReq := authorizeRequest{
		service:    this,
		connection: conn,
	}

	auth, err := this.authorizer.AuthorizePublicKey(&publicKeyAuthorizeRequest{authReq, key})
	if err != nil {
		if errors.IsType(err, errors.User) {
			l.WithError(err).Debug("public key failed by user")
			return false, nil
		}
		return false, errors.Newf(errors.System, "cannot resolve public key authorization request: %w", err)
	}

	if auth == nil || !auth.IsAuthorized() {
		l.Debug("public key rejected")
		return false, nil
	}
	if compatible, err := authReq.IsSessionCompatible(auth); err != nil {
		return false, errors.Newf(errors.System, "cannot validate environment session compatibility: %w", err)
	} else if !compatible {
		l.Debug("public key session is incompatible with the current environment")
		return false, nil
	}

	ctx.SetValue(authorizationCtxKey, auth)
	// We've authorized via the regular public key we do not store them.
	ctx.SetValue(handshakeKeyCtxKey, nil)

	l.Debug("public key accepted")
	return true, nil
}

func (this *service) handlePassword(ctx essh.Context, _ gossh.ConnMetadata, password string) (bool, error) {
	conn := this.connection(ctx)
	if conn == nil {
		return false, nil
	}
	l := conn.logger

	authReq := authorizeRequest{service: this, connection: conn}
	auth, err := this.authorizer.AuthorizePassword(&passwordAuthorizeRequest{
		authorizeRequest: authReq,
		password:         password,
	})
	if err != nil {
		if errors.IsType(err, errors.User) {
			l.WithError(err).Debug("password failed by user")
			return false, nil
		}
		return false, errors.Newf(errors.System, "cannot resolve password authorization request: %w", err)
	}
	if auth == nil || !auth.IsAuthorized() {
		l.Debug("password rejected")
		return false, nil
	}
	if compatible, err := authReq.IsSessionCompatible(auth); err != nil {
		return false, errors.Newf(errors.System, "cannot validate environment session compatibility: %w", err)
	} else if !compatible {
		l.Debug("password session is incompatible with the current environment")
		return false, nil
	}

	ctx.SetValue(authorizationCtxKey, auth)

	l.Debug("password accepted")
	return true, nil
}

func (this *service) handleKeyboardInteractiveChallenge(ctx essh.Context, _ gossh.ConnMetadata, challenger gossh.KeyboardInteractiveChallenge) (bool, error) {
	conn := this.connection(ctx)
	if conn == nil {
		return false, nil
	}
	l := conn.logger

	authReq := authorizeRequest{service: this, connection: conn}
	auth, err := this.authorizer.AuthorizeInteractive(&interactiveAuthorizeRequest{
		authorizeRequest: authReq,
		challenger:       challenger,
	})
	if err != nil {
		if errors.IsType(err, errors.User) {
			l.WithError(err).Debug("interactive failed by user")
			return false, nil
		}
		return false, errors.Newf(errors.System, "cannot resolve interactive authorization request: %w", err)
	}
	if auth == nil || !auth.IsAuthorized() {
		l.Debug("interactive rejected")
		return false, nil
	}
	if compatible, err := authReq.IsSessionCompatible(auth); err != nil {
		return false, errors.Newf(errors.System, "cannot validate environment session compatibility: %w", err)
	} else if !compatible {
		l.Debug("interactive session is incompatible with the current environment")
		return false, nil
	}

	ctx.SetValue(authorizationCtxKey, auth)

	l.Debug("interactive accepted")
	return true, nil
}

func (this *service) resolveAuthorizationAndSession(ctx essh.Context) (authorization.Authorization, session.Session, session.State, error) {
	failf := func(t errors.Type, msg string, args ...any) (authorization.Authorization, session.Session, session.State, error) {
		return nil, nil, 0, errors.Newf(t, msg, args...)
	}

	auth, _ := ctx.Value(authorizationCtxKey).(authorization.Authorization)
	if auth == nil {
		return failf(errors.System, "no authorization resolved, but it should")
	}
	sess := auth.FindSession()
	if sess == nil {
		return failf(errors.System, "authorization resolved, but does not have a valid session")
	}

	var err error
	var oldState session.State
	if oldState, err = sess.NotifyLastAccess(ctx, &remote{ctx}, session.StateAuthorized); err != nil {
		return failf(errors.System, "cannot update session sate: %w", err)
	}
	if oldState == session.StateNew {
		if pub, _ := ctx.Value(handshakeKeyCtxKey).(essh.PublicKey); pub != nil {
			if err := sess.AddPublicKey(ctx, pub); err != nil {
				return failf(errors.System, "cannot add public key to session: %w", err)
			}
		}
	}

	return auth, sess, oldState, nil
}

func (this *service) onPtyRequest(ctx essh.Context, _ essh.Session, pty essh.Pty) (bool, error) {
	auth, ok := ctx.Value(authorizationCtxKey).(authorization.Authorization)
	if !ok {
		return false, errors.Newf(errors.System, "no authorization resolved for PTY request")
	}
	if policy := authorization.AuthorizedKeyPolicyOf(auth); policy != nil && !policy.PtyAllowed {
		return false, nil
	}

	conn := this.connection(ctx)
	if conn == nil {
		return false, errors.Newf(errors.System, "no connection resolved for PTY request")
	}
	logger := conn.Logger()

	ok, err := this.environments.DoesSupportPty(&environmentContext{
		service:       this,
		connection:    conn,
		authorization: auth,
	}, pty)
	if err != nil {
		return false, errors.Newf(errors.System, "cannot evaluate if PTY is allowed for request: %w", err)
	}

	if !ok {
		logger.Debug("PTY was requested but is forbidden")
		return false, nil
	}

	logger.Debug("PTY was requested and was permitted")
	return true, nil
}

func (this *service) onAgentForwardingRequested(ctx essh.Context, _ essh.Session) (bool, error) {
	auth, ok := ctx.Value(authorizationCtxKey).(authorization.Authorization)
	if !ok || auth == nil {
		return false, errors.Newf(errors.System, "no authorization resolved for agent forwarding request")
	}
	return authorization.IsAgentForwardingAllowed(auth), nil
}
