package service

import (
	"github.com/gliderlabs/ssh"
	gssh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

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

	if _, ok := ctx.Value(handshakeKeyCtxKey).(ssh.PublicKey); !ok {
		ctx.SetValue(handshakeKeyCtxKey, key)
	}

	authReq := authorizeRequest{
		service: this,
		remote:  remote{ctx},
	}

	auth, err := this.authorizer.AuthorizePublicKey(&publicKeyAuthorizeRequest{authReq, key})
	if err != nil {
		if errors.IsType(err, errors.User) {
			l.WithError(err).Debug("public key failed by user")
			return false
		}
		if !this.isSilentError(err) {
			l.WithError(err).Warn("was not able to resolve public key authorization request; treat as rejected")
		}
		return false
	}

	if auth == nil || !auth.IsAuthorized() {
		l.Debug("public key rejected")
		return false
	}

	ctx.SetValue(authorizationCtxKey, auth)
	// We've authorized via the regular public key we do not store them.
	ctx.SetValue(handshakeKeyCtxKey, nil)

	l.Debug("public key accepted")
	return true
}

func (this *service) handlePassword(ctx ssh.Context, password string) bool {
	l := this.logger(ctx)

	auth, err := this.authorizer.AuthorizePassword(&passwordAuthorizeRequest{
		authorizeRequest: authorizeRequest{
			service: this,
			remote:  remote{ctx},
		},
		password: password,
	})
	if err != nil {
		if errors.IsType(err, errors.User) {
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

	auth, err := this.authorizer.AuthorizeInteractive(&interactiveAuthorizeRequest{
		authorizeRequest: authorizeRequest{
			service: this,
			remote:  remote{ctx},
		},
		challenger: challenger,
	})
	if err != nil {
		if errors.IsType(err, errors.User) {
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

func (this *service) resolveAuthorizationAndSession(sshSess ssh.Session) (authorization.Authorization, session.Session, session.State, error) {
	failf := func(t errors.Type, msg string, args ...any) (authorization.Authorization, session.Session, session.State, error) {
		return nil, nil, 0, errors.Newf(t, msg, args...)
	}

	ctx := sshSess.Context()
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
	if oldState, err = sess.NotifyLastAccess(sshSess.Context(), &remote{ctx}, session.StateAuthorized); err != nil {
		return failf(errors.System, "cannot update session sate: %w", err)
	}
	if oldState == session.StateNew {
		if pub, _ := ctx.Value(handshakeKeyCtxKey).(ssh.PublicKey); pub != nil {
			if err := sess.AddPublicKey(sshSess.Context(), pub); err != nil {
				return failf(errors.System, "cannot add public key to session: %w", err)
			}
		}
	}
	return auth, sess, oldState, nil
}

func (this *service) onPtyRequest(ctx ssh.Context, pty ssh.Pty) bool {
	auth, ok := ctx.Value(authorizationCtxKey).(authorization.Authorization)
	if !ok {
		return false
	}

	logger := this.logger(ctx)

	ok, err := this.environments.DoesSupportPty(&environmentRequest{
		this,
		&remote{ctx},
		auth,
	}, pty)
	if this.isRelevantError(err) {
		logger.WithError(err).Warn("cannot evaluate if PTY is allowed or not for request")
		return false
	}

	if !ok {
		logger.Debug("PTY was requested but is forbidden")
	}

	logger.Debug("PTY was requested and was permitted")
	return true
}
