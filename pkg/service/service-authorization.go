package service

import (
	"context"

	essh "github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

func (this *service) handlePublicKey(ctx essh.Context, _ gossh.ConnMetadata, key essh.PublicKey) (bool, error) {
	return this.authorizePublicKey(ctx, key, false)
}

func (this *service) authorizePublicKey(ctx essh.Context, key essh.PublicKey, verified bool) (bool, error) {
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

	if _, isCertificate := key.(*gossh.Certificate); !isCertificate {
		if _, ok := ctx.Value(handshakeKeyCtxKey).(essh.PublicKey); !ok {
			ctx.SetValue(handshakeKeyCtxKey, key)
		}
	}

	authReq := authorizeRequest{
		service:    this,
		connection: conn,
	}

	auth, err := this.authorizer.AuthorizePublicKey(&publicKeyAuthorizeRequest{authReq, key, verified})
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
		if err := this.recordAuthenticationCompleted(ctx, auth, audit.AuthenticationMethodPublicKey, audit.EventOutcomeDenied, audit.EventReasonSessionIncompatible); err != nil {
			return false, err
		}
		l.Debug("public key session is incompatible with the current environment")
		return false, nil
	}

	ctx.SetValue(authorizationCtxKey, auth)
	// We've authorized via the regular public key we do not store them.
	ctx.SetValue(handshakeKeyCtxKey, nil)

	l.Debug("public key accepted")
	return true, nil
}

func (this *service) verifiedPublicKeyAuditCallback(ctx essh.Context) func(gossh.ConnMetadata, gossh.PublicKey, *gossh.Permissions, string) (*gossh.Permissions, error) {
	return func(_ gossh.ConnMetadata, key gossh.PublicKey, permissions *gossh.Permissions, _ string) (*gossh.Permissions, error) {
		if _, isCertificate := key.(*gossh.Certificate); isCertificate {
			accepted, err := this.authorizePublicKey(ctx, key, true)
			if err != nil {
				return nil, err
			}
			if !accepted {
				return nil, errors.User.Newf("user certificate rejected after public key verification")
			}
		}
		auth, _ := ctx.Value(authorizationCtxKey).(authorization.Authorization)
		if auth == nil {
			return nil, errors.System.Newf("no authorization resolved after public key verification")
		}
		if err := this.recordAuthenticationCompleted(ctx, auth, audit.AuthenticationMethodPublicKey, audit.EventOutcomeSuccess, ""); err != nil {
			return nil, err
		}
		return permissions, nil
	}
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
		if err := this.recordAuthenticationCompleted(ctx, auth, audit.AuthenticationMethodPassword, audit.EventOutcomeDenied, audit.EventReasonSessionIncompatible); err != nil {
			return false, err
		}
		l.Debug("password session is incompatible with the current environment")
		return false, nil
	}

	if err := this.recordAuthenticationCompleted(ctx, auth, audit.AuthenticationMethodPassword, audit.EventOutcomeSuccess, ""); err != nil {
		return false, err
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
		if err := this.recordAuthenticationCompleted(ctx, auth, audit.AuthenticationMethodKeyboardInteractive, audit.EventOutcomeDenied, audit.EventReasonSessionIncompatible); err != nil {
			return false, err
		}
		l.Debug("interactive session is incompatible with the current environment")
		return false, nil
	}

	if err := this.recordAuthenticationCompleted(ctx, auth, audit.AuthenticationMethodKeyboardInteractive, audit.EventOutcomeSuccess, ""); err != nil {
		return false, err
	}
	ctx.SetValue(authorizationCtxKey, auth)

	l.Debug("interactive accepted")
	return true, nil
}

func (this *service) observeFlowAuthorization(ctx context.Context, observation authorization.FlowAuthorizationObservation) error {
	outcome := audit.EventOutcomeFailure
	if observation.Outcome == authorization.FlowAuthorizationOutcomeAccepted {
		outcome = audit.EventOutcomeSuccess
	} else if observation.Outcome == authorization.FlowAuthorizationOutcomeDenied || errors.IsType(observation.Err, errors.User) {
		outcome = audit.EventOutcomeDenied
	}
	event := audit.Event{
		Name:                 audit.EventNameAuthenticationFlowEvaluated,
		Domain:               audit.EventDomainAuthentication,
		Outcome:              outcome,
		Flow:                 observation.Flow.String(),
		ConnectionId:         observation.ConnectionId,
		SessionId:            observation.SessionId,
		AuthenticationMethod: audit.AuthenticationMethod(observation.Method),
		AuthenticationPhase:  audit.AuthenticationPhase(observation.Phase),
		AuthorizationKind:    observation.AuthorizationKind,
	}
	if observation.Err != nil {
		event.ErrorCategory = auditErrorCategory(observation.Err)
	}
	if flowAuthorizationObservationIsUnauthenticated(observation) {
		return this.recordUnauthenticatedFlowAudit(ctx, observation.Flow, event)
	}
	return this.recordFlowAudit(ctx, observation.Flow, event)
}

func flowAuthorizationObservationIsUnauthenticated(observation authorization.FlowAuthorizationObservation) bool {
	if observation.Method == authorization.FlowAuthorizationMethodPublicKey {
		return observation.Phase != authorization.FlowAuthorizationPhaseVerified
	}
	return observation.Outcome != authorization.FlowAuthorizationOutcomeAccepted
}

func (this *service) recordAuthenticationCompleted(ctx essh.Context, auth authorization.Authorization, method audit.AuthenticationMethod, outcome audit.EventOutcome, reason audit.EventReason) error {
	event := audit.Event{
		Name:                 audit.EventNameAuthenticationCompleted,
		Domain:               audit.EventDomainAuthentication,
		Outcome:              outcome,
		Flow:                 auth.Flow().String(),
		AuthenticationMethod: method,
		AuthorizationKind:    authorization.KindOf(auth),
		Reason:               reason,
	}
	if conn := this.connection(ctx); conn != nil {
		event.ConnectionId = conn.Id().String()
	}
	if sess := auth.FindSession(); sess != nil {
		event.SessionId = sess.Id().String()
	}
	return this.recordFlowAudit(ctx, auth.Flow(), event)
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
	if !ok || auth == nil {
		return false, errors.Newf(errors.System, "no authorization resolved for PTY request")
	}
	if policy := authorization.AuthorizedKeyPolicyOf(auth); policy != nil && !policy.PtyAllowed {
		event := this.authorizationAuditEvent(ctx, auth, audit.EventNameSessionPtyDecided, audit.EventDomainSession)
		event.Outcome = audit.EventOutcomeDenied
		event.Reason = audit.EventReasonAuthorizedKeyPolicy
		if err := this.recordFlowAudit(ctx, auth.Flow(), event); err != nil {
			return false, err
		}
		return false, nil
	}

	conn := this.connection(ctx)
	if conn == nil {
		return false, errors.Newf(errors.System, "no connection resolved for PTY request")
	}
	logger := conn.Logger()
	if err := this.validateSessionRecordingPty(auth.Flow(), pty); err != nil {
		event := this.authorizationAuditEvent(ctx, auth, audit.EventNameSessionPtyDecided, audit.EventDomainSession)
		event.Outcome = audit.EventOutcomeDenied
		event.Reason = audit.EventReasonInvalidRequest
		if recordErr := this.recordFlowAudit(ctx, auth.Flow(), event); recordErr != nil {
			return false, recordErr
		}
		logger.Debug("PTY request is not recordable")
		return false, nil
	}

	ok, err := this.environments.DoesSupportPty(&environmentContext{
		service:       this,
		connection:    conn,
		authorization: auth,
	}, pty)
	if err != nil {
		event := this.authorizationAuditEvent(ctx, auth, audit.EventNameSessionPtyDecided, audit.EventDomainSession)
		event.Outcome = audit.EventOutcomeFailure
		event.Reason = audit.EventReasonEnvironmentPolicy
		event.ErrorCategory = auditErrorCategory(err)
		if recordErr := this.recordFlowAudit(ctx, auth.Flow(), event); recordErr != nil {
			return false, recordErr
		}
		return false, errors.Newf(errors.System, "cannot evaluate if PTY is allowed for request: %w", err)
	}

	if !ok {
		event := this.authorizationAuditEvent(ctx, auth, audit.EventNameSessionPtyDecided, audit.EventDomainSession)
		event.Outcome = audit.EventOutcomeDenied
		event.Reason = audit.EventReasonEnvironmentPolicy
		if err := this.recordFlowAudit(ctx, auth.Flow(), event); err != nil {
			return false, err
		}
		logger.Debug("PTY was requested but is forbidden")
		return false, nil
	}

	event := this.authorizationAuditEvent(ctx, auth, audit.EventNameSessionPtyDecided, audit.EventDomainSession)
	event.Outcome = audit.EventOutcomeSuccess
	if err := this.recordFlowAudit(ctx, auth.Flow(), event); err != nil {
		return false, err
	}
	logger.Debug("PTY was requested and was permitted")
	return true, nil
}

func (this *service) validateSessionRecordingPty(flow configuration.FlowName, pty essh.Pty) error {
	auditlog, ok := this.flowAuditlogs[flow]
	if !ok || this.auditlogDisabled(auditlog) || this.recordingRepositories[auditlog] == nil {
		return nil
	}
	_, err := sessionRecordingTerminal(recordedSessionPty{pty: pty, hasPty: true})
	return err
}

func (this *service) onAgentForwardingRequested(ctx essh.Context, sess essh.Session) (bool, error) {
	auth, ok := ctx.Value(authorizationCtxKey).(authorization.Authorization)
	if !ok || auth == nil {
		return false, errors.Newf(errors.System, "no authorization resolved for agent forwarding request")
	}
	late := sess.Subsystem() != ""
	if request, ok := ctx.Value(sshSessionRequestContextKey{}).(*sshSessionRequest); ok && request.kind.Load() != uint32(sshSessionRequestUnknown) {
		late = true
	}
	allowed := !late && authorization.IsAgentForwardingAllowed(auth)
	event := this.authorizationAuditEvent(ctx, auth, audit.EventNameSessionAgentForwardingDecided, audit.EventDomainSession)
	if allowed {
		event.Outcome = audit.EventOutcomeSuccess
	} else {
		event.Outcome = audit.EventOutcomeDenied
		if late {
			event.Reason = audit.EventReasonInvalidRequest
		} else {
			event.Reason = audit.EventReasonAuthorizedKeyPolicy
		}
	}
	if err := this.recordFlowAudit(ctx, auth.Flow(), event); err != nil {
		return false, err
	}
	return allowed, nil
}
