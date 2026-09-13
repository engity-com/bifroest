package service

import (
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"math"
	"syscall"
	"time"

	essh "github.com/engity-com/ssh-server-go"
	"github.com/google/uuid"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
)

type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

func (this localForwardChannelData) dest() (net.HostPort, error) {
	var buf net.HostPort
	if err := buf.Host.Set(this.DestAddr); err != nil {
		return net.HostPort{}, err
	}
	if this.DestPort > math.MaxUint16 {
		return net.HostPort{}, fmt.Errorf("port out of range: %d", this.DestPort)
	}
	buf.Port = uint16(this.DestPort)
	return buf, nil
}

func (this *service) handleNewDirectTcpIp(_ *essh.Server, _ *gossh.ServerConn, newChan gossh.NewChannel, ctx essh.Context) error {
	conn := this.connection(ctx)
	if conn == nil {
		return nil
	}
	l := conn.logger

	auth, _, _, err := this.resolveAuthorizationAndSession(ctx)
	if err != nil {
		l.WithError(err).
			Error("cannot resolve active authorization and its session; rejecting...")
		if rejectErr := newChan.Reject(gossh.ConnectionFailed, "cannot resolve authorization and its session"); rejectErr != nil {
			return rejectErr
		}
		return err
	}
	operationId, err := uuid.NewRandom()
	if err != nil {
		return errors.Newf(errors.System, "cannot generate port forwarding audit operation ID: %w", err)
	}
	recordDecision := func(outcome audit.EventOutcome, reason string, decisionErr error) error {
		event := this.authorizationAuditEvent(ctx, auth, "port-forwarding.direct.decided", audit.EventDomainPortForwarding)
		event.OperationId = operationId.String()
		event.Outcome = outcome
		event.Reason = reason
		if decisionErr != nil {
			event.ErrorCategory = auditErrorCategory(decisionErr)
		}
		return this.recordFlowAudit(ctx, auth.Flow(), event)
	}
	recordOpenFailure := func(outcome audit.EventOutcome, reason string, openErr error) error {
		event := this.authorizationAuditEvent(ctx, auth, "port-forwarding.direct.open-failed", audit.EventDomainPortForwarding)
		event.OperationId = operationId.String()
		event.Outcome = outcome
		event.Reason = reason
		if openErr != nil {
			event.ErrorCategory = auditErrorCategory(openErr)
		}
		return this.recordFlowAudit(ctx, auth.Flow(), event)
	}

	d := localForwardChannelData{}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		l.WithError(err).
			Info("cannot parse client's forward data; rejecting...")
		rejectErr := newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return goerrors.Join(rejectErr, recordDecision(audit.EventOutcomeFailure, "invalid-request", err))
	}
	dest, err := d.dest()
	if err != nil {
		l.WithError(err).
			Info("cannot parse client's forward data; rejecting...")
		rejectErr := newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return goerrors.Join(rejectErr, recordDecision(audit.EventOutcomeFailure, "invalid-request", err))
	}
	if policy := authorization.AuthorizedKeyPolicyOf(auth); policy != nil && !policy.AllowsOpen(dest) {
		l.Info("port forwarding requested by client was rejected by authorized key policy")
		rejectErr := newChan.Reject(gossh.Prohibited, "port forwarding is disabled by authorized key policy")
		return goerrors.Join(rejectErr, recordDecision(audit.EventOutcomeDenied, "authorized-key-policy", nil))
	}

	l = l.With("dest", dest)

	req := environmentRequest{
		environmentContext{
			service:       this,
			connection:    conn,
			authorization: auth,
		},
		nil,
	}

	env, err := this.environments.Ensure(&req)
	if err != nil {
		l.WithError(err).
			Error("cannot ensure environment; rejecting...")
		rejectErr := newChan.Reject(gossh.Prohibited, "cannot ensure environment")
		return goerrors.Join(err, rejectErr, recordDecision(audit.EventOutcomeFailure, "environment", err))
	}
	defer common.IgnoreCloseError(env)

	if ok, err := env.IsPortForwardingAllowed(dest); err != nil {
		l.WithError(err).
			Error("cannot check if port forwarding is allowed; rejecting...")
		rejectErr := newChan.Reject(gossh.ConnectionFailed, "port forwarding is disabled")
		return goerrors.Join(err, rejectErr, recordDecision(audit.EventOutcomeFailure, "environment-policy", err))
	} else if !ok {
		l.Info("port forwarding requested by client was rejected")
		rejectErr := newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return goerrors.Join(rejectErr, recordDecision(audit.EventOutcomeDenied, "environment-policy", nil))
	}
	if err := recordDecision(audit.EventOutcomeSuccess, "", nil); err != nil {
		_ = newChan.Reject(gossh.ConnectionFailed, "cannot record port forwarding decision")
		return err
	}

	dConn, err := env.NewDestinationConnection(ctx, dest)
	if err != nil {
		var re errors.RemoteError
		if errors.As(err, &re) {
			l.WithError(err).
				Info("cannot connect to port forwarding destination; rejecting...")
			_ = newChan.Reject(gossh.ConnectionFailed, fmt.Sprintf("cannot connect to %v: %v", dest, re))
		} else if ufe := this.reWrapUserFacingErrors(err); ufe != nil {
			l.WithError(ufe).
				Info("cannot connect to port forwarding destination; rejecting...")
			_ = newChan.Reject(gossh.ConnectionFailed, fmt.Sprintf("cannot connect to %v: %v", dest, ufe))
		} else {
			l.WithError(err).
				Warn("cannot connect to port forwarding destination; rejecting...")
			_ = newChan.Reject(gossh.ConnectionFailed, fmt.Sprintf("cannot connect to %v: internal error", dest))
		}
		return recordOpenFailure(audit.EventOutcomeFailure, "destination-connect", err)
	}
	if dConn == nil {
		l.Info("connection rejected")
		_ = newChan.Reject(gossh.ConnectionFailed, "rejected")
		return recordOpenFailure(audit.EventOutcomeDenied, "destination-rejected", nil)
	}
	defer common.IgnoreCloseError(dConn)

	sConn, reqs, err := newChan.Accept()
	if err != nil {
		return goerrors.Join(err, recordOpenFailure(audit.EventOutcomeFailure, "channel-accept", err))
	}
	defer common.IgnoreCloseError(sConn)
	startedEvent := this.authorizationAuditEvent(ctx, auth, "port-forwarding.direct.started", audit.EventDomainPortForwarding)
	startedEvent.OperationId = operationId.String()
	if err := this.recordFlowAudit(ctx, auth.Flow(), startedEvent); err != nil {
		return err
	}

	nameOf := func(isL2r bool) string {
		if isL2r {
			return "source -> destination"
		}
		return "destination -> source"
	}

	type forwardingCompletion struct {
		s2d      int64
		d2s      int64
		duration time.Duration
		err      error
	}
	completed := make(chan forwardingCompletion, 1)
	copyErr := copyForwardedConnection(ctx, reqs, sConn, dConn, &essh.FullDuplexCopyOpts{
		OnStart: func() {
			l.Debug("port forwarding started")
		},
		OnEnd: func(s2d, d2s int64, duration time.Duration, err error, wasInL2r *bool) {
			ld := l.
				With("s2d", s2d).
				With("d2s", d2s).
				With("duration", duration)
			if wasInL2r != nil {
				ld = ld.With("direction", nameOf(*wasInL2r))
			}

			if err != nil {
				ld.WithError(err).Error("cannot successful handle port forwarding request; canceling...")
			} else {
				ld.Info("port forwarding finished")
			}
			completed <- forwardingCompletion{s2d: s2d, d2s: d2s, duration: duration, err: err}
		},
		OnStreamEnd: func(isL2r bool, err error) {
			l.WithError(err).Tracef("copying of %s done", nameOf(isL2r))
		},
	})
	completion := <-completed
	streamErr := goerrors.Join(copyErr, completion.err)
	event := this.authorizationAuditEvent(ctx, auth, "port-forwarding.direct.completed", audit.EventDomainPortForwarding)
	event.OperationId = operationId.String()
	event.BytesRead = common.P(completion.s2d)
	event.BytesWritten = common.P(completion.d2s)
	event.DurationMillis = common.P(completion.duration.Milliseconds())
	switch {
	case errors.Is(ctx.Err(), context.Canceled), errors.Is(streamErr, context.Canceled):
		event.Outcome = audit.EventOutcomeCanceled
		event.Reason = "context-canceled"
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(streamErr, context.DeadlineExceeded):
		event.Outcome = audit.EventOutcomeCanceled
		event.Reason = "deadline-exceeded"
	case streamErr != nil:
		event.Outcome = audit.EventOutcomeFailure
		event.ErrorCategory = auditErrorCategory(streamErr)
	default:
		event.Outcome = audit.EventOutcomeSuccess
	}
	auditErr := this.recordFlowAudit(ctx, auth.Flow(), event)
	return goerrors.Join(copyErr, auditErr)
}

func copyForwardedConnection(ctx context.Context, requests <-chan *gossh.Request, source, destination io.ReadWriteCloser, opts *essh.FullDuplexCopyOpts) error {
	copyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		gossh.DiscardRequests(requests)
		cancel()
	}()
	return essh.FullDuplexCopy(copyCtx, source, destination, opts)
}

func (this *service) onReversePortForwardingRequested(ctx essh.Context, _ gossh.ConnMetadata, host string, port uint32) (bool, error) {
	auth, ok := ctx.Value(authorizationCtxKey).(authorization.Authorization)
	if !ok || auth == nil {
		return false, errors.Newf(errors.System, "no authorization resolved for reverse port forwarding request")
	}
	operationId, err := uuid.NewRandom()
	if err != nil {
		return false, errors.Newf(errors.System, "cannot generate reverse port forwarding audit operation ID: %w", err)
	}
	recordDecision := func(allowed bool, outcome audit.EventOutcome, reason string, decisionErr error) (bool, error) {
		event := this.authorizationAuditEvent(ctx, auth, "port-forwarding.reverse.decided", audit.EventDomainPortForwarding)
		event.OperationId = operationId.String()
		event.Outcome = outcome
		event.Reason = reason
		if decisionErr != nil {
			event.ErrorCategory = auditErrorCategory(decisionErr)
		}
		if recordErr := this.recordFlowAudit(ctx, auth.Flow(), event); recordErr != nil {
			return false, recordErr
		}
		return allowed, decisionErr
	}
	policy := authorization.AuthorizedKeyPolicyOf(auth)
	if policy != nil && !policy.AllowsListen(host, port) {
		return recordDecision(false, audit.EventOutcomeDenied, "authorized-key-policy", nil)
	}
	if port > math.MaxUint16 {
		return recordDecision(false, audit.EventOutcomeDenied, "invalid-bind", nil)
	}
	var bind net.HostPort
	if err := bind.Host.Set(host); err != nil {
		return recordDecision(false, audit.EventOutcomeDenied, "invalid-bind", nil)
	}
	bind.Port = uint16(port)
	conn := this.connection(ctx)
	if conn == nil {
		return false, errors.Newf(errors.System, "no connection resolved for reverse port forwarding request")
	}
	req := environmentRequest{environmentContext{service: this, connection: conn, authorization: auth}, nil}
	env, err := this.environments.Ensure(&req)
	if err != nil {
		wrapped := errors.Newf(errors.System, "cannot ensure environment for reverse port forwarding: %w", err)
		return recordDecision(false, audit.EventOutcomeFailure, "environment", wrapped)
	}
	defer common.IgnoreCloseError(env)
	var allowed bool
	if policy, ok := env.(environment.ReversePortForwardingPolicy); ok {
		allowed, err = policy.IsReversePortForwardingAllowed(bind)
	} else {
		allowed, err = env.IsPortForwardingAllowed(bind)
	}
	if err != nil {
		wrapped := errors.Newf(errors.System, "cannot check if reverse port forwarding is allowed: %w", err)
		return recordDecision(false, audit.EventOutcomeFailure, "environment-policy", wrapped)
	}
	if !allowed {
		return recordDecision(false, audit.EventOutcomeDenied, "environment-policy", nil)
	}
	return recordDecision(true, audit.EventOutcomeSuccess, "", nil)
}

func (this *service) reWrapUserFacingErrors(err error) *errors.Error {
	if err == nil {
		return nil
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return &errors.Error{
			Message:    io.EOF.Error(),
			Cause:      err,
			Type:       errors.Network,
			UserFacing: true,
		}
	}

	var sce syscall.Errno
	if errors.As(err, &sce) {
		switch sce {
		case syscall.ECONNREFUSED, syscall.ETIMEDOUT, syscall.EHOSTDOWN, syscall.ENETUNREACH:
			return &errors.Error{
				Message:    sce.Error(),
				Cause:      sce,
				Type:       errors.Network,
				UserFacing: true,
			}
		default:
			return nil
		}
	}

	return nil
}
