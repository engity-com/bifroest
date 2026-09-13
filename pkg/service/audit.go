package service

import (
	"context"

	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

func (this *service) recordFlowAudit(ctx context.Context, flow configuration.FlowName, event audit.Event) error {
	fail := func(err error) error {
		if sshContext, ok := ctx.(essh.Context); ok {
			if conn := this.connection(sshContext); conn != nil {
				_ = conn.Close()
			}
		}
		return err
	}
	recorder := this.flowAuditRecorders[flow]
	if recorder == nil {
		return fail(errors.System.Newf("no audit recorder configured for flow %q", flow))
	}
	if err := recorder.Record(ctx, event); err != nil {
		return fail(errors.System.Newf("cannot record audit event %q for flow %q: %w", event.Name, flow, err))
	}
	return nil
}

func (this *service) recordUnauthenticatedFlowAudit(ctx context.Context, flow configuration.FlowName, event audit.Event) error {
	fail := func(err error) error {
		if sshContext, ok := ctx.(essh.Context); ok {
			if conn := this.connection(sshContext); conn != nil {
				_ = conn.Close()
			}
		}
		return err
	}
	recorder := this.flowAuditRecorders[flow]
	if recorder == nil {
		return fail(errors.System.Newf("no audit recorder configured for flow %q", flow))
	}
	auditlog, ok := this.flowAuditlogs[flow]
	if !ok {
		return fail(errors.System.Newf("no auditlog configured for flow %q", flow))
	}
	if err := this.unauthenticatedAudit.Record(ctx, auditlog, this.enabledAuditlogs[auditlog], recorder, event); err != nil {
		return fail(errors.System.Newf("cannot record unauthenticated audit event %q for flow %q: %w", event.Name, flow, err))
	}
	return nil
}

func (this *service) authorizationAuditEvent(ctx essh.Context, auth authorization.Authorization, name audit.EventName, domain audit.EventDomain) audit.Event {
	event := audit.Event{
		Name:              name,
		Domain:            domain,
		Flow:              auth.Flow().String(),
		AuthorizationKind: authorization.KindOf(auth),
	}
	if conn := this.connection(ctx); conn != nil {
		event.ConnectionId = conn.Id().String()
	}
	if sess := auth.FindSession(); sess != nil {
		event.SessionId = sess.Id().String()
	}
	return event
}

func auditErrorCategory(err error) audit.ErrorCategory {
	switch {
	case errors.IsType(err, errors.System):
		return audit.ErrorCategorySystem
	case errors.IsType(err, errors.Config):
		return audit.ErrorCategoryConfig
	case errors.IsType(err, errors.Network):
		return audit.ErrorCategoryNetwork
	case errors.IsType(err, errors.User):
		return audit.ErrorCategoryUser
	case errors.IsType(err, errors.Permission):
		return audit.ErrorCategoryPermission
	case errors.IsType(err, errors.Expired):
		return audit.ErrorCategoryExpired
	default:
		return audit.ErrorCategoryUnknown
	}
}
