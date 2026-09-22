package service

import (
	"context"
	"sync"

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
	auditlog, configured := this.flowAuditlogs[flow]
	if configured && this.auditlogDisabled(auditlog) {
		return nil
	}
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
	if this.auditlogDisabled(auditlog) {
		return nil
	}
	if err := this.unauthenticatedAudit.Record(ctx, auditlog, this.enabledAuditlogs[auditlog], recorder, event); err != nil {
		return fail(errors.System.Newf("cannot record unauthenticated audit event %q for flow %q: %w", event.Name, flow, err))
	}
	return nil
}

func (this *service) auditlogDisabled(name configuration.AuditlogName) bool {
	state := this.auditlogStates[name]
	return state != nil && state.disabled.Load()
}

func (this *service) handleAuditlogFailure(name configuration.AuditlogName, component string, err error) error {
	if err == nil {
		return nil
	}
	state := this.auditlogStates[name]
	if state == nil || state.policy == configuration.AuditlogFailurePolicyStrict {
		return err
	}
	state.disabled.Store(true)
	state.logOnce.Do(func() {
		this.logger().
			With("auditlog", name).
			With("component", component).
			WithError(err).
			Error("auditlog failed and was disabled by best-effort failure policy")
	})
	return nil
}

func (this *service) handleRecordingFailure(name configuration.AuditlogName, component string, err error) error {
	result := this.handleAuditlogFailure(name, component, err)
	if err != nil && result == nil {
		if state := this.auditlogStates[name]; state != nil {
			state.recordingFailed.Store(true)
		}
	}
	return result
}

type failurePolicyAuditRecorder struct {
	service  *service
	auditlog configuration.AuditlogName
	delegate audit.Recorder
	mutex    sync.Mutex
	failed   bool
}

func (this *failurePolicyAuditRecorder) Record(ctx context.Context, event audit.Event) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.service.auditlogDisabled(this.auditlog) {
		return nil
	}
	return this.handleFailure(this.delegate.Record(ctx, event))
}

func (this *failurePolicyAuditRecorder) RecordSuppressible(ctx context.Context, event audit.Event) (bool, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.service.auditlogDisabled(this.auditlog) {
		return true, nil
	}
	if recorder, ok := this.delegate.(audit.SuppressibleRecorder); ok {
		recorded, err := recorder.RecordSuppressible(ctx, event)
		return recorded, this.handleFailure(err)
	}
	err := this.handleFailure(this.delegate.Record(ctx, event))
	return err == nil, err
}

func (this *failurePolicyAuditRecorder) Seal() error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.service.auditlogDisabled(this.auditlog) {
		return nil
	}
	if recorder, ok := this.delegate.(audit.SealableRecorder); ok {
		return this.handleFailure(recorder.Seal())
	}
	return nil
}

func (this *failurePolicyAuditRecorder) Close() error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.failed {
		if closer, ok := this.delegate.(interface{ CloseAfterAcceptedFailure() error }); ok {
			return closer.CloseAfterAcceptedFailure()
		}
	}
	return this.delegate.Close()
}

func (this *failurePolicyAuditRecorder) handleFailure(err error) error {
	result := this.service.handleAuditlogFailure(this.auditlog, "journal", err)
	if err != nil && result == nil {
		this.failed = true
	}
	return result
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

type sessionRecordingDeliveryAuditor struct {
	service    *service
	auditlog   configuration.AuditlogName
	repository *sessionRecordingRepository
}

func (this *sessionRecordingDeliveryAuditor) RecordRemoteArtifactDelivery(ctx context.Context, transition audit.RemoteArtifactDeliveryAuditEvent) error {
	if this == nil || this.service == nil || this.repository == nil {
		return errors.System.Newf("nil session Recording delivery auditor")
	}
	if transition.Scope.Auditlog != this.auditlog {
		return errors.Config.Newf("Recording delivery target %q belongs to auditlog %q instead of %q", transition.Scope.Target, transition.Scope.Auditlog, this.auditlog)
	}
	recordingId, err := this.repository.recordingIdFromArtifactName(transition.FileName)
	if err != nil {
		return err
	}
	event := audit.Event{
		Domain:      audit.EventDomainSession,
		OperationId: transition.OperationId,
		RecordingId: recordingId.String(),
		Target:      transition.Scope.Target,
	}
	switch transition.State {
	case audit.RemoteArtifactDeliveryAuditFailed:
		event.Name = audit.EventNameSessionRecordingDeliveryFailed
		event.Outcome = audit.EventOutcomeFailure
		event.ErrorCategory = transition.ErrorCategory
	case audit.RemoteArtifactDeliveryAuditSucceeded:
		event.Name = audit.EventNameSessionRecordingDeliverySucceeded
		event.Outcome = audit.EventOutcomeSuccess
	default:
		return errors.Config.Newf("unknown session Recording delivery audit state %q", transition.State)
	}
	recorder := this.service.auditRecorders[this.auditlog]
	if recorder == nil {
		return errors.System.Newf("no audit recorder configured for Recording delivery of auditlog %q", this.auditlog)
	}
	if err := recorder.Record(ctx, event); err != nil {
		return errors.System.Newf("cannot record Recording delivery audit event %q for auditlog %q: %w", event.Name, this.auditlog, err)
	}
	if this.service.auditlogDisabled(this.auditlog) {
		return errors.System.Newf("auditlog %q was disabled before the Recording delivery audit event was committed", this.auditlog)
	}
	return nil
}
