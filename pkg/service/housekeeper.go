package service

import (
	"context"
	goerrors "errors"
	"fmt"
	"sync/atomic"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

type houseKeeper struct {
	service       *service
	closed        atomic.Bool
	contextCancel context.CancelFunc
	done          chan struct{}
	orphanedFlows map[configuration.FlowName]struct{}
}

func (this *houseKeeper) init(service *service) error {
	success := false
	this.service = service
	var ctx context.Context
	ctx, this.contextCancel = context.WithCancel(context.Background())
	defer common.DoIfFalse(&success, this.contextCancel)

	var nextRunIn time.Duration
	if initialDelay := this.service.Configuration.HouseKeeping.InitialDelay; initialDelay.IsZero() {
		var err error
		if nextRunIn, err = this.checkedRun(ctx); err != nil {
			return errors.Newf(errors.System, "initial house keeping run failed: %w", err)
		}
	} else {
		nextRunIn = initialDelay.Native()
	}

	this.done = make(chan struct{})
	go func() {
		defer close(this.done)
		this.loop(ctx, nextRunIn)
	}()

	success = true

	return nil
}

func (this *houseKeeper) loop(ctx context.Context, firstIn time.Duration) {
	t := time.NewTimer(firstIn)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, _ := this.checkedRun(ctx)
			t.Reset(n)
		}
	}
}

func (this *houseKeeper) checkedRun(ctx context.Context) (nextRunIn time.Duration, rErr error) {
	l := this.logger()
	started := time.Now()
	defer func() {
		nextRunIn = this.service.Configuration.HouseKeeping.Every.Native()
		ld := l.
			With("duration", time.Since(started).Truncate(time.Microsecond)).
			With("nextRunIn", nextRunIn)
		if rErr != nil {
			ld.WithError(rErr).Error("housekeeping run failed")
		} else {
			ld.Info("housekeeping run done")
		}
	}()

	defer func() {
		if v := recover(); v != nil {
			if err, ok := v.(error); ok {
				rErr = err
			} else {
				rErr = fmt.Errorf("panic while housekeeping occurred: %v", v)
			}
		}
	}()

	l.Debug("housekeeping run started")

	return 0, this.run(l, ctx)
}

func (this *houseKeeper) run(logger log.Logger, ctx context.Context) error {
	this.orphanedFlows = make(map[configuration.FlowName]struct{})
	defer func() { this.orphanedFlows = nil }()
	inspectionErr := this.inspectSessions(logger, ctx)
	if err := ctx.Err(); err != nil {
		return goerrors.Join(inspectionErr, err)
	}
	result := inspectionErr
	if inspectionErr == nil {
		result = goerrors.Join(result, this.cleanup(logger, ctx))
		if err := ctx.Err(); err != nil {
			return goerrors.Join(result, err)
		}
	}
	recordingErr := this.cleanupRecordings(logger, ctx, time.Now().UTC())
	return goerrors.Join(result, recordingErr)
}

func (this *houseKeeper) cleanupRecordings(logger log.Logger, ctx context.Context, now time.Time) error {
	var result error
	for index := range this.service.Configuration.Auditlogs {
		if err := ctx.Err(); err != nil {
			return goerrors.Join(result, err)
		}
		auditlog := &this.service.Configuration.Auditlogs[index]
		if !auditlog.Enabled || !auditlog.Recording.Enabled || this.service.auditlogDisabled(auditlog.Name) {
			continue
		}
		repository := this.service.recordingRepositories[auditlog.Name]
		if repository == nil {
			failure := errors.System.Newf("no Recording repository configured for auditlog %q", auditlog.Name)
			result = goerrors.Join(result, this.service.handleRecordingFailure(auditlog.Name, "Recording retention", failure))
			continue
		}
		var cutoff time.Time
		if !auditlog.Recording.RetainFor.IsZero() {
			cutoff = now.Add(-auditlog.Recording.RetainFor.Native())
		}
		candidates, err := repository.retentionCandidates(ctx, cutoff)
		if err != nil {
			if ctx.Err() != nil {
				return goerrors.Join(result, ctx.Err())
			}
			failure := errors.System.Newf("cannot inspect Recording retention of auditlog %q: %w", auditlog.Name, err)
			result = goerrors.Join(result, this.service.handleRecordingFailure(auditlog.Name, "Recording retention", failure))
			continue
		}
		for _, candidate := range candidates {
			if err := ctx.Err(); err != nil {
				return goerrors.Join(result, err)
			}
			_, actionErr, auditErr := this.auditRecordingDeletion(ctx, auditlog.Name, candidate, func() (bool, sessionRecordingRetentionCandidate, error) {
				return repository.deleteRetentionCandidate(ctx, candidate, cutoff)
			}, func(completed sessionRecordingRetentionCandidate) error {
				return repository.completeRetentionCandidate(ctx, completed, cutoff)
			})
			if err := goerrors.Join(actionErr, auditErr); err != nil {
				if ctx.Err() != nil {
					return goerrors.Join(result, err, ctx.Err())
				}
				if policyErr := this.service.handleRecordingFailure(auditlog.Name, "Recording retention", err); policyErr != nil {
					logger.WithError(policyErr).With("auditlog", auditlog.Name).With("recordingId", candidate.recordingId).Warn("cannot delete retained session Recording; preserving remaining local state")
				}
				if this.service.auditlogDisabled(auditlog.Name) {
					break
				}
			}
		}
	}
	return result
}

func (this *houseKeeper) auditRecordingDeletion(ctx context.Context, auditlog configuration.AuditlogName, candidate sessionRecordingRetentionCandidate, perform func() (bool, sessionRecordingRetentionCandidate, error), complete func(sessionRecordingRetentionCandidate) error) (changed bool, actionErr, auditErr error) {
	recorder := this.service.auditRecorders[auditlog]
	if recorder == nil {
		return false, nil, errors.System.Newf("no audit recorder configured for auditlog %q", auditlog)
	}
	if candidate.receipt.CompletionPending {
		event := recordingRetentionCompletionEvent(candidate)
		if auditErr = recorder.Record(ctx, event); auditErr == nil {
			if !this.service.auditlogDisabled(auditlog) {
				actionErr = complete(candidate)
			}
		}
		return
	}
	startedAt := time.Now()
	event := audit.Event{
		Name:        audit.EventNameHousekeepingRecordingDeleteStarted,
		Domain:      audit.EventDomainHousekeeping,
		OperationId: candidate.receipt.AuditOperationId,
		RecordingId: candidate.recordingId.String(),
		Reason:      audit.EventReasonRetentionElapsed,
	}
	if err := recorder.Record(ctx, event); err != nil {
		return false, nil, err
	}
	if this.service.auditlogDisabled(auditlog) {
		return false, nil, nil
	}
	var completed sessionRecordingRetentionCandidate
	changed, completed, actionErr = perform()
	event.Name = audit.EventNameHousekeepingRecordingDeleteCompleted
	completionPending := completed.receipt.CompletionPending && completed.receipt.AuditOperationId == candidate.receipt.AuditOperationId
	if completionPending && actionErr != nil {
		// The completion rename is visible but was not durably synced. A later
		// scan resolves whether the old or new marker survived before auditing.
		return
	}
	if completionPending {
		event = recordingRetentionCompletionEvent(completed)
	} else if actionErr != nil {
		event.DurationMillis = common.P(time.Since(startedAt).Milliseconds())
		event.Outcome = audit.EventOutcomeFailure
		event.ErrorCategory = auditErrorCategory(actionErr)
	} else {
		actionErr = errors.System.Newf("Recording retention completion was not persisted")
		event.DurationMillis = common.P(time.Since(startedAt).Milliseconds())
		event.Outcome = audit.EventOutcomeFailure
		event.ErrorCategory = auditErrorCategory(actionErr)
	}
	auditErr = recorder.Record(ctx, event)
	if completionPending && auditErr == nil && !this.service.auditlogDisabled(auditlog) {
		actionErr = goerrors.Join(actionErr, complete(completed))
	}
	return
}

func recordingRetentionCompletionEvent(candidate sessionRecordingRetentionCandidate) audit.Event {
	// The durable completion marker contains no mutable metadata, so retries emit
	// an equivalent event without consuming additional spool quota.
	return audit.Event{
		Name:           audit.EventNameHousekeepingRecordingDeleteCompleted,
		Domain:         audit.EventDomainHousekeeping,
		OperationId:    candidate.receipt.AuditOperationId,
		RecordingId:    candidate.recordingId.String(),
		Reason:         audit.EventReasonRetentionElapsed,
		Outcome:        audit.EventOutcomeSuccess,
		DurationMillis: common.P(int64(0)),
	}
}

func (this *houseKeeper) inspectSessions(logger log.Logger, ctx context.Context) error {
	return this.service.sessions.FindAll(ctx, this.inspectSession, &session.FindOpts{
		AutoCleanUpAllowed: common.P(this.service.Configuration.HouseKeeping.AutoRepair && this.sessionAutoRepairAllowed()),
		AutoCleanUpAllowedFor: func(_ context.Context, flow configuration.FlowName, _ session.Id) bool {
			_, known := this.service.knownFlows[flow]
			return known
		},
		Logger: logger,
		DiagnosticConsumer: func(_ context.Context, diagnostic session.FindDiagnostic) error {
			if _, known := this.service.knownFlows[diagnostic.Flow]; !known {
				this.rememberOrphanedFlow(diagnostic.Flow)
			}
			logger.
				With("flow", diagnostic.Flow).
				With("sessionId", diagnostic.Id).
				With("path", diagnostic.Path).
				WithError(diagnostic.Err).
				Warn("cannot inspect corrupt session entry; preserving it and continuing")
			return nil
		},
	})
}

func (this *houseKeeper) inspectSession(ctx context.Context, sess session.Session) (bool, error) {
	logger := this.logger().With("session", sess)
	started := time.Now()

	reportAndContinue := func(err error) (bool, error) {
		logger.WithError(err).
			With("duration", time.Since(started).Truncate(time.Microsecond)).
			Warn("cannot inspect session; skipping...")
		return true, nil
	}

	logger.Debug("inspecting session...")
	if _, flowExists := this.service.knownFlows[sess.Flow()]; !flowExists {
		this.rememberOrphanedFlow(sess.Flow())
		event := audit.Event{
			Name:      audit.EventNameHousekeepingOrphanedSessionCleanupSkipped,
			Domain:    audit.EventDomainHousekeeping,
			Outcome:   audit.EventOutcomeDenied,
			Flow:      sess.Flow().String(),
			SessionId: sess.Id().String(),
			Reason:    audit.EventReasonMissingFlow,
		}
		logger.Warn("session belongs to a missing flow; preserving it for operator recovery")
		if this.hasEnabledAuditlog() {
			if err := this.recordOrphanedSessionAudit(ctx, event); err != nil {
				return reportAndContinue(err)
			}
		}
		return true, nil
	}

	if shouldBeDeleted, err := session.IsExpiredWithThreshold(this.service.Configuration.HouseKeeping.KeepExpiredFor.Native())(ctx, sess); err != nil {
		return reportAndContinue(err)
	} else if shouldBeDeleted {
		_, disposeErr, disposeAuditErr := this.auditSessionAction(ctx, sess, audit.EventNameHousekeepingSessionDisposeStarted, audit.EventNameHousekeepingSessionDisposeCompleted, audit.EventReasonRetentionElapsed, func() (bool, error) {
			return this.dispose(ctx, logger, sess)
		})
		if err := goerrors.Join(disposeErr, disposeAuditErr); err != nil {
			return reportAndContinue(err)
		}
		_, deleteErr, deleteAuditErr := this.auditSessionAction(ctx, sess, audit.EventNameHousekeepingSessionDeleteStarted, audit.EventNameHousekeepingSessionDeleteCompleted, audit.EventReasonRetentionElapsed, func() (bool, error) {
			return true, this.service.sessions.Delete(ctx, sess)
		})
		if err := goerrors.Join(deleteErr, deleteAuditErr); err != nil {
			return reportAndContinue(err)
		}
		logger.Info("session reached maximum age to be kept after being expired and was therefore deleted")

	} else if expired, err := session.IsExpired(ctx, sess); err != nil {
		return reportAndContinue(err)
	} else if expired {
		disposed, actionErr, auditErr := this.auditSessionAction(ctx, sess, audit.EventNameHousekeepingSessionDisposeStarted, audit.EventNameHousekeepingSessionDisposeCompleted, audit.EventReasonExpired, func() (bool, error) {
			return this.dispose(ctx, logger, sess)
		})
		if err := goerrors.Join(actionErr, auditErr); err != nil {
			return reportAndContinue(err)
		}
		if disposed {
			logger.Info("session is expired and was therefore disposed")
		} else {
			logger.Trace("session is expired and was therefore disposed; but nothing relevant happen while disposing all components")
		}
	}

	if logger.IsDebugEnabled() {
		logger.
			With("duration", time.Since(started).Truncate(time.Microsecond)).
			Debug("inspecting session... DONE!")
	}

	return true, nil
}

func (this *houseKeeper) auditSessionAction(ctx context.Context, sess session.Session, startedEventName, completedEventName audit.EventName, reason audit.EventReason, perform func() (bool, error)) (changed bool, actionErr, auditErr error) {
	record := func(event audit.Event) error {
		return this.service.recordFlowAudit(ctx, sess.Flow(), event)
	}
	operationId, err := uuid.NewRandom()
	if err != nil {
		return false, nil, errors.Newf(errors.System, "cannot generate housekeeping audit operation ID: %w", err)
	}
	startedAt := time.Now()
	event := audit.Event{
		Name:        startedEventName,
		Domain:      audit.EventDomainHousekeeping,
		Flow:        sess.Flow().String(),
		SessionId:   sess.Id().String(),
		OperationId: operationId.String(),
		Reason:      reason,
	}
	if err := record(event); err != nil {
		return false, nil, err
	}

	changed, actionErr = perform()
	event.Name = completedEventName
	event.DurationMillis = common.P(time.Since(startedAt).Milliseconds())
	if actionErr != nil {
		event.Outcome = audit.EventOutcomeFailure
		event.ErrorCategory = auditErrorCategory(actionErr)
	} else {
		event.Outcome = audit.EventOutcomeSuccess
	}
	auditErr = record(event)
	return
}

func (this *houseKeeper) hasEnabledAuditlog() bool {
	for _, auditlog := range this.service.Configuration.Auditlogs {
		if auditlog.Enabled && !this.service.auditlogDisabled(auditlog.Name) {
			return true
		}
	}
	return false
}

func (this *houseKeeper) recordOrphanedSessionAudit(ctx context.Context, event audit.Event) error {
	var result error
	for _, auditlog := range this.service.Configuration.Auditlogs {
		if !auditlog.Enabled || this.service.auditlogDisabled(auditlog.Name) {
			continue
		}
		recorder := this.service.auditRecorders[auditlog.Name]
		if recorder == nil {
			result = goerrors.Join(result, errors.System.Newf("no audit recorder configured for enabled auditlog %q", auditlog.Name))
			continue
		}
		if err := recorder.Record(ctx, event); err != nil {
			result = goerrors.Join(result, errors.System.Newf("cannot record orphaned-session audit event %q to auditlog %q: %w", event.Name, auditlog.Name, err))
		}
	}
	return result
}

func (this *houseKeeper) sessionAutoRepairAllowed() bool {
	for _, auditlog := range this.service.Configuration.Auditlogs {
		if auditlog.Enabled && !this.service.auditlogDisabled(auditlog.Name) {
			return false
		}
	}
	return true
}

// dispose will dispose a given session.Session but NOT delete it.
func (this *houseKeeper) dispose(ctx context.Context, logger log.Logger, sess session.Session) (bool, error) {
	fail := func(err error) (bool, error) {
		return false, errors.Newf(errors.System, "cannot dispose session %v: %w", sess, err)
	}

	sessionDisposed, err := sess.Dispose(ctx)
	if err != nil {
		return fail(err)
	}
	environmentDisposed, err := this.disposeEnvironment(ctx, logger, sess)
	if err != nil {
		return fail(err)
	}
	authorizationDisposed, err := this.disposeAuthorization(ctx, logger, sess)
	if err != nil {
		return fail(err)
	}

	return environmentDisposed || authorizationDisposed || sessionDisposed, nil
}

func (this *houseKeeper) disposeEnvironment(ctx context.Context, logger log.Logger, sess session.Session) (_ bool, rErr error) {
	fail := func(err error) (bool, error) {
		return false, errors.Newf(errors.System, "cannot dispose authorization: %w", err)
	}

	env, err := this.service.environments.FindBySession(ctx, sess, &environment.FindOpts{
		AutoCleanUpAllowed: common.P(true),
		Logger:             logger,
	})
	if errors.Is(err, environment.ErrNoSuchEnvironment) {
		// Ok, treat it as already disposed.
		return false, nil
	}
	if err != nil {
		return fail(err)
	}
	defer common.KeepCloseError(&rErr, env)

	disposed, err := env.Dispose(ctx)
	if err != nil {
		return fail(err)
	}

	return disposed, nil
}
func (this *houseKeeper) disposeAuthorization(ctx context.Context, logger log.Logger, sess session.Session) (bool, error) {
	fail := func(err error) (bool, error) {
		logger.WithError(err).Warn("cannot dispose authorization of session")
		return false, errors.Newf(errors.System, "cannot dispose authorization of session: %w", err)
	}

	auth, err := this.service.authorizer.RestoreFromSession(ctx, sess, &authorization.RestoreOpts{
		AutoCleanUpAllowed: common.P(false),
		Logger:             logger,
	})
	if errors.Is(err, authorization.ErrNoSuchAuthorization) {
		// Ok, treat it as already disposed.
		return false, nil
	}
	if errors.Is(err, authorization.ErrUnusableAuthorizationToken) {
		if err := sess.SetAuthorizationToken(ctx, nil); err != nil {
			return fail(err)
		}
		logger.WithError(err).Info("removed permanently unusable authorization token from session")
		return true, nil
	}
	if err != nil {
		return fail(err)
	}

	disposed, err := auth.Dispose(ctx)
	if err != nil {
		return fail(err)
	}

	return disposed, nil
}

func (this *houseKeeper) cleanup(logger log.Logger, ctx context.Context) error {
	return this.service.environments.Cleanup(ctx, &environment.CleanupOpts{
		FlowOfNamePredicate: this.doesFlowExists,
		SessionExists:       this.doesSessionExist(logger),
		Logger:              logger,
	})
}

func (this *houseKeeper) doesFlowExists(name configuration.FlowName) (bool, error) {
	_, ok := this.service.knownFlows[name]
	if !ok {
		_, ok = this.orphanedFlows[name]
	}
	return ok, nil
}

func (this *houseKeeper) rememberOrphanedFlow(flow configuration.FlowName) {
	if this.orphanedFlows == nil {
		this.orphanedFlows = make(map[configuration.FlowName]struct{})
	}
	this.orphanedFlows[flow] = struct{}{}
}

func (this *houseKeeper) doesSessionExist(logger log.Logger) func(ctx context.Context, flow configuration.FlowName, sessionId session.Id) (bool, error) {
	return func(ctx context.Context, flow configuration.FlowName, sessionId session.Id) (bool, error) {
		_, err := this.service.sessions.FindBy(ctx, flow, sessionId, &session.FindOpts{
			AutoCleanUpAllowed: common.P(this.service.Configuration.HouseKeeping.AutoRepair && this.sessionAutoRepairAllowed()),
			Logger:             logger,
		})
		if errors.Is(err, session.ErrNoSuchSession) {
			return false, nil
		} else if err != nil {
			return false, err
		}
		return true, nil
	}
}

func (this *houseKeeper) Close() error {
	if !this.closed.CompareAndSwap(false, true) {
		return nil
	}
	if this.contextCancel != nil {
		this.contextCancel()
	}
	if this.done != nil {
		<-this.done
	}
	return nil
}

func (this *houseKeeper) logger() log.Logger {
	if v := this.service.Logger; v != nil {
		return v
	}
	return log.GetLogger("housekeeping")
}
