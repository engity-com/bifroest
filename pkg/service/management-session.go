package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/session"
)

// Bound to the authorized invocation, not to the shared application schema.
type managementSessionControl struct {
	service *service
	task    environment.TaskContext
}

func (this managementSessionControl) Disconnect(ctx context.Context, id session.Id) (model.SessionActionResult, error) {
	return this.perform(ctx, id, false)
}

func (this managementSessionControl) Dispose(ctx context.Context, id session.Id) (model.SessionActionResult, error) {
	return this.perform(ctx, id, true)
}

func (this managementSessionControl) perform(ctx context.Context, id session.Id, dispose bool) (result model.SessionActionResult, resultErr error) {
	if err := ctx.Err(); err != nil {
		return result, err
	}
	var target session.Session
	if err := this.service.sessions.FindAll(ctx, func(_ context.Context, candidate session.Session) (bool, error) {
		if candidate.Id() != id {
			return true, nil
		}
		if target != nil {
			return false, fmt.Errorf("session ID %q exists in multiple flows", id)
		}
		target = candidate
		return true, nil
	}, nil); err != nil {
		return result, err
	}
	if target == nil {
		return result, fmt.Errorf("session %q: %w", id, session.ErrNoSuchSession)
	}
	return this.performTarget(ctx, target, dispose, nil)
}

// Both SSH and structured operations converge here. A structured confirmation
// supplies an additional generation check after the started audit, before any
// disconnect/revocation/disposal. SSH keeps its existing ID ambiguity behavior.
func (this managementSessionControl) performTarget(ctx context.Context, target session.Session, dispose bool, check func(context.Context) error) (result model.SessionActionResult, resultErr error) {
	id := target.Id()
	caller := this.task.Authorization().FindSession()
	if caller == nil {
		return result, fmt.Errorf("management invocation has no authorized session")
	}
	if caller.Flow() == target.Flow() && caller.Id() == target.Id() {
		return result, fmt.Errorf("cannot disconnect or dispose the session executing this management command; use a different management session")
	}
	result = model.SessionActionResult{ID: id.String(), Flow: target.Flow().String(), Action: "disconnect"}
	startedName, completedName := audit.EventNameSessionDisconnectStarted, audit.EventNameSessionDisconnectCompleted
	if dispose {
		result.Action = "dispose"
		startedName, completedName = audit.EventNameSessionDisposeStarted, audit.EventNameSessionDisposeCompleted
	}
	operationID, err := uuid.NewRandom()
	if err != nil {
		return result, err
	}
	event := audit.Event{
		Name: startedName, Domain: audit.EventDomainSession,
		Flow: result.Flow, SessionId: result.ID, OperationId: operationID.String(),
		ConnectionId: this.task.Connection().Id().String(),
	}
	// Record the target and initiating connection in both flows. The initiating
	// connection links these operations to the management authentication/task.
	record := func(event audit.Event) error {
		result := this.service.recordFlowAudit(ctx, caller.Flow(), event)
		callerLog, callerConfigured := this.service.flowAuditlogs[caller.Flow()]
		targetLog, targetConfigured := this.service.flowAuditlogs[target.Flow()]
		if target.Flow() != caller.Flow() && (!callerConfigured || !targetConfigured || callerLog != targetLog) {
			result = errors.Join(result, this.service.recordFlowAudit(ctx, target.Flow(), event))
		}
		return result
	}
	if err := record(event); err != nil {
		return result, err
	}
	started := time.Now()
	defer func() {
		event.Name = completedName
		event.DurationMillis = common.P(time.Since(started).Milliseconds())
		event.Outcome = audit.EventOutcomeSuccess
		if resultErr != nil {
			event.Outcome = audit.EventOutcomeFailure
			event.ErrorCategory = auditErrorCategory(resultErr)
		}
		resultErr = errors.Join(resultErr, record(event))
	}()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if check != nil {
		if err := check(ctx); err != nil {
			return result, err
		}
	}
	if !dispose {
		return result, this.service.sessionConnections.disconnect(target.Flow(), target.Id())
	}
	// Fail closed for late registrations, even if persisting disposal fails.
	// Only disposeWith may remove resources, after durable session disposal.
	disconnectErr := this.service.sessionConnections.revoke(target.Flow(), target.Id())
	this.service.oidcRefresh.stop(target)
	_, err = this.service.houseKeeper.disposeWith(ctx, this.service.logger().With("session", target), target, false, nil, func() {
		disconnectErr = errors.Join(disconnectErr, this.service.sessionConnections.revoke(target.Flow(), target.Id()))
	})
	return result, errors.Join(disconnectErr, err)
}
