package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/session"
)

type managementActionContextKey struct{}

var errManagementConfirmation = errors.New("management confirmation is invalid or expired")

// A generation pin contains immutable creation/association evidence, never
// mutable state/activity, tokens, credentials or a saved authorization policy.
func managementSessionPin(ctx context.Context, current session.Session) ([32]byte, error) {
	info, err := current.Info(ctx)
	if err != nil {
		return [32]byte{}, err
	}
	created, err := info.Created(ctx)
	if err != nil {
		return [32]byte{}, err
	}
	if created == nil || created.At().IsZero() {
		return [32]byte{}, errManagementConfirmation
	}
	owner, err := session.AssociationOf(ctx, current)
	if err != nil && !errors.Is(err, session.ErrAssociationUnavailable) {
		return [32]byte{}, err
	}
	remote := ""
	if created.Remote() != nil {
		remote = created.Remote().String()
	}
	raw, err := json.Marshal(struct {
		Flow, ID string
		Created  time.Time
		Remote   string
		Owner    *session.Association
	}{current.Flow().String(), current.Id().String(), created.At(), remote, owner})
	if err != nil || len(raw) > 16<<10 {
		return [32]byte{}, errManagementConfirmation
	}
	return sha256.Sum256(raw), nil
}

func (this *service) managementActionTarget(ctx context.Context, caller session.Session, request protocol.SessionAction, limited bool) (session.Session, protocol.ActionTarget, [32]byte, error) {
	var empty protocol.ActionTarget
	if request.Validate() != nil || configuration.FlowName(request.Flow).Validate() != nil {
		return nil, empty, [32]byte{}, protocol.ErrRequest
	}
	var id session.Id
	if err := id.UnmarshalText([]byte(request.ID)); err != nil {
		return nil, empty, [32]byte{}, err
	}
	if caller == nil || caller.Flow().String() == request.Flow && caller.Id() == id {
		return nil, empty, [32]byte{}, errManagementPolicy
	}
	current, err := this.sessions.FindBy(ctx, configuration.FlowName(request.Flow), id, nil)
	if err != nil {
		return nil, empty, [32]byte{}, err
	}
	if current.Flow().String() != request.Flow || current.Id() != id {
		return nil, empty, [32]byte{}, errManagementConfirmation
	}
	if limited {
		if err := this.uniqueForcedSessionID(ctx, current); err != nil {
			return nil, empty, [32]byte{}, err
		}
	}
	before, err := managementSessionPin(ctx, current)
	if err != nil {
		return nil, empty, before, err
	}
	item := protocol.ActionTarget{ID: request.ID, Flow: request.Flow}
	if !limited {
		details, err := managementSessionItem(ctx, current)
		if err != nil {
			return nil, empty, before, err
		}
		item.Details = &details
	}
	after, err := managementSessionPin(ctx, current)
	if err != nil || before != after {
		return nil, empty, before, errManagementConfirmation
	}
	return current, item, before, nil
}

func (this *service) RunManagementAction(task environment.TaskContext, request protocol.SessionAction, output io.Writer, _ bool, _ bool) (int, error) {
	if task == nil || task.Authorization() == nil || !task.Authorization().IsAuthorized() || task.Authorization().FindSession() == nil || task.Authorization().FindSession().Flow() != task.Authorization().Flow() || !this.isManagementFlow(task.Authorization().Flow()) || managementActionPolicy(task.Authorization(), request) != nil {
		return -1, errManagementPolicy
	}
	permission, ok := task.Context().Value(managementActionContextKey{}).(*webManagementConfirmation)
	if !ok || permission == nil || permission.preparing == permission.claiming || permission.request != request || permission.connection != task.Connection().Id() {
		return -1, errManagementConfirmation
	}
	caller := task.Authorization().FindSession()
	if caller.Flow() != permission.access.auth.FindSession().Flow() || caller.Id() != permission.access.auth.FindSession().Id() {
		return -1, errManagementConfirmation
	}
	key := authorization.AuthorizedKeyPolicyOf(task.Authorization())
	limited := key != nil && key.ForcedCommand != nil
	if permission.preparing {
		_, target, pin, err := this.managementActionTarget(task.Context(), caller, request, limited)
		if err != nil {
			return -1, err
		}
		encoded, err := json.Marshal(target)
		if err != nil {
			return -1, err
		}
		if _, err := output.Write(encoded); err != nil {
			return -1, err
		}
		permission.pin = pin
		return 0, nil
	}
	var current session.Session
	check := func(ctx context.Context) error {
		if err := managementActionPolicy(task.Authorization(), request); err != nil {
			return err
		}
		candidate, _, pin, err := this.managementActionTarget(ctx, caller, request, limited)
		if err != nil {
			return err
		}
		if pin != permission.pin {
			return errManagementConfirmation
		}
		current = candidate
		return nil
	}
	if err := check(task.Context()); err != nil {
		return -1, err
	}
	control := managementSessionControl{service: this, task: task}
	result, err := control.performTarget(task.Context(), current, request.Action == "dispose", check)
	if err != nil {
		return -1, err
	}
	encoded, err := json.Marshal(protocol.ActionResult{Version: protocol.Version, Status: "completed", Result: result})
	if err != nil {
		return -1, err
	}
	if _, err := io.Copy(output, bytes.NewReader(encoded)); err != nil {
		return -1, fmt.Errorf("cannot capture management action result: %w", err)
	}
	return 0, nil
}
