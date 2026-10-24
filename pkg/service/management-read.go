package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	managementpolicy "github.com/engity-com/bifroest/pkg/management/policy"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	managementview "github.com/engity-com/bifroest/pkg/management/view"
	"github.com/engity-com/bifroest/pkg/session"
)

var errManagementPolicy = errors.New("structured management is not allowed by the invocation policy")

func managementReadPolicy(auth authorization.Authorization) error {
	if policy := authorization.AuthorizedKeyPolicyOf(auth); policy != nil && policy.ForcedCommand != nil {
		if _, err := managementpolicy.ForcedRead(*policy.ForcedCommand); err != nil {
			return errManagementPolicy
		}
	}
	return nil
}

func managementReadCeiling(auth authorization.Authorization, request protocol.ReadRequest) (*managementpolicy.ReadCeiling, error) {
	if key := authorization.AuthorizedKeyPolicyOf(auth); key != nil && key.ForcedCommand != nil {
		ceiling, err := managementpolicy.ForcedRead(*key.ForcedCommand)
		if err != nil || !ceiling.Allows(request) {
			return nil, errManagementPolicy
		}
		return &ceiling, nil
	}
	return nil, nil
}

func managementActionPolicy(auth authorization.Authorization) error {
	if key := authorization.AuthorizedKeyPolicyOf(auth); key != nil && key.ForcedCommand != nil {
		return errManagementPolicy
	}
	return nil
}

// This is the shared environment capability, not a CLI command adapter. These
// initial operations intentionally expose no credentials or artifact transfers.
func (this *service) RunManagementRead(task environment.TaskContext, request protocol.ReadRequest, output io.Writer, _ bool, _ bool) (int, error) {
	if task == nil || task.Authorization() == nil || !task.Authorization().IsAuthorized() || task.Authorization().FindSession() == nil || task.Authorization().FindSession().Flow() != task.Authorization().Flow() || !this.isManagementFlow(task.Authorization().Flow()) {
		return -1, errManagementPolicy
	}
	if err := managementReadPolicy(task.Authorization()); err != nil {
		return -1, err
	}
	request, err := request.Normalize()
	if err != nil {
		return -1, err
	}
	ceiling, err := managementReadCeiling(task.Authorization(), request)
	if err != nil {
		return -1, err
	}
	ctx := task.Context()
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	result := protocol.ReadResult{Version: protocol.Version, Operation: request.Operation}
	switch request.Operation {
	case protocol.ListFlows:
		page, err := this.managementFlowPage(ctx, request)
		if err != nil {
			return -1, err
		}
		result.Flows = &page
	case protocol.ListSessions:
		page, err := this.managementSessionPage(ctx, request, ceiling)
		if err != nil {
			return -1, err
		}
		result.Sessions = &page
	case protocol.ShowSession:
		var id session.Id
		if err := id.UnmarshalText([]byte(request.ID)); err != nil {
			return -1, err
		}
		current, err := this.sessions.FindBy(ctx, configuration.FlowName(request.Flow), id, nil)
		if err != nil {
			return -1, err
		}
		if ceiling != nil {
			if err := this.uniqueForcedSessionID(ctx, current); err != nil {
				return -1, err
			}
		}
		item, err := managementSessionItemWithOwner(ctx, current, ceiling == nil)
		if err != nil {
			return -1, err
		}
		if ceiling != nil {
			item = ceiling.Project(item)
		}
		result.Session = &item
	default:
		return -1, protocol.ErrRequest
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return -1, err
	}
	if len(encoded) > protocol.MaximumResponseBytes {
		return -1, fmt.Errorf("management result exceeds response bound")
	}
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	_, err = io.Copy(output, bytes.NewReader(encoded))
	if err != nil {
		return -1, err
	}
	return 0, nil
}

type readSlot[T any] struct {
	key   string
	value T
}

func insertRead[T any](items []readSlot[T], key string, value T, maximum int) []readSlot[T] {
	index := sort.Search(len(items), func(i int) bool { return items[i].key >= key })
	if index >= maximum {
		return items
	}
	if len(items) < maximum {
		items = append(items, readSlot[T]{})
	}
	copy(items[index+1:], items[index:len(items)-1])
	items[index] = readSlot[T]{key, value}
	return items
}

func (this *service) managementFlowPage(ctx context.Context, request protocol.ReadRequest) (protocol.Page[protocol.FlowSummary], error) {
	page := protocol.Page[protocol.FlowSummary]{Items: make([]protocol.FlowSummary, 0)}
	after, _, err := request.Cursor()
	if err != nil {
		return page, err
	}
	var items []readSlot[protocol.FlowSummary]
	for _, flow := range this.Configuration.Flows {
		if err := ctx.Err(); err != nil {
			return page, err
		}
		if flow.Name.String() <= after {
			continue
		}
		items = insertRead(items, flow.Name.String(), managementview.Flow(flow), request.Limit+1)
	}
	for i, item := range items {
		if i == request.Limit {
			last := items[i-1].value
			page.Next = request.Next(last.Name, "")
			break
		}
		page.Items = append(page.Items, item.value)
	}
	return page, nil
}

func managementSessionItem(ctx context.Context, current session.Session) (protocol.SessionItem, error) {
	return managementSessionItemWithOwner(ctx, current, true)
}

func managementSessionItemWithOwner(ctx context.Context, current session.Session, includeOwner bool) (protocol.SessionItem, error) {
	var result protocol.SessionItem
	info, err := current.Info(ctx)
	if err != nil {
		return result, err
	}
	result.SessionView, err = managementview.Session(ctx, info)
	if err != nil {
		return result, err
	}
	if includeOwner {
		owner, err := session.AssociationOf(ctx, current)
		if err != nil && !errors.Is(err, session.ErrAssociationUnavailable) {
			return result, err
		}
		if owner != nil {
			result.Owner = &protocol.Owner{Issuer: owner.Issuer, Subject: owner.Subject}
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > 8<<10 {
		return result, fmt.Errorf("session view exceeds metadata bound")
	}
	return result, nil
}

func (this *service) managementSessionPage(ctx context.Context, request protocol.ReadRequest, ceiling *managementpolicy.ReadCeiling) (protocol.Page[protocol.SessionItem], error) {
	page := protocol.Page[protocol.SessionItem]{Items: make([]protocol.SessionItem, 0)}
	flow, id, err := request.Cursor()
	if err != nil {
		return page, err
	}
	after := ""
	if flow != "" {
		after = flow + "\x00" + id
	}
	var items []readSlot[protocol.SessionItem]
	now := time.Now()
	err = this.sessions.FindAll(ctx, func(ctx context.Context, current session.Session) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if request.Flow != "" && current.Flow().String() != request.Flow {
			return true, nil
		}
		key := current.Flow().String() + "\x00" + current.Id().String()
		if key <= after {
			return true, nil
		}
		item, err := managementSessionItemWithOwner(ctx, current, ceiling == nil)
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			page.Skipped++
			return true, nil
		}
		if request.User != "" && item.User != request.User || !managementview.MatchesState(item.SessionView, request.State, now) {
			return true, nil
		}
		if ceiling != nil {
			if ceiling.Flow != "" && item.Flow != ceiling.Flow || ceiling.User != "" && item.User != ceiling.User || !managementview.MatchesState(item.SessionView, ceiling.State, now) {
				return true, nil
			}
			item = ceiling.Project(item)
		}
		items = insertRead(items, key, item, request.Limit+1)
		return true, nil
	}, &session.FindOpts{DiagnosticConsumer: func(context.Context, session.FindDiagnostic) error { page.Skipped++; return nil }})
	if err != nil {
		return page, err
	}
	for i, item := range items {
		if i == request.Limit {
			last := items[i-1].value
			page.Next = request.Next(last.Flow, last.ID)
			break
		}
		page.Items = append(page.Items, item.value)
	}
	return page, nil
}

func (this *service) uniqueForcedSessionID(ctx context.Context, target session.Session) error {
	count := 0
	err := this.sessions.FindAll(ctx, func(_ context.Context, current session.Session) (bool, error) {
		if current.Id() == target.Id() {
			count++
			if current.Flow() != target.Flow() || count > 1 {
				return false, errManagementPolicy
			}
		}
		return true, nil
	}, &session.FindOpts{DiagnosticConsumer: func(context.Context, session.FindDiagnostic) error { return nil }})
	if err != nil {
		return err
	}
	if count != 1 {
		return errManagementPolicy
	}
	return nil
}
