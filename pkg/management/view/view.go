// Package view constructs management data shared by CLI and structured adapters.
// It performs no authentication, command parsing, output formatting or cleanup.
package view

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/session"
)

func Flows(conf *configuration.Configuration) ([]protocol.FlowSummary, error) {
	if conf == nil {
		return nil, fmt.Errorf("missing configuration")
	}
	entries := make([]protocol.FlowSummary, 0, len(conf.Flows))
	for _, flow := range conf.Flows {
		entries = append(entries, Flow(flow))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

func Flow(flow configuration.Flow) protocol.FlowSummary {
	authorization, environment := "", ""
	if flow.Authorization.V != nil {
		authorization = flow.Authorization.V.Types()[0]
	}
	if flow.Environment.V != nil {
		environment = flow.Environment.V.Types()[0]
	}
	return protocol.FlowSummary{Name: flow.Name.String(), Auditlog: flow.Auditlog.String(), Authorization: authorization, Environment: environment}
}

func Session(ctx context.Context, info session.Info) (protocol.SessionView, error) {
	view := protocol.SessionView{ID: info.Id().String(), Flow: info.Flow().String(), State: info.State().String()}
	created, err := info.Created(ctx)
	if err != nil {
		return view, err
	}
	if created != nil {
		view.CreatedAt = created.At()
		if remote := created.Remote(); remote != nil {
			view.Remote, view.User = remote.String(), remote.User()
		}
	}
	last, err := info.LastAccessed(ctx)
	if err != nil {
		return view, err
	}
	if last != nil && !last.At().IsZero() {
		at := last.At()
		view.LastAccessed = &at
	}
	valid, err := info.ValidUntil(ctx)
	if err != nil {
		return view, err
	}
	if !valid.IsZero() {
		view.ValidUntil = &valid
	}
	return view, nil
}

func MatchesState(view protocol.SessionView, state string, now time.Time) bool {
	switch state {
	case "all":
		return true
	case "active":
		return view.State == session.StateAuthorized.String() && (view.ValidUntil == nil || now.Before(*view.ValidUntil))
	default:
		return view.State == state
	}
}
