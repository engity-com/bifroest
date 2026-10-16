package session

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	cliformat "github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/session"
)

type SessionSource func(context.Context, func(context.Context, session.Info) (bool, error), session.FindDiagnosticConsumer) error

func ListSessions(ctx context.Context, output io.Writer, selected cliformat.Format, source SessionSource, flow, user, state string, diagnostics session.FindDiagnosticConsumer) error {
	entries := make([]model.SessionView, 0)
	err := source(ctx, func(ctx context.Context, info session.Info) (bool, error) {
		if flow != "" && info.Flow().String() != flow {
			return true, nil
		}
		view, err := newSessionView(ctx, info)
		if err != nil {
			return false, err
		}
		if user != "" && view.User != user {
			return true, nil
		}
		if !matchesSessionState(view, state, time.Now()) {
			return true, nil
		}
		entries = append(entries, view)
		return true, nil
	}, diagnostics)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].CreatedAt.Equal(entries[j].CreatedAt) {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].CreatedAt.Before(entries[j].CreatedAt)
	})
	return cliformat.WriteSessionList(output, selected, entries)
}

func matchesSessionState(view model.SessionView, state string, now time.Time) bool {
	switch state {
	case "all":
		return true
	case "active":
		return view.State == session.StateAuthorized.String() && (view.ValidUntil == nil || now.Before(*view.ValidUntil))
	default:
		return view.State == state
	}
}

func ShowSession(ctx context.Context, output io.Writer, selected cliformat.Format, source SessionSource, id session.Id, diagnostics session.FindDiagnosticConsumer) error {
	var result *model.SessionView
	err := source(ctx, func(ctx context.Context, info session.Info) (bool, error) {
		if info.Id() != id {
			return true, nil
		}
		if result != nil {
			return false, fmt.Errorf("session ID %s exists in multiple flows; use session ls to disambiguate", id)
		}
		view, err := newSessionView(ctx, info)
		if err != nil {
			return false, err
		}
		result = &view
		return true, nil
	}, diagnostics)
	if err != nil {
		return err
	}
	if result == nil {
		return fmt.Errorf("session %s does not exist", id)
	}
	return cliformat.WriteSessionDetail(output, selected, *result)
}

func newSessionView(ctx context.Context, info session.Info) (model.SessionView, error) {
	view := model.SessionView{ID: info.Id().String(), Flow: info.Flow().String(), State: info.State().String()}
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
		value := last.At()
		view.LastAccessed = &value
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

func SessionSourceFromRepository(repository session.Repository) SessionSource {
	return func(ctx context.Context, consumer func(context.Context, session.Info) (bool, error), diagnostics session.FindDiagnosticConsumer) error {
		return repository.FindAll(ctx, func(ctx context.Context, current session.Session) (bool, error) {
			info, err := current.Info(ctx)
			if err != nil {
				return false, err
			}
			return consumer(ctx, info)
		}, &session.FindOpts{DiagnosticConsumer: diagnostics})
	}
}
