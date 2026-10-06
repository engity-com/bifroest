package management

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/session"
)

type SessionSource func(context.Context, string, func(context.Context, session.Info) (bool, error), session.FindDiagnosticConsumer) error

type SessionView struct {
	ID           string     `json:"id" yaml:"id"`
	Flow         string     `json:"flow" yaml:"flow"`
	State        string     `json:"state" yaml:"state"`
	User         string     `json:"user" yaml:"user"`
	Remote       string     `json:"remote" yaml:"remote"`
	CreatedAt    time.Time  `json:"createdAt" yaml:"createdAt"`
	LastAccessed *time.Time `json:"lastAccessed,omitempty" yaml:"lastAccessed,omitempty"`
	ValidUntil   *time.Time `json:"validUntil,omitempty" yaml:"validUntil,omitempty"`
}

func RegisterSessionCommands(app *kingpin.Application, source SessionSource, ctx context.Context, output, diagnostics io.Writer, local bool) {
	parent := app.Command("session", "Inspect Bifröst sessions.")
	var format, configPath string
	formats := []string{"table", "json", "yaml"}
	if !local {
		formats = append(formats, "cbor")
	}
	parent.Flag("format", "Display as a table/list, JSON, or YAML.").Default("table").EnumVar(&format, formats...)
	if local {
		parent.Flag("configuration", "Bifröst configuration file.").Short('c').StringVar(&configPath)
	}
	report := func(_ context.Context, diagnostic session.FindDiagnostic) error {
		_, err := fmt.Fprintln(diagnostics, diagnostic.Error())
		return err
	}
	var flow, user, state string
	cmd := parent.Command("ls", "List active sessions by default.")
	cmd.Flag("flow", "Filter by flow name.").StringVar(&flow)
	cmd.Flag("user", "Filter by requesting user.").StringVar(&user)
	cmd.Flag("state", "Select active, new, authorized, disposed or all.").Default("active").EnumVar(&state, "active", "new", "authorized", "disposed", "all")
	cmd.Action(func(*kingpin.ParseContext) error {
		return ListSessions(ctx, output, Format(format), source, configPath, flow, user, state, report)
	})
	var id session.Id
	parent.Command("show", "Show one session by ID.").Action(func(*kingpin.ParseContext) error {
		return ShowSession(ctx, output, Format(format), source, configPath, id, report)
	}).Arg("id", "Session UUID.").Required().SetValue(&id)
}

func ListSessions(ctx context.Context, output io.Writer, format Format, source SessionSource, configPath, flow, user, state string, diagnostics session.FindDiagnosticConsumer) error {
	entries := make([]SessionView, 0)
	err := source(ctx, configPath, func(ctx context.Context, info session.Info) (bool, error) {
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
	return WriteSessionList(output, format, entries)
}

func WriteSessionList(output io.Writer, format Format, entries []SessionView) error {
	rows := make([][]string, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, []string{entry.ID, entry.Flow, entry.State, entry.User, entry.CreatedAt.Format(time.RFC3339)})
	}
	return WriteList(output, format, []string{"ID", "FLOW", "STATE", "USER", "CREATED"}, rows, entries)
}

func matchesSessionState(view SessionView, state string, now time.Time) bool {
	switch state {
	case "all":
		return true
	case "active":
		return view.State == session.StateAuthorized.String() && (view.ValidUntil == nil || now.Before(*view.ValidUntil))
	default:
		return view.State == state
	}
}

func ShowSession(ctx context.Context, output io.Writer, format Format, source SessionSource, configPath string, id session.Id, diagnostics session.FindDiagnosticConsumer) error {
	var result *SessionView
	err := source(ctx, configPath, func(ctx context.Context, info session.Info) (bool, error) {
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
	return WriteSessionDetail(output, format, *result)
}

func WriteSessionDetail(output io.Writer, format Format, result SessionView) error {
	fields := []Field{{"ID", result.ID}, {"Flow", result.Flow}, {"State", result.State}, {"User", result.User}, {"Remote", result.Remote}, {"Created", result.CreatedAt.Format(time.RFC3339)}}
	if result.LastAccessed != nil {
		fields = append(fields, Field{"Last accessed", result.LastAccessed.Format(time.RFC3339)})
	}
	if result.ValidUntil != nil {
		fields = append(fields, Field{"Valid until", result.ValidUntil.Format(time.RFC3339)})
	}
	return WriteDetail(output, format, fields, result)
}

func newSessionView(ctx context.Context, info session.Info) (SessionView, error) {
	view := SessionView{ID: info.Id().String(), Flow: info.Flow().String(), State: info.State().String()}
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
	return func(ctx context.Context, path string, consumer func(context.Context, session.Info) (bool, error), diagnostics session.FindDiagnosticConsumer) error {
		if strings.TrimSpace(path) != "" {
			return fmt.Errorf("remote session commands do not accept local configuration files")
		}
		return repository.FindAll(ctx, func(ctx context.Context, current session.Session) (bool, error) {
			info, err := current.Info(ctx)
			if err != nil {
				return false, err
			}
			return consumer(ctx, info)
		}, &session.FindOpts{DiagnosticConsumer: diagnostics})
	}
}
