package session

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	cliformat "github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

type testSessionInfo struct {
	id    session.Id
	flow  configuration.FlowName
	state session.State
	user  string
	valid time.Time
}

func (this testSessionInfo) Flow() configuration.FlowName { return this.flow }
func (this testSessionInfo) Id() session.Id               { return this.id }
func (this testSessionInfo) State() session.State         { return this.state }
func (this testSessionInfo) Created(context.Context) (session.InfoCreated, error) {
	return testCreated{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), testRemote{this.user}}, nil
}
func (this testSessionInfo) LastAccessed(context.Context) (session.InfoLastAccessed, error) {
	return nil, nil
}
func (this testSessionInfo) ValidUntil(context.Context) (time.Time, error) { return this.valid, nil }
func (this testSessionInfo) String() string                                { return this.id.String() }

type testCreated struct {
	at     time.Time
	remote net.Remote
}

func (this testCreated) At() time.Time      { return this.at }
func (this testCreated) Remote() net.Remote { return this.remote }

type testRemote struct{ user string }

func (this testRemote) User() string   { return this.user }
func (this testRemote) Host() net.Host { return net.Host{} }
func (this testRemote) String() string { return this.user + "@host" }

func TestManagementSessionSelection(t *testing.T) {
	first := testSessionInfo{id: session.MustNewId(), flow: "production", state: session.StateAuthorized, user: "alice", valid: time.Now().Add(time.Hour)}
	second := testSessionInfo{id: session.MustNewId(), flow: "production", state: session.StateAuthorized, user: "bob", valid: time.Now().Add(-time.Hour)}
	third := testSessionInfo{id: session.MustNewId(), flow: "other", state: session.StateNew, user: "carol"}
	source := func(ctx context.Context, consumer func(context.Context, session.Info) (bool, error), _ session.FindDiagnosticConsumer) error {
		for _, info := range []testSessionInfo{first, second, third} {
			cont, err := consumer(ctx, info)
			if err != nil || !cont {
				return err
			}
		}
		return nil
	}
	var output bytes.Buffer
	require.NoError(t, ListSessions(t.Context(), &output, cliformat.Json, source, "", "", "active", nil))
	var active []model.SessionView
	require.NoError(t, json.Unmarshal(output.Bytes(), &active))
	require.Len(t, active, 1)
	require.Equal(t, first.id.String(), active[0].ID)
	output.Reset()
	require.NoError(t, ListSessions(t.Context(), &output, cliformat.Json, source, "production", "bob", "all", nil))
	var filtered []model.SessionView
	require.NoError(t, json.Unmarshal(output.Bytes(), &filtered))
	require.Len(t, filtered, 1)
	require.Equal(t, second.id.String(), filtered[0].ID)
	output.Reset()
	require.NoError(t, ShowSession(t.Context(), &output, cliformat.Text, source, third.id, nil))
	require.Contains(t, output.String(), "carol")
	require.Contains(t, output.String(), "other")
	require.NotContains(t, output.String(), "authorizationToken")
}
