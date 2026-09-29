package environment

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
)

type localCoordinatorTestRepository struct {
	session.Repository
	sessions []session.Session
	err      error
}

func (this *localCoordinatorTestRepository) FindAll(ctx context.Context, consume session.Consumer, _ *session.FindOpts) error {
	if this.err != nil {
		return this.err
	}
	for _, candidate := range this.sessions {
		cont, err := consume(ctx, candidate)
		if err != nil {
			return err
		}
		if !cont {
			break
		}
	}
	return nil
}

type localCoordinatorTestSession struct {
	session.Session
	flow        configuration.FlowName
	id          session.Id
	token       []byte
	state       session.State
	connections bool
}

func (this *localCoordinatorTestSession) Flow() configuration.FlowName { return this.flow }
func (this *localCoordinatorTestSession) Id() session.Id               { return this.id }
func (this *localCoordinatorTestSession) EnvironmentToken(context.Context) ([]byte, error) {
	return this.token, nil
}
func (this *localCoordinatorTestSession) SetEnvironmentToken(_ context.Context, value []byte) error {
	this.token = value
	return nil
}
func (this *localCoordinatorTestSession) Info(context.Context) (session.Info, error) {
	return localCoordinatorTestInfo{state: this.state}, nil
}
func (this *localCoordinatorTestSession) HasActiveConnections() bool { return this.connections }

type localCoordinatorTestInfo struct {
	session.Info
	state session.State
}

func (this localCoordinatorTestInfo) State() session.State { return this.state }

func TestLocalAccountCoordinatorOtherActiveAcrossFlows(t *testing.T) {
	current := &localCoordinatorTestSession{flow: "first", id: session.MustNewId(), token: []byte(`{"user":{"name":"local-user","uid":1234}}`)}
	other := &localCoordinatorTestSession{
		flow: "second", id: current.id,
		token: []byte(`{"user":{"name":"local-user","uid":1234}}`),
	}
	for _, test := range []struct {
		name        string
		state       session.State
		connections bool
		want        bool
	}{
		{name: "active in another flow", state: session.StateAuthorized, want: true},
		{name: "disposed without connections", state: session.StateDisposed},
		{name: "disposed with connections", state: session.StateDisposed, connections: true, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			other.state, other.connections = test.state, test.connections
			coordinator := &localAccountCoordinator{sessions: &localCoordinatorTestRepository{sessions: []session.Session{current, other}}}
			active, err := coordinator.otherActive(context.Background(), current, "local-user", "1234")
			require.NoError(t, err)
			require.Equal(t, test.want, active)
		})
	}
}

func TestLocalAccountCoordinatorKillWaitsForLastSessionAndConnections(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	current := &localCoordinatorTestSession{flow: "first", id: session.MustNewId(), state: session.StateDisposed, token: []byte(`{"user":{"name":"alice","sid":"S-1-5-21-1-2-3-1001"}}`)}
	other := &localCoordinatorTestSession{flow: "second", id: session.MustNewId(), token: []byte(`{"user":{"name":"alice","sid":"S-1-5-21-1-2-3-1001"}}`)}
	coordinator := &localAccountCoordinator{sessions: &localCoordinatorTestRepository{sessions: []session.Session{current, other}}}
	for _, test := range []struct {
		name               string
		currentState       session.State
		currentConnections bool
		otherState         session.State
		otherConnections   bool
		want               bool
	}{
		{name: "current session is active", currentState: session.StateAuthorized, otherState: session.StateDisposed},
		{name: "current connection remains", currentState: session.StateDisposed, currentConnections: true, otherState: session.StateDisposed},
		{name: "other session is active", currentState: session.StateDisposed, otherState: session.StateAuthorized},
		{name: "other connection remains", currentState: session.StateDisposed, otherState: session.StateDisposed, otherConnections: true},
		{name: "last session disposed", currentState: session.StateDisposed, otherState: session.StateDisposed, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			current.state, current.connections = test.currentState, test.currentConnections
			other.state, other.connections = test.otherState, test.otherConnections
			ready, err := coordinator.canKillProcesses(context.Background(), current, "alice", sid)
			require.NoError(t, err)
			require.Equal(t, test.want, ready)
		})
	}
}

func TestLocalAccountCoordinatorKillFailsClosed(t *testing.T) {
	current := &localCoordinatorTestSession{flow: "first", id: session.MustNewId(), state: session.StateDisposed, token: []byte(`{"user":{"name":"alice","uid":1234}}`)}
	for _, test := range []struct {
		name        string
		coordinator *localAccountCoordinator
	}{
		{name: "no coordinator"},
		{name: "no repository", coordinator: &localAccountCoordinator{}},
		{name: "enumeration fails", coordinator: &localAccountCoordinator{sessions: &localCoordinatorTestRepository{err: errors.New("cannot inspect sessions")}}},
		{name: "current session missing", coordinator: &localAccountCoordinator{sessions: &localCoordinatorTestRepository{}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ready, err := test.coordinator.canKillProcesses(context.Background(), current, "alice", "1234")
			require.False(t, ready)
			require.Error(t, err)
		})
	}
}

func TestLocalAccountCoordinatorReadsTextMarshaledUID(t *testing.T) {
	current := &localCoordinatorTestSession{flow: "first", id: session.MustNewId(), token: []byte(`{"user":{"name":"original-account","uid":"1234"}}`)}
	other := &localCoordinatorTestSession{
		flow: "second", id: session.MustNewId(), state: session.StateAuthorized,
		token: []byte(`{"user":{"name":"renamed-account","uid":"1234"}}`),
	}
	coordinator := &localAccountCoordinator{sessions: &localCoordinatorTestRepository{sessions: []session.Session{current, other}}}
	active, err := coordinator.otherActive(context.Background(), current, "original-account", "1234")
	require.NoError(t, err)
	require.True(t, active, "UID must identify a renamed Unix account across flows")
}

func TestLocalAccountCoordinatorOtherActiveFailsClosed(t *testing.T) {
	current := &localCoordinatorTestSession{flow: "first", id: session.MustNewId()}
	for _, test := range []struct {
		name        string
		coordinator *localAccountCoordinator
	}{
		{name: "no coordinator"},
		{name: "no repository", coordinator: &localAccountCoordinator{}},
		{name: "session repository was deleted", coordinator: &localAccountCoordinator{sessions: &localCoordinatorTestRepository{}}},
		{name: "unknown sessions", coordinator: &localAccountCoordinator{sessions: &localCoordinatorTestRepository{err: errors.New("cannot enumerate sessions")}}},
		{name: "corrupt token", coordinator: &localAccountCoordinator{sessions: &localCoordinatorTestRepository{sessions: []session.Session{
			&localCoordinatorTestSession{flow: "second", id: session.MustNewId(), token: []byte(`{"user":`)},
		}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			active, err := test.coordinator.otherActive(context.Background(), current, "local-user", "1234")
			require.False(t, active)
			require.Error(t, err, "unknown session state must not authorize account deletion")
		})
	}
}
