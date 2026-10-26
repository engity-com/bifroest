package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/management/protocol"
)

func TestForcedReadRecognizesOnlyExplicitReadCeilings(t *testing.T) {
	id := "9c77b24c-62f4-44c2-aea3-771c75e5a107"
	for _, test := range []struct {
		raw       string
		operation protocol.ReadOperation
		table     bool
	}{
		{"flow ls", protocol.ListFlows, false},
		{"audit ls", protocol.ListAuditlogs, false},
		{`audit ls --format='json'`, protocol.ListAuditlogs, false},
		{"audit ls --format yaml", protocol.ListAuditlogs, false},
		{"audit ls --format=cbor", protocol.ListAuditlogs, false},
		{"  flow ls --format=json", protocol.ListFlows, false},
		{`session ls --flow=work --user='ALICE' --state=all --format table`, protocol.ListSessions, true},
		{"session ls --format=cbor", protocol.ListSessions, false},
		{"session show " + id + " --format=yaml", protocol.ShowSession, false},
	} {
		rule, err := ForcedRead(test.raw)
		require.NoError(t, err, test.raw)
		require.Equal(t, test.operation, rule.Operation)
		require.Equal(t, test.table, rule.TableList)
		require.True(t, rule.Allows(protocol.ReadRequest{Operation: test.operation, ID: rule.ID, State: rule.State}))
		require.False(t, rule.Allows(protocol.ReadRequest{Operation: "session.dispose", ID: rule.ID}))
	}
	rule, err := ForcedRead(`session ls --flow=work --user='ALICE' --state=all --format table`)
	require.NoError(t, err)
	require.Equal(t, "work", rule.Flow)
	require.Equal(t, "ALICE", rule.User)
	require.Equal(t, "all", rule.State)
	show, err := ForcedRead("session show " + id)
	require.NoError(t, err)
	require.False(t, show.Allows(protocol.ReadRequest{Operation: protocol.ShowSession, ID: "00000000-0000-0000-0000-000000000001"}))
}

func TestForcedAuditListGrantsOnlyTheExistingSummaryOperation(t *testing.T) {
	for _, format := range []string{"table", "json", "yaml", "cbor"} {
		rule, err := ForcedRead("audit ls --format=" + format)
		require.NoError(t, err)
		request, err := (protocol.ReadRequest{Operation: protocol.ListAuditlogs, Limit: 1}).Normalize()
		require.NoError(t, err)
		require.True(t, rule.Allows(request))
		request.After = request.Next("default", "")
		request, err = request.Normalize()
		require.NoError(t, err)
		require.True(t, rule.Allows(request), "paging may narrow the same complete SSH summary list")
		for _, other := range []protocol.ReadOperation{protocol.ListFlows, protocol.ListSessions, protocol.ShowSession, protocol.ListRecordings, "sessions.dispose", "audit.export"} {
			require.False(t, rule.Allows(protocol.ReadRequest{Operation: other}), format+"/"+string(other))
		}
	}
	for _, raw := range []string{
		"audit", "audit list", "audit show default", "audit events default", "audit export default", "audit ls default", "audit ls --name=default", "audit ls --flow=work", "audit ls --user=alice", "audit ls --state=all", "audit ls --limit=20", "audit ls --after=default", "audit ls --includingCredentials", "audit ls --configuration=private-file", "audit ls --format=json --format=yaml", "audit ls --format=internal-cbor", "audit ls --format=text", "audit ls --format=JSON", "audit ls --format=@private", "audit ls #comment", "audit ls && flow ls", "recording ls default --format=json",
	} {
		_, err := ForcedRead(raw)
		require.Error(t, err, raw)
	}
}

func TestForcedReadDeniesUnknownAmbiguousMutationAndDispatcherForms(t *testing.T) {
	for _, raw := range []string{"", "_bifroest-management-v1", "_bifroest-management-recording-v1", "sh -c 'flow ls'", "flow show work", "flow ls # comment", "flow ls && session ls", "session dispose 9c77b24c-62f4-44c2-aea3-771c75e5a107", "session disconnect 9c77b24c-62f4-44c2-aea3-771c75e5a107", "flow ls @private-file", "session ls --configuration private-file", "session ls --state active --state all", "session ls --user --state=all", "session ls --format=internal-cbor", "session ls --format=text", "flow ls --format=JSON", "session show", "session show bad-id", "session ls --unknown=true", "session ls --user='unterminated", "flow ls\x00", strings.Repeat("x", (16<<10)+1)} {
		_, err := ForcedRead(raw)
		require.Error(t, err, raw)
	}
}

func TestForcedReadProjectionDoesNotInventMissingOwnerOrInfiniteLifetime(t *testing.T) {
	at := time.Now()
	item := protocol.SessionItem{SessionView: protocol.SessionView{ID: "id", Flow: "work", State: "authorized", User: "requester", Remote: "private remote", CreatedAt: at, LastAccessed: &at, ValidUntil: &at}, Owner: &protocol.Owner{Issuer: "issuer", Subject: "owner"}}
	table, err := ForcedRead("session ls")
	require.NoError(t, err)
	limited := table.Project(item)
	require.True(t, limited.PolicyLimited)
	require.Nil(t, limited.Owner)
	require.Empty(t, limited.Remote)
	require.Nil(t, limited.LastAccessed)
	require.Nil(t, limited.ValidUntil)
	require.Equal(t, item.ID, limited.ID)
	require.Equal(t, item.User, limited.User)
	require.Equal(t, item.CreatedAt.Truncate(time.Second), limited.CreatedAt)
	structured, err := ForcedRead("session ls --format=json")
	require.NoError(t, err)
	limited = structured.Project(item)
	require.Nil(t, limited.Owner)
	require.True(t, limited.PolicyLimited)
	require.Equal(t, item.Remote, limited.Remote)
	require.Equal(t, item.ValidUntil, limited.ValidUntil)
	require.NotNil(t, item.Owner, "projection must not mutate the original metadata")
	cborRule, err := ForcedRead("session ls --format=cbor")
	require.NoError(t, err)
	limited = cborRule.Project(item)
	require.Zero(t, limited.CreatedAt.Nanosecond())
	require.Zero(t, limited.ValidUntil.Nanosecond())
	require.Equal(t, at, *item.ValidUntil, "precision reduction must not mutate the original pointer")
}

func TestForcedReadDoesNotExposeValidityThroughAnAdditionalActivePredicate(t *testing.T) {
	for _, format := range []string{"table", "json", "yaml", "cbor"} {
		rule, err := ForcedRead("session ls --state=all --format=" + format)
		require.NoError(t, err)
		require.False(t, rule.Allows(protocol.ReadRequest{Operation: protocol.ListSessions, State: "active"}), format)
		for _, state := range []string{"all", "new", "authorized", "disposed"} {
			require.True(t, rule.Allows(protocol.ReadRequest{Operation: protocol.ListSessions, State: state}), format+"/"+state)
		}
	}
	rule, err := ForcedRead("session ls")
	require.NoError(t, err)
	require.True(t, rule.Allows(protocol.ReadRequest{Operation: protocol.ListSessions, State: "active"}))
	require.True(t, rule.Allows(protocol.ReadRequest{Operation: protocol.ListSessions, State: "all"}))
}
