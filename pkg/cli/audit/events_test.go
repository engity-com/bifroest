package audit

import (
	"testing"

	"github.com/stretchr/testify/require"

	bfAudit "github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestReadAuditEventsSelectsNewestAfterNameFlowAndTimeFilters(t *testing.T) {
	configured := createAuditCliTestJournal(t, t.TempDir(), "default", "seed")
	key, err := LoadAuditPrivateKey(configured.IdentityFile)
	require.NoError(t, err)
	identity, err := bfAudit.NewIdentity(key)
	require.NoError(t, err)
	recorder, err := bfAudit.NewRecorder(&configured, identity)
	require.NoError(t, err)
	for _, event := range []bfAudit.Event{
		{Name: "wanted", Flow: "admin"},
		{Name: "skip", Flow: "admin"},
		{Name: "wanted", Flow: "other"},
		{Name: "wanted", Flow: "admin"},
		{Name: "wanted", Flow: "admin"},
		{Name: "skip", Flow: "admin"},
	} {
		require.NoError(t, recorder.Record(t.Context(), event))
	}
	require.NoError(t, recorder.Close())
	conf := &configuration.Configuration{Auditlogs: configuration.Auditlogs{configured}}
	verified, err := bfAudit.VerifyLiveJournals(t.Context(), []bfAudit.JournalSource{{
		Name: "default", Directory: configured.Directory, ExpectedProducerId: identity.ProducerId(), WithSensitive: true,
	}})
	require.NoError(t, err)
	all := verified.Records()
	require.Len(t, all, 7)
	filter := EventFilter{Name: "wanted", Flow: "admin", Since: all[2].RecordedAt, Until: all[5].RecordedAt, Limit: 2}
	_, err = ReadAuditEvents(t.Context(), conf, configured.Name, identity.ProducerId(), filter, false, nil)
	require.ErrorContains(t, err, "--with-sensitive")
	for _, sensitive := range []bool{false, true} {
		filter.Flow = ""
		if sensitive {
			filter.Flow = "admin"
		}
		records, err := ReadAuditEvents(t.Context(), conf, configured.Name, identity.ProducerId(), filter, sensitive, nil)
		require.NoError(t, err)
		require.Len(t, records, 2)
		require.Equal(t, all[4].Id, records[0].Id)
		require.Equal(t, all[5].Id, records[1].Id)
		for _, record := range records {
			if sensitive {
				require.Equal(t, "admin", record.Event.Flow)
			} else {
				require.Empty(t, record.Event.Flow)
			}
		}
	}
}
