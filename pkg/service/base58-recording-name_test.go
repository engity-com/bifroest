package service

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/audit/evidence"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/stretchr/testify/require"
)

func TestSessionRecordingNamePreservesLegacyLifecycleDuringNewNotationStage(t *testing.T) {
	svc, _, _, _ := managementWebFixture(t)
	repository := svc.recordingRepositories["default"]
	classic := "34e34ab8-7457-4d88-a5e4-c57791775c3a"
	var id recording.Id
	require.NoError(t, id.UnmarshalText([]byte(classic)))
	legacyName := classic + ".bcast"
	started := audit.Event{Name: audit.EventNameSessionRecordingStarted, Domain: audit.EventDomainSession, Flow: svc.Configuration.Flows[0].Name.String(), RecordingId: classic, ConnectionId: "82d8fdda-4730-43b7-bfde-72733c217bde", SessionId: "6d05798f-b877-4191-8aa0-4576a30411ad", OperationId: "f73ac7c7-ae47-4a6e-878d-e81237773130", SessionTask: audit.SessionTaskExec}
	pty := false
	started.Pty = &pty
	require.NoError(t, repository.receipts.BeginLifecycle(t.Context(), legacyName, time.Now().UTC().Add(-time.Minute), started))
	name, err := repository.artifactName(id)
	require.NoError(t, err)
	require.Equal(t, legacyName, name)
	terminal, err := evidence.NormalizeEventIDs(started)
	require.NoError(t, err)
	terminal.Name = audit.EventNameSessionRecordingCompleted
	terminal.Outcome = audit.EventOutcomeSuccess
	terminal.Pty = nil
	duration := int64(1000)
	exit := 0
	terminal.DurationMillis = &duration
	terminal.ExitCode = &exit
	require.NoError(t, repository.stageLifecycle(t.Context(), id, terminal))
	name, err = repository.artifactName(id)
	require.NoError(t, err)
	require.Equal(t, legacyName, name)
	// A metadata-only name resolution cannot invent a recording or migrate an
	// archive. There is still no sealed file under either notation.
	for _, text := range []string{classic, id.String()} {
		_, err = os.Lstat(filepath.Join(svc.Configuration.Auditlogs[0].Recording.Directory, "sealed", text+".bcast"))
		require.True(t, os.IsNotExist(err))
	}
}
