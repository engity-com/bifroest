package service

import (
	"context"
	goerrors "errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/recording"
)

func TestFailurePolicyAuditRecorderStrictReturnsFailure(t *testing.T) {
	failure := goerrors.New("journal unavailable")
	delegate := &recordingAuditRecorder{recordErr: failure}
	svc := &service{
		Service: &Service{},
		auditlogStates: map[configuration.AuditlogName]*auditlogRuntimeState{
			"security": {policy: configuration.AuditlogFailurePolicyStrict},
		},
	}
	recorder := &failurePolicyAuditRecorder{service: svc, auditlog: "security", delegate: delegate}

	require.ErrorIs(t, recorder.Record(t.Context(), audit.Event{Name: "test.failure"}), failure)
	require.False(t, svc.auditlogDisabled("security"))
}

func TestFailurePolicyAuditRecorderBestEffortDisablesAuditlog(t *testing.T) {
	failure := goerrors.New("journal unavailable")
	delegate := &recordingAuditRecorder{recordErr: failure}
	svc := &service{
		Service: &Service{},
		auditlogStates: map[configuration.AuditlogName]*auditlogRuntimeState{
			"security": {policy: configuration.AuditlogFailurePolicyBestEffort},
		},
	}
	recorder := &failurePolicyAuditRecorder{service: svc, auditlog: "security", delegate: delegate}

	require.NoError(t, recorder.Record(t.Context(), audit.Event{Name: "test.failure"}))
	require.True(t, svc.auditlogDisabled("security"))
	require.NoError(t, recorder.Record(t.Context(), audit.Event{Name: "test.ignored"}))
	require.Len(t, delegate.eventsSnapshot(), 1)
}

func TestBestEffortSessionRecordingSinkDisablesAfterFailure(t *testing.T) {
	delegate := &failurePolicyRecordingSink{err: goerrors.New("disk full")}
	svc := &service{
		Service: &Service{},
		auditlogStates: map[configuration.AuditlogName]*auditlogRuntimeState{
			"security": {policy: configuration.AuditlogFailurePolicyBestEffort},
		},
	}
	sink := &bestEffortSessionRecordingSink{service: svc, auditlog: "security", delegate: delegate}

	require.NoError(t, sink.WriteOutput(time.Second, recording.OutputStreamTerminal, []byte("first")))
	require.NoError(t, sink.WriteOutput(2*time.Second, recording.OutputStreamTerminal, []byte("second")))
	require.True(t, svc.auditlogDisabled("security"))
	require.Equal(t, 1, delegate.calls)
}

func TestBestEffortAuditFailurePreservesRecordingRetentionState(t *testing.T) {
	for _, completionPending := range []bool{false, true} {
		t.Run(map[bool]string{false: "before deletion", true: "before completion"}[completionPending], func(t *testing.T) {
			delegate := &recordingAuditRecorder{recordErr: goerrors.New("journal unavailable")}
			svc := &service{
				Service: &Service{},
				auditRecorders: map[configuration.AuditlogName]audit.Recorder{
					"security": &failurePolicyAuditRecorder{auditlog: "security", delegate: delegate},
				},
				auditlogStates: map[configuration.AuditlogName]*auditlogRuntimeState{
					"security": {policy: configuration.AuditlogFailurePolicyBestEffort},
				},
			}
			svc.auditRecorders["security"].(*failurePolicyAuditRecorder).service = svc
			id, err := recording.NewId()
			require.NoError(t, err)
			candidate := sessionRecordingRetentionCandidate{recordingId: id}
			candidate.receipt.CompletionPending = completionPending
			performed := false
			completed := false

			changed, actionErr, auditErr := (&houseKeeper{service: svc}).auditRecordingDeletion(t.Context(), "security", candidate, func() (bool, sessionRecordingRetentionCandidate, error) {
				performed = true
				return true, candidate, nil
			}, func(sessionRecordingRetentionCandidate) error {
				completed = true
				return nil
			})

			require.False(t, changed)
			require.NoError(t, actionErr)
			require.NoError(t, auditErr)
			require.False(t, performed)
			require.False(t, completed)
			require.True(t, svc.auditlogDisabled("security"))
		})
	}
}

func TestPrepareBestEffortDisablesAuditlogWithUnavailableJournal(t *testing.T) {
	directory := t.TempDir()
	journal := filepath.Join(directory, "journal")
	require.NoError(t, os.WriteFile(journal, []byte("not a directory"), 0600))
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Auditlogs[0].Enabled = true
		conf.Auditlogs[0].FailurePolicy = configuration.AuditlogFailurePolicyBestEffort
		conf.Auditlogs[0].IdentityFile = filepath.Join(directory, "identity")
		conf.Auditlogs[0].Journal.Directory = journal
	})

	require.True(t, server.service.auditlogDisabled(configuration.DefaultAuditlogName))
	require.NoError(t, server.service.flowAuditRecorders[server.service.Configuration.Flows[0].Name].Record(context.Background(), audit.Event{Name: "test.ignored"}))
}

type failurePolicyRecordingSink struct {
	calls int
	err   error
}

func (this *failurePolicyRecordingSink) WriteOutput(time.Duration, recording.OutputStream, []byte) error {
	this.calls++
	return this.err
}

func (this *failurePolicyRecordingSink) WriteResize(time.Duration, uint32, uint32) error {
	this.calls++
	return this.err
}
