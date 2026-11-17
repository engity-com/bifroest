package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfconnection "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestPrepareWithoutAuditlogUsesNoopAndDoesNotRecord(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	conf.Auditlogs = nil
	conf.Flows[0].Auditlog = ""
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	defer func() { require.NoError(t, svc.Close()) }()
	require.Empty(t, svc.auditIdentities)
	require.Empty(t, svc.auditRecorders)
	require.Empty(t, svc.recordingRepositories)
	flow := conf.Flows[0].Name
	require.NotNil(t, svc.flowAuditRecorders[flow])
	require.NoError(t, svc.recordFlowAudit(t.Context(), flow, audit.Event{Name: "test.optional"}))
	require.NoError(t, svc.recordUnauthenticatedFlowAudit(t.Context(), flow, audit.Event{Name: "test.optional"}))
	capture, lifecycle, err := svc.beginRecording(nil, terminalRecordingPty{}, nil, nil, uuid.New(), flow, audit.SessionTaskExec)
	require.NoError(t, err)
	require.Nil(t, capture)
	require.Nil(t, lifecycle)
	require.NoDirExists(t, filepath.Join(root, "audit"))
	require.NoDirExists(t, filepath.Join(root, "recording-storage"))
}

func TestPrepareOptionalAuditDoesNotUseAnotherFlowAuditlog(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	conf.Auditlogs[0].Name = "security"
	conf.Auditlogs[0].Recording.Enabled = true
	conf.Flows[0].Auditlog = ""
	audited := conf.Flows[0]
	audited.Name, audited.Auditlog = "audited", "security"
	conf.Flows = append(conf.Flows, audited)
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	defer func() { require.NoError(t, svc.Close()) }()
	require.Empty(t, svc.flowAuditlogs[conf.Flows[0].Name])
	require.Equal(t, configuration.AuditlogName("security"), svc.flowAuditlogs[audited.Name])
	require.NotNil(t, svc.recordingRepositories["security"])
	spy := &recordingAuditRecorder{}
	svc.auditRecorders["security"] = spy
	svc.flowAuditRecorders[audited.Name] = spy
	require.NoError(t, svc.recordFlowAudit(t.Context(), conf.Flows[0].Name, audit.Event{Name: "test.optional"}))
	require.NoError(t, svc.recordUnauthenticatedFlowAudit(t.Context(), conf.Flows[0].Name, audit.Event{Name: "test.optional"}))
	capture, lifecycle, err := svc.beginRecording(nil, terminalRecordingPty{}, nil, nil, uuid.New(), conf.Flows[0].Name, audit.SessionTaskExec)
	require.NoError(t, err)
	require.Nil(t, capture)
	require.Nil(t, lifecycle)
	require.Empty(t, spy.eventsSnapshot())
	require.NoError(t, svc.recordFlowAudit(t.Context(), audited.Name, audit.Event{Name: "test.audited"}))
	require.Len(t, spy.eventsSnapshot(), 1)
}

func TestPrepareRejectsUnknownAuditlogInsteadOfUsingNoop(t *testing.T) {
	conf := sessionRecordingTestConfiguration(t, t.TempDir())
	conf.Auditlogs = nil
	conf.Flows[0].Auditlog = "missing"
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.Nil(t, svc)
	require.ErrorContains(t, err, "missing")
}

// Legacy recording-only evidence remains recognizable. Removing Enabled from
// configuration must never silently reinterpret its repository as audited.
func TestRecordingOnlyLegacyRepositoryCannotSwitchToConfiguredAuditlog(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, state := range []string{"empty", "active", "sealed"} {
			t.Run(fmt.Sprintf("encrypted=%t/%s", encrypted, state), func(t *testing.T) {
				root := t.TempDir()
				conf := sessionRecordingTestConfiguration(t, root)
				configured := &conf.Auditlogs[0]
				configured.Recording.Enabled = true
				if encrypted {
					configured.EncryptionPublicKey = sessionRecordingEncryptionPublicKey(t)
				}
				identity, err := audit.EnsureIdentity(configured)
				require.NoError(t, err)
				repository, err := newSessionRecordingRepository(t.Context(), configured.Recording, identity, configured.EncryptionPublicKey, configured.Name, nil, false)
				require.NoError(t, err)
				if state != "empty" {
					id, err := recording.NewId()
					require.NoError(t, err)
					startedAt := time.Now().UTC().Truncate(time.Second)
					active, err := repository.createActive(t.Context(), recording.CastHeader{
						Version: recording.CastVersion, Terminal: recording.CastTerminal{Columns: 80, Rows: 24}, Timestamp: startedAt.Unix(),
					}, recording.CastMetadata{
						RecordingId: id, ConnectionId: bfconnection.MustNewId(), SessionId: session.MustNewId(), OperationId: uuid.New(),
						Flow: conf.Flows[0].Name, Task: audit.SessionTaskExec, ProducerId: identity.ProducerId(), StartedAt: startedAt,
					}, 300)
					require.NoError(t, err)
					require.NoError(t, active.WriteOutput(time.Millisecond, recording.OutputStreamStdout, []byte("preserve legacy evidence")))
					if state == "sealed" {
						exitCode := uint32(0)
						_, err = active.Seal(time.Second, recording.CastResult{Status: recording.CastStatusCompleted, EndedAt: startedAt.Add(time.Second)}, &exitCode)
						require.NoError(t, err)
					}
					require.NoError(t, active.Close())
				}
				require.NoError(t, repository.Close())
				changed, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
				require.Nil(t, changed)
				require.Error(t, err)
				require.NoDirExists(t, configured.Directory)
				marker := "bcast-recording-only/v1\n"
				if encrypted {
					marker = "becast-cbor-recording-only/v1\n"
				}
				requireRecordingFormat(t, configured.Recording.Directory, marker)
			})
		}
	}
}

func TestConfiguredRecordingCannotShareAnotherAuditlogJournalDirectory(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	second := conf.Auditlogs[0]
	second.Name = "recording"
	second.Recording.Enabled = true
	second.IdentityFile = filepath.Join(root, "recording-key")
	second.Recording.Directory = filepath.Join(root, "recording-repository")
	conf.Auditlogs = append(conf.Auditlogs, second)
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.Nil(t, svc)
	require.ErrorContains(t, err, "duplicates auditlog")
	require.NoFileExists(t, second.IdentityFile)
}

func TestConfiguredRecordingFailurePolicies(t *testing.T) {
	for _, policy := range []configuration.AuditlogFailurePolicy{configuration.AuditlogFailurePolicyStrict, configuration.AuditlogFailurePolicyBestEffort} {
		t.Run(string(policy), func(t *testing.T) {
			root := t.TempDir()
			conf := sessionRecordingTestConfiguration(t, root)
			conf.Auditlogs[0].Recording.Enabled = true
			conf.Auditlogs[0].FailurePolicy = policy
			require.NoError(t, os.Mkdir(conf.Auditlogs[0].Recording.Directory, 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(conf.Auditlogs[0].Recording.Directory, "state"), []byte("preserve"), 0o600))
			svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
			if policy == configuration.AuditlogFailurePolicyStrict {
				require.Nil(t, svc)
				require.ErrorContains(t, err, "Recording directory")
			} else {
				require.NoError(t, err)
				require.True(t, svc.auditlogDisabled(conf.Auditlogs[0].Name))
				require.Empty(t, svc.recordingRepositories)
				require.NoError(t, svc.Close())
			}
			require.NoFileExists(t, conf.Auditlogs[0].IdentityFile)
			require.NoDirExists(t, conf.Auditlogs[0].Directory)
		})
	}
}

func TestConfiguredRecordingRejectsSigningIdentityAsEncryptionRecipient(t *testing.T) {
	conf := sessionRecordingTestConfiguration(t, t.TempDir())
	conf.Auditlogs[0].Recording.Enabled = true
	first, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	identity := first.auditIdentities[conf.Auditlogs[0].Name]
	require.NoError(t, first.Close())
	conf.Auditlogs[0].EncryptionPublicKey = crypto.PublicKeys(strings.TrimSpace(string(gossh.MarshalAuthorizedKey(identity.PublicKey().ToSsh()))))
	restarted, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.Nil(t, restarted)
	require.ErrorContains(t, err, "encryption")
	requireRecordingFormat(t, conf.Auditlogs[0].Recording.Directory, "bcast/v1\n")
}
