package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

const sessionRecordingFormatMarker = ".bifroest-recording-format"

func TestPrepareRecordingDisabledHasNoRepositorySideEffects(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	recordingRoot := conf.Auditlogs[0].Recording.Directory

	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	require.Empty(t, svc.recordingRepositories)
	require.Empty(t, svc.recordingRepositoryOrder)
	require.NoDirExists(t, recordingRoot)
	require.NoError(t, svc.Close())
}

func TestPrepareRecordingDisabledIgnoresUnusableNestedDirectory(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	blockingPath := filepath.Join(root, "not-a-directory")
	require.NoError(t, os.WriteFile(blockingPath, []byte("blocked"), 0o600))
	configuredRecordingRoot := filepath.Join(blockingPath, "missing", "recordings")
	conf.Auditlogs[0].Recording.Directory = configuredRecordingRoot

	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	require.Empty(t, svc.recordingRepositories)
	require.NoDirExists(t, configuredRecordingRoot)
	require.NoError(t, svc.Close())
}

func TestPrepareRecordingOpensNativeBCastRepository(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])

	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	repository := svc.recordingRepositories[configuration.DefaultAuditlogName]
	require.NotNil(t, repository)
	require.Equal(t, sessionRecordingRepositoryFormatBCast, repository.format)
	require.NotNil(t, repository.native)
	require.Equal(t, []configuration.AuditlogName{configuration.DefaultAuditlogName}, svc.recordingRepositoryOrder)
	requireRecordingFormat(t, conf.Auditlogs[0].Recording.Directory, "bcast/v1\n")
	require.NoError(t, svc.Close())
}

func TestPrepareRecordingResolvesAndOwnsArtifactTargets(t *testing.T) {
	tests := []struct {
		name            string
		configure       func(*configuration.Auditlog, *serviceRemoteDeliveryTestConfiguration)
		expected        bool
		expectedCreated int
	}{
		{
			name: "inherit",
			configure: func(auditlog *configuration.Auditlog, target *serviceRemoteDeliveryTestConfiguration) {
				auditlog.Targets = configuration.AuditlogTargets{{Name: "archive", V: target}}
			},
			expected:        true,
			expectedCreated: 2,
		},
		{
			name: "disabled",
			configure: func(auditlog *configuration.Auditlog, target *serviceRemoteDeliveryTestConfiguration) {
				auditlog.Targets = configuration.AuditlogTargets{{Name: "archive", V: target}}
				auditlog.Recording.Targets.Mode = configuration.AuditlogRecordingTargetsModeDisabled
			},
			expectedCreated: 1,
		},
		{
			name: "custom",
			configure: func(auditlog *configuration.Auditlog, target *serviceRemoteDeliveryTestConfiguration) {
				auditlog.Recording.Targets.Mode = configuration.AuditlogRecordingTargetsModeCustom
				auditlog.Recording.Targets.Targets = configuration.AuditlogTargets{{Name: "recordings", V: target}}
			},
			expected:        true,
			expectedCreated: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			conf := sessionRecordingTestConfiguration(t, root)
			enableSessionRecording(&conf.Auditlogs[0])
			var targets []*serviceRemoteDeliveryTestTarget
			targetConfiguration := &serviceRemoteDeliveryTestConfiguration{newTarget: func() audit.RemoteTarget {
				target := &serviceRemoteDeliveryTestTarget{published: make(chan uint64, 1)}
				targets = append(targets, target)
				return target
			}}
			test.configure(&conf.Auditlogs[0], targetConfiguration)

			svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
			require.NoError(t, err)
			_, exists := svc.recordingTargets[configuration.DefaultAuditlogName]
			require.Equal(t, test.expected, exists)
			require.Len(t, targets, test.expectedCreated)
			require.NoError(t, svc.Close())
			for _, target := range targets {
				require.True(t, target.closed.Load())
			}
		})
	}
}

func TestPrepareRecordingRejectsJournalOnlyTarget(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	target := &serviceJournalOnlyTestTarget{}
	conf.Auditlogs[0].Recording.Targets.Mode = configuration.AuditlogRecordingTargetsModeCustom
	conf.Auditlogs[0].Recording.Targets.Targets = configuration.AuditlogTargets{{
		Name: "recordings",
		V:    &serviceRemoteDeliveryTestConfiguration{target: target},
	}}

	serviceDefinition := &Service{Configuration: conf, Version: serviceTestVersion{}}
	svc, err := serviceDefinition.prepare()
	require.Nil(t, svc)
	require.ErrorContains(t, err, "does not support remote artifacts")
	require.True(t, target.closed.Load())

	serviceDefinition.Configuration.Auditlogs[0].Recording.Targets.Mode = configuration.AuditlogRecordingTargetsModeDisabled
	serviceDefinition.Configuration.Auditlogs[0].Recording.Targets.Targets = nil
	reopened, err := serviceDefinition.prepare()
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
}

func TestServiceCloseAggregatesRecordingTargetFailureAndReleasesRepository(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	conf.Auditlogs[0].FailurePolicy = configuration.AuditlogFailurePolicyBestEffort
	target := &serviceRemoteDeliveryTestTarget{published: make(chan uint64, 1), closeErr: fmt.Errorf("injected Recording target close failure")}
	conf.Auditlogs[0].Recording.Targets.Mode = configuration.AuditlogRecordingTargetsModeCustom
	conf.Auditlogs[0].Recording.Targets.Targets = configuration.AuditlogTargets{{
		Name: "recordings",
		V:    &serviceRemoteDeliveryTestConfiguration{target: target},
	}}
	serviceDefinition := &Service{Configuration: conf, Version: serviceTestVersion{}}
	svc, err := serviceDefinition.prepare()
	require.NoError(t, err)
	svc.auditlogStates[configuration.DefaultAuditlogName].disabled.Store(true)
	err = svc.Close()
	require.ErrorContains(t, err, "injected Recording target close failure")
	require.True(t, target.closed.Load())

	serviceDefinition.Configuration.Auditlogs[0].Recording.Targets.Mode = configuration.AuditlogRecordingTargetsModeDisabled
	serviceDefinition.Configuration.Auditlogs[0].Recording.Targets.Targets = nil
	reopened, err := serviceDefinition.prepare()
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
}

func TestPrepareRecordingRejectsExistingSpoolAboveLimitWithoutDeletingData(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	auditlog := &conf.Auditlogs[0]
	identity, err := audit.EnsureIdentity(auditlog)
	require.NoError(t, err)
	repository, err := recording.NewLocalNativeRecordingRepository(t.Context(), auditlog.Recording.Directory, identity, nil, recording.NativeRecordingVerifyOptions{}, recording.LocalRepositoryOptions{
		MaximumSpoolBytes: auditlog.Recording.MaximumSpoolBytes,
	})
	require.NoError(t, err)
	require.NoError(t, repository.Close())

	auditlog.Recording.MaximumSpoolBytes = auditlog.Recording.FlushSizeBytes
	payload := make([]byte, auditlog.Recording.MaximumSpoolBytes+1)
	path := filepath.Join(auditlog.Recording.Directory, "quarantine", "preserve")
	require.NoError(t, os.WriteFile(path, payload, 0o600))

	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.ErrorContains(t, err, "exceeding its")
	require.True(t, bferrors.Config.IsErr(err))
	require.Nil(t, svc)
	after, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, payload, after)
}

func TestPrepareRecordingOpensEncryptedNativeWithoutLegacyFallback(t *testing.T) {
	t.Run("opens encrypted native", func(t *testing.T) {
		root := t.TempDir()
		conf := sessionRecordingTestConfiguration(t, root)
		enableSessionRecording(&conf.Auditlogs[0])
		conf.Auditlogs[0].EncryptionPublicKey = sessionRecordingEncryptionPublicKey(t)

		svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
		require.NoError(t, err)
		repository := svc.recordingRepositories[configuration.DefaultAuditlogName]
		require.NotNil(t, repository)
		require.Equal(t, sessionRecordingRepositoryFormatBECast, repository.format)
		require.NotNil(t, repository.native)
		requireRecordingFormat(t, conf.Auditlogs[0].Recording.Directory, "becast-cbor/v1\n")
		require.NoError(t, svc.Close())
	})

	t.Run("rejects an existing Zstd repository", func(t *testing.T) {
		root := t.TempDir()
		conf := sessionRecordingTestConfiguration(t, root)
		enableSessionRecording(&conf.Auditlogs[0])
		identity, err := audit.EnsureIdentity(&conf.Auditlogs[0])
		require.NoError(t, err)
		zstdRepository, err := recording.NewLocalCastZstdRepository(context.Background(), conf.Auditlogs[0].Recording.Directory, identity, recording.CastZstdVerifyOptions{}, recording.LocalRepositoryOptions{
			MaximumSpoolBytes: conf.Auditlogs[0].Recording.MaximumSpoolBytes,
		})
		require.NoError(t, err)
		require.NoError(t, zstdRepository.Close())
		conf.Auditlogs[0].EncryptionPublicKey = sessionRecordingEncryptionPublicKey(t)

		svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
		require.ErrorContains(t, err, "cannot open Recording repository of auditlog \"default\"")
		require.True(t, bferrors.Config.IsErr(err))
		require.Nil(t, svc)
		requireRecordingFormat(t, conf.Auditlogs[0].Recording.Directory, "cast-zstd/v1\n")
	})
}

func TestSessionRecordingRepositoryCreatesAndSealsActiveFormats(t *testing.T) {
	tests := []struct {
		name      string
		encrypted bool
		suffix    string
	}{
		{name: "BCast", suffix: ".bcast"},
		{name: "BECast", encrypted: true, suffix: ".becast"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			conf := sessionRecordingTestConfiguration(t, root)
			identity, err := audit.EnsureIdentity(&conf.Auditlogs[0])
			require.NoError(t, err)
			var encryptionPublicKey bfcrypto.PublicKeys
			if test.encrypted {
				encryptionPublicKey = sessionRecordingEncryptionPublicKey(t)
			}
			repository, err := newSessionRecordingRepository(t.Context(), conf.Auditlogs[0].Recording, identity, encryptionPublicKey, conf.Auditlogs[0].Name, nil)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, repository.Close()) })

			startedAt := time.Now().UTC()
			recordingId, err := recording.NewId()
			require.NoError(t, err)
			connectionId, err := bfconnection.NewId()
			require.NoError(t, err)
			sessionId, err := session.NewId()
			require.NoError(t, err)
			header := recording.CastHeader{
				Version:   3,
				Terminal:  recording.CastTerminal{Columns: 80, Rows: 24, Type: "xterm"},
				Timestamp: startedAt.Unix(),
			}
			metadata := recording.CastMetadata{
				RecordingId:  recordingId,
				ConnectionId: connectionId,
				SessionId:    sessionId,
				OperationId:  uuid.New(),
				Flow:         conf.Flows[0].Name,
				Task:         audit.SessionTaskShell,
				Pty:          true,
				ProducerId:   identity.ProducerId(),
				StartedAt:    startedAt,
			}
			fileName, err := repository.artifactName(recordingId)
			require.NoError(t, err)
			startedEvent := sessionRecordingAuditEvent(metadata, audit.EventNameSessionRecordingStarted, "", "", nil, 0, nil, nil)
			require.NoError(t, repository.receipts.BeginLifecycle(t.Context(), fileName, startedAt, startedEvent))
			exists, err := repository.recordingStateExists(recordingId)
			require.NoError(t, err)
			require.False(t, exists)
			active, err := repository.createActive(t.Context(), header, metadata, 300)
			require.NoError(t, err)
			exists, err = repository.recordingStateExists(recordingId)
			require.NoError(t, err)
			require.True(t, exists)
			require.NoError(t, active.WriteOutput(time.Second, recording.OutputStreamTerminal, []byte("adapter output\r\n")))
			require.NoError(t, active.Checkpoint())
			require.FileExists(t, filepath.Join(conf.Auditlogs[0].Recording.Directory, "active", recordingId.String(), "head.cbor"))
			exitStatus := uint32(7)
			terminalEvent := sessionRecordingAuditEvent(metadata, audit.EventNameSessionRecordingCompleted, audit.EventOutcomeSuccess, "", nil, 2*time.Second, nil, &exitStatus)
			require.NoError(t, repository.receipts.StageLifecycle(t.Context(), fileName, terminalEvent))
			summary, err := active.Seal(2*time.Second, recording.CastResult{
				Status:  recording.CastStatusCompleted,
				EndedAt: startedAt.Add(2 * time.Second),
			}, &exitStatus)
			require.NoError(t, err)
			require.Equal(t, recordingId, summary.recordingId)
			require.Equal(t, recording.CastStatusCompleted, summary.status)
			require.False(t, summary.digest.IsZero())
			require.NoError(t, active.Close())
			names, err := repository.ListSealedArtifactNames(t.Context())
			require.NoError(t, err)
			require.Equal(t, []string{fileName}, names)
			artifact, err := repository.OpenSealedArtifact(t.Context(), fileName)
			require.NoError(t, err)
			remote, err := artifact.RemoteArtifact()
			require.NoError(t, err)
			require.Equal(t, fileName, remote.FileName())
			require.NoError(t, artifact.Close())
			_, err = repository.OpenSealedArtifact(t.Context(), recordingId.String()+".cast.zst")
			require.ErrorContains(t, err, "does not match repository format")

			sealedPath := filepath.Join(conf.Auditlogs[0].Recording.Directory, "sealed", recordingId.String()+test.suffix)
			file, err := os.Open(sealedPath)
			require.NoError(t, err)
			info, err := file.Stat()
			require.NoError(t, err)
			var verification *recording.NativeRecordingVerification
			if test.encrypted {
				verification, err = recording.VerifyNativeRecordingOuter(file, info.Size(), recording.NativeRecordingVerifyOptions{ExpectedProducerId: identity.ProducerId()})
			} else {
				verification, err = recording.VerifyNativeRecordingFull(file, info.Size(), nil, recording.NativeRecordingVerifyOptions{ExpectedProducerId: identity.ProducerId()})
			}
			require.NoError(t, err)
			require.Equal(t, summary.digest, recording.CastDigest(verification.Seal.CastDigest))
			require.Equal(t, recordingId, recording.Id(verification.Header.RecordingId))
			if test.encrypted {
				require.Equal(t, uint8(1), verification.Header.Encryption)
				require.NotEmpty(t, verification.Header.Recipient)
			} else {
				require.Equal(t, uint8(0), verification.Header.Encryption)
			}
			require.NoError(t, file.Close())
			require.NoError(t, repository.Close())
			require.NoError(t, os.RemoveAll(filepath.Join(conf.Auditlogs[0].Recording.Directory, ".delivery")))
			require.NoError(t, os.Mkdir(filepath.Join(conf.Auditlogs[0].Recording.Directory, "active", recordingId.String()), 0o700))
			missing, err := newSessionRecordingRepository(t.Context(), conf.Auditlogs[0].Recording, identity, encryptionPublicKey, conf.Auditlogs[0].Name, nil)
			require.Nil(t, missing)
			require.ErrorContains(t, err, "delivery receipt")
			require.ErrorContains(t, err, "is missing")
		})
	}
}

func TestSessionRecordingStartupRejectsMissingSealedArtifactWithReceipt(t *testing.T) {
	for _, test := range []struct {
		name             string
		encrypted        bool
		retentionStarted bool
	}{
		{name: "BCast missing without retention"},
		{name: "BECast missing without retention", encrypted: true},
		{name: "BCast missing after retention started", retentionStarted: true},
		{name: "BECast missing after retention started", encrypted: true, retentionStarted: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			conf := sessionRecordingTestConfiguration(t, t.TempDir())
			identity, err := audit.EnsureIdentity(&conf.Auditlogs[0])
			require.NoError(t, err)
			var encryptionPublicKey bfcrypto.PublicKeys
			if test.encrypted {
				encryptionPublicKey = sessionRecordingEncryptionPublicKey(t)
			}
			repository, err := newSessionRecordingRepository(t.Context(), conf.Auditlogs[0].Recording, identity, encryptionPublicKey, conf.Auditlogs[0].Name, nil)
			require.NoError(t, err)
			startedAt := time.Now().UTC()
			recordingId, err := recording.NewId()
			require.NoError(t, err)
			connectionId, err := bfconnection.NewId()
			require.NoError(t, err)
			sessionId, err := session.NewId()
			require.NoError(t, err)
			metadata := recording.CastMetadata{
				RecordingId: recordingId, ConnectionId: connectionId, SessionId: sessionId,
				OperationId: uuid.New(), Flow: conf.Flows[0].Name, Task: audit.SessionTaskShell,
				Pty: true, ProducerId: identity.ProducerId(), StartedAt: startedAt,
			}
			name, err := repository.artifactName(recordingId)
			require.NoError(t, err)
			require.NoError(t, repository.receipts.BeginLifecycle(t.Context(), name, startedAt, sessionRecordingAuditEvent(metadata, audit.EventNameSessionRecordingStarted, "", "", nil, 0, nil, nil)))
			active, err := repository.createActive(t.Context(), recording.CastHeader{
				Version: recording.CastVersion, Terminal: recording.CastTerminal{Columns: 80, Rows: 24, Type: "xterm"}, Timestamp: startedAt.Unix(),
			}, metadata, 300)
			require.NoError(t, err)
			require.NoError(t, active.WriteOutput(time.Second, recording.OutputStreamTerminal, []byte("recorded\r\n")))
			require.NoError(t, repository.receipts.StageLifecycle(t.Context(), name, sessionRecordingAuditEvent(metadata, audit.EventNameSessionRecordingCompleted, audit.EventOutcomeSuccess, "", nil, time.Second, nil, commonUint32(0))))
			_, err = active.Seal(time.Second, recording.CastResult{Status: recording.CastStatusCompleted, EndedAt: startedAt.Add(time.Second)}, commonUint32(0))
			require.NoError(t, err)
			require.NoError(t, active.Close())
			if test.retentionStarted {
				pending, err := repository.receipts.PendingLifecycle(t.Context())
				require.NoError(t, err)
				require.Len(t, pending, 1)
				require.NoError(t, repository.receipts.CompleteLifecycle(t.Context(), pending[0]))
				candidates, err := repository.receipts.ListRetentionCandidates(t.Context(), startedAt.Add(time.Minute))
				require.NoError(t, err)
				require.Len(t, candidates, 1)
				require.NoError(t, repository.receipts.MarkRetentionDeleting(t.Context(), candidates[0], startedAt.Add(time.Minute)))
			}
			require.NoError(t, repository.Close())
			sealedPath := filepath.Join(conf.Auditlogs[0].Recording.Directory, "sealed", name)
			require.NoError(t, os.Remove(sealedPath))

			restarted, err := newSessionRecordingRepository(t.Context(), conf.Auditlogs[0].Recording, identity, encryptionPublicKey, conf.Auditlogs[0].Name, nil)
			if test.retentionStarted {
				require.NoError(t, err)
				require.NoError(t, restarted.Close())
			} else {
				require.Nil(t, restarted)
				require.ErrorContains(t, err, name)
				require.ErrorContains(t, err, "is missing despite its delivery receipt")
				require.DirExists(t, filepath.Join(conf.Auditlogs[0].Recording.Directory, ".delivery", identity.ProducerId().String()))
			}
		})
	}
}

func TestPrepareRecordingFailsClosedOnExistingRepositoryLockAndCanRetry(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	identity, err := audit.EnsureIdentity(&conf.Auditlogs[0])
	require.NoError(t, err)
	locked, err := recording.NewLocalNativeRecordingRepository(context.Background(), conf.Auditlogs[0].Recording.Directory, identity, nil, recording.NativeRecordingVerifyOptions{}, recording.LocalRepositoryOptions{
		MaximumSpoolBytes: conf.Auditlogs[0].Recording.MaximumSpoolBytes,
	})
	require.NoError(t, err)

	serviceDefinition := &Service{Configuration: conf, Version: serviceTestVersion{}}
	svc, err := serviceDefinition.prepare()
	require.ErrorContains(t, err, "cannot open Recording repository of auditlog \"default\"")
	require.True(t, bferrors.System.IsErr(err))
	require.Nil(t, svc)

	require.NoError(t, locked.Close())
	svc, err = serviceDefinition.prepare()
	require.NoError(t, err)
	require.NoError(t, svc.Close())
}

func TestServiceCloseReleasesRecordingLock(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	serviceDefinition := &Service{Configuration: conf, Version: serviceTestVersion{}}
	svc, err := serviceDefinition.prepare()
	require.NoError(t, err)

	concurrent, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.Error(t, err)
	require.Nil(t, concurrent)
	require.NoError(t, svc.Close())
	require.NoError(t, svc.closeRecording(false))
	require.NoError(t, svc.closeRecording(false))

	reopened, err := serviceDefinition.prepare()
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
}

func TestPrepareRecordingFailsClosedOnWrongFormatMarker(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	recordingRoot := conf.Auditlogs[0].Recording.Directory
	require.NoError(t, os.Mkdir(recordingRoot, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(recordingRoot, sessionRecordingFormatMarker), []byte("unknown/v1\n"), 0o600))

	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.ErrorContains(t, err, "cannot open Recording repository of auditlog \"default\"")
	require.True(t, bferrors.Config.IsErr(err), "unexpected error type: %v", err)
	require.Nil(t, svc)
	requireRecordingFormat(t, recordingRoot, "unknown/v1\n")
}

func TestPrepareRecordingLaterFailureReleasesEarlierRepositoryLock(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	second := conf.Auditlogs[0]
	second.Name = "second"
	second.IdentityFile = filepath.Join(root, "audit-second", "identity")
	second.Journal.Directory = filepath.Join(root, "audit-second", "journal")
	second.Recording.Directory = filepath.Join(root, "recording-second")
	conf.Auditlogs = append(conf.Auditlogs, second)
	secondIdentity, err := audit.EnsureIdentity(&conf.Auditlogs[1])
	require.NoError(t, err)
	lockedSecond, err := recording.NewLocalNativeRecordingRepository(context.Background(), conf.Auditlogs[1].Recording.Directory, secondIdentity, nil, recording.NativeRecordingVerifyOptions{}, recording.LocalRepositoryOptions{
		MaximumSpoolBytes: conf.Auditlogs[1].Recording.MaximumSpoolBytes,
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, lockedSecond.Close()) }()

	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.ErrorContains(t, err, "cannot open Recording repository of auditlog \"second\"")
	require.Nil(t, svc)
	firstIdentity, identityErr := audit.EnsureIdentity(&conf.Auditlogs[0])
	require.NoError(t, identityErr)
	firstRepository, openErr := recording.NewLocalNativeRecordingRepository(context.Background(), conf.Auditlogs[0].Recording.Directory, firstIdentity, nil, recording.NativeRecordingVerifyOptions{}, recording.LocalRepositoryOptions{
		MaximumSpoolBytes: conf.Auditlogs[0].Recording.MaximumSpoolBytes,
	})
	require.NoError(t, openErr, "the first repository lock must be released when the second open fails")
	require.NoError(t, firstRepository.Close())
}

func TestPrepareRecordingRecoversActiveBCastAsIncomplete(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	identity, err := audit.EnsureIdentity(&conf.Auditlogs[0])
	require.NoError(t, err)
	repository, err := newSessionRecordingRepository(t.Context(), conf.Auditlogs[0].Recording, identity, bfcrypto.PublicKeys(""), conf.Auditlogs[0].Name, nil)
	require.NoError(t, err)
	startedAt := time.Now().UTC().Truncate(time.Second)
	recordingId, err := recording.NewId()
	require.NoError(t, err)
	connectionId, err := bfconnection.NewId()
	require.NoError(t, err)
	sessionId, err := session.NewId()
	require.NoError(t, err)
	header := recording.CastHeader{
		Version:   3,
		Terminal:  recording.CastTerminal{Columns: 80, Rows: 24, Type: "xterm"},
		Timestamp: startedAt.Unix(),
	}
	metadata := recording.CastMetadata{
		RecordingId:  recordingId,
		ConnectionId: connectionId,
		SessionId:    sessionId,
		OperationId:  uuid.New(),
		Flow:         conf.Flows[0].Name,
		Task:         audit.SessionTaskShell,
		Pty:          true,
		ProducerId:   identity.ProducerId(),
		StartedAt:    startedAt,
	}
	fileName, err := repository.artifactName(recordingId)
	require.NoError(t, err)
	startedEvent := sessionRecordingAuditEvent(metadata, audit.EventNameSessionRecordingStarted, "", "", nil, 0, nil, nil)
	require.NoError(t, repository.receipts.BeginLifecycle(t.Context(), fileName, startedAt, startedEvent))
	active, err := repository.createActive(context.Background(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, recording.OutputStreamTerminal, []byte("interrupted\r\n")))
	require.NoError(t, repository.Close())

	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	recoveries := svc.recordingRepositories[configuration.DefaultAuditlogName].startupRecoveries()
	require.Len(t, recoveries, 1)
	require.Equal(t, recordingId, recoveries[0].recordingId)
	require.Equal(t, recording.CastStatusIncomplete, recoveries[0].status)
	require.False(t, recoveries[0].alreadySealed)
	require.NoError(t, svc.Close())
}

func TestSessionRecordingLifecycleStartupRecoveryCreatesIncompleteEvent(t *testing.T) {
	for _, test := range []struct {
		name      string
		encrypted bool
	}{
		{name: "BCast"},
		{name: "BECast without recipient private key", encrypted: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			conf := sessionRecordingTestConfiguration(t, root)
			enableSessionRecording(&conf.Auditlogs[0])
			identity, err := audit.EnsureIdentity(&conf.Auditlogs[0])
			require.NoError(t, err)
			var encryptionPublicKey bfcrypto.PublicKeys
			if test.encrypted {
				encryptionPublicKey = sessionRecordingEncryptionPublicKey(t)
			}
			repository, err := newSessionRecordingRepository(t.Context(), conf.Auditlogs[0].Recording, identity, encryptionPublicKey, conf.Auditlogs[0].Name, nil)
			require.NoError(t, err)
			startedAt := time.Now().UTC().Add(-time.Second)
			recordingId, err := recording.NewId()
			require.NoError(t, err)
			connectionId, err := bfconnection.NewId()
			require.NoError(t, err)
			sessionId, err := session.NewId()
			require.NoError(t, err)
			metadata := recording.CastMetadata{
				RecordingId:  recordingId,
				ConnectionId: connectionId,
				SessionId:    sessionId,
				OperationId:  uuid.New(),
				Flow:         conf.Flows[0].Name,
				Task:         audit.SessionTaskShell,
				Pty:          true,
				ProducerId:   identity.ProducerId(),
				StartedAt:    startedAt,
			}
			fileName, err := repository.artifactName(recordingId)
			require.NoError(t, err)
			startedEvent := sessionRecordingAuditEvent(metadata, audit.EventNameSessionRecordingStarted, "", "", nil, 0, nil, nil)
			require.NoError(t, repository.receipts.BeginLifecycle(t.Context(), fileName, startedAt, startedEvent))
			active, err := repository.createActive(t.Context(), recording.CastHeader{
				Version:   recording.CastVersion,
				Terminal:  recording.CastTerminal{Columns: 80, Rows: 24, Type: "xterm"},
				Timestamp: startedAt.Unix(),
			}, metadata, 300)
			require.NoError(t, err)
			require.NoError(t, active.WriteOutput(time.Second, recording.OutputStreamTerminal, []byte("interrupted\r\n")))
			stagedEvent := sessionRecordingAuditEvent(metadata, audit.EventNameSessionRecordingCompleted, audit.EventOutcomeSuccess, "", nil, time.Second, nil, commonUint32(0))
			require.NoError(t, repository.receipts.StageLifecycle(t.Context(), fileName, stagedEvent))
			require.NoError(t, repository.Close())

			restarted, err := newSessionRecordingRepository(t.Context(), conf.Auditlogs[0].Recording, identity, encryptionPublicKey, conf.Auditlogs[0].Name, nil)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, restarted.Close()) })
			recoveries := restarted.startupRecoveries()
			require.Len(t, recoveries, 1)
			require.Equal(t, recording.CastStatusIncomplete, recoveries[0].status)
			require.False(t, recoveries[0].alreadySealed)
			pending, err := restarted.receipts.PendingLifecycle(t.Context())
			require.NoError(t, err)
			require.Len(t, pending, 1)
			event := pending[0].Event
			require.Equal(t, audit.EventNameSessionRecordingIncomplete, event.Name)
			require.Equal(t, audit.EventOutcomeFailure, event.Outcome)
			require.Equal(t, audit.EventReasonStartupRecovery, event.Reason)
			require.Equal(t, metadata.Flow.String(), event.Flow)
			require.Equal(t, metadata.ConnectionId.String(), event.ConnectionId)
			require.Equal(t, metadata.SessionId.String(), event.SessionId)
			require.Equal(t, metadata.OperationId.String(), event.OperationId)
			require.Equal(t, metadata.RecordingId.String(), event.RecordingId)
			require.NotNil(t, event.DurationMillis)
			artifact, err := restarted.OpenSealedArtifact(t.Context(), fileName)
			require.NoError(t, err)
			remote, err := artifact.RemoteArtifact()
			require.NoError(t, err)
			require.Equal(t, remote.Digest(), pending[0].ArtifactDigest)
			require.Equal(t, recoveries[0].digest.String(), event.RecordingDigest)
			require.NotEqual(t, remote.Digest().String(), event.RecordingDigest)
			require.NoError(t, artifact.Close())
		})
	}
}

func sessionRecordingTestConfiguration(t *testing.T, root string) configuration.Configuration {
	t.Helper()
	var conf configuration.Configuration
	err := conf.LoadFromYaml(strings.NewReader(fmt.Sprintf(`
ssh:
  addresses: ["127.0.0.1:0"]
  keys:
    hostKeys: ["%s"]
  banner: ""
session:
  type: fs
  storage: "%s"
flows:
  - name: recording-test
    authorization:
      type: none
    environment:
      type: dummy
`, filepath.ToSlash(filepath.Join(root, "ssh", "host-key")), filepath.ToSlash(filepath.Join(root, "session-storage")))), "session-recording-test.yaml")
	require.NoError(t, err)
	auditlog := &conf.Auditlogs[0]
	auditlog.Enabled = true
	auditlog.IdentityFile = filepath.Join(root, "audit", "identity")
	auditlog.Journal.Directory = filepath.Join(root, "audit", "journal")
	auditlog.Recording.Directory = filepath.Join(root, "recording-storage")
	return conf
}

func enableSessionRecording(auditlog *configuration.Auditlog) {
	auditlog.Recording.Enabled = true
}

func sessionRecordingEncryptionPublicKey(t *testing.T) bfcrypto.PublicKeys {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPublicKey, err := gossh.NewPublicKey(publicKey)
	require.NoError(t, err)
	return bfcrypto.PublicKeys(strings.TrimSpace(string(gossh.MarshalAuthorizedKey(sshPublicKey))))
}

func requireRecordingFormat(t *testing.T, root, expected string) {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(root, sessionRecordingFormatMarker))
	require.NoError(t, err)
	require.Equal(t, expected, string(payload))
}
