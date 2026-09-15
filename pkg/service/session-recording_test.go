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

func TestPrepareRecordingOpensCastZstdRepository(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])

	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	repository := svc.recordingRepositories[configuration.DefaultAuditlogName]
	require.NotNil(t, repository)
	require.Equal(t, sessionRecordingRepositoryFormatCastZstd, repository.format)
	require.NotNil(t, repository.castZstd)
	require.Nil(t, repository.becast)
	require.Equal(t, []configuration.AuditlogName{configuration.DefaultAuditlogName}, svc.recordingRepositoryOrder)
	requireRecordingFormat(t, conf.Auditlogs[0].Recording.Directory, "cast-zstd/v1\n")
	require.NoError(t, svc.Close())
}

func TestPrepareRecordingOpensBECastWithoutZstdFallback(t *testing.T) {
	t.Run("opens BECast", func(t *testing.T) {
		root := t.TempDir()
		conf := sessionRecordingTestConfiguration(t, root)
		enableSessionRecording(&conf.Auditlogs[0])
		conf.Auditlogs[0].EncryptionPublicKey = sessionRecordingEncryptionPublicKey(t)

		svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
		require.NoError(t, err)
		repository := svc.recordingRepositories[configuration.DefaultAuditlogName]
		require.NotNil(t, repository)
		require.Equal(t, sessionRecordingRepositoryFormatBECast, repository.format)
		require.Nil(t, repository.castZstd)
		require.NotNil(t, repository.becast)
		requireRecordingFormat(t, conf.Auditlogs[0].Recording.Directory, "becast/v1\n")
		require.NoError(t, svc.Close())
	})

	t.Run("rejects an existing Zstd repository", func(t *testing.T) {
		root := t.TempDir()
		conf := sessionRecordingTestConfiguration(t, root)
		enableSessionRecording(&conf.Auditlogs[0])
		identity, err := audit.EnsureIdentity(&conf.Auditlogs[0])
		require.NoError(t, err)
		zstdRepository, err := recording.NewLocalCastZstdRepository(context.Background(), conf.Auditlogs[0].Recording.Directory, identity, recording.CastZstdVerifyOptions{})
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
		{name: "Cast Zstandard", suffix: ".cast.zst"},
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
			repository, err := newSessionRecordingRepository(t.Context(), conf.Auditlogs[0].Recording.Directory, identity, encryptionPublicKey)
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
			active, err := repository.createActive(t.Context(), header, metadata, 300)
			require.NoError(t, err)
			require.NoError(t, active.WriteOutput(time.Second, recording.OutputStreamTerminal, []byte("adapter output\r\n")))
			require.NoError(t, active.Checkpoint())
			exitStatus := uint32(7)
			require.NoError(t, active.Seal(2*time.Second, recording.CastResult{
				Status:  recording.CastStatusCompleted,
				EndedAt: startedAt.Add(2 * time.Second),
			}, &exitStatus))
			require.NoError(t, active.Close())

			sealedPath := filepath.Join(conf.Auditlogs[0].Recording.Directory, "sealed", recordingId.String()+test.suffix)
			file, err := os.Open(sealedPath)
			require.NoError(t, err)
			info, err := file.Stat()
			require.NoError(t, err)
			if test.encrypted {
				verification, verifyErr := recording.VerifyBECast(file, info.Size(), recording.BECastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
				require.NoError(t, verifyErr)
				require.Equal(t, recording.CastStatusCompleted, verification.Summary.Status)
			} else {
				verification, verifyErr := recording.VerifyCastZstd(file, info.Size(), recording.CastZstdVerifyOptions{ExpectedProducerId: identity.ProducerId()})
				require.NoError(t, verifyErr)
				require.Equal(t, recording.CastStatusCompleted, verification.Summary.Status)
			}
			require.NoError(t, file.Close())
		})
	}
}

func TestPrepareRecordingFailsClosedOnExistingRepositoryLockAndCanRetry(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	identity, err := audit.EnsureIdentity(&conf.Auditlogs[0])
	require.NoError(t, err)
	locked, err := recording.NewLocalCastZstdRepository(context.Background(), conf.Auditlogs[0].Recording.Directory, identity, recording.CastZstdVerifyOptions{})
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
	require.NoError(t, svc.closeRecordingRepositories())
	require.NoError(t, svc.closeRecordingRepositories())

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
	require.NoError(t, os.WriteFile(filepath.Join(recordingRoot, sessionRecordingFormatMarker), []byte("unknown/v1\n"), 0o400))

	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.ErrorContains(t, err, "cannot open Recording repository of auditlog \"default\"")
	require.True(t, bferrors.Config.IsErr(err))
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
	lockedSecond, err := recording.NewLocalCastZstdRepository(context.Background(), conf.Auditlogs[1].Recording.Directory, secondIdentity, recording.CastZstdVerifyOptions{})
	require.NoError(t, err)
	defer func() { require.NoError(t, lockedSecond.Close()) }()

	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.ErrorContains(t, err, "cannot open Recording repository of auditlog \"second\"")
	require.Nil(t, svc)
	firstIdentity, identityErr := audit.EnsureIdentity(&conf.Auditlogs[0])
	require.NoError(t, identityErr)
	firstRepository, openErr := recording.NewLocalCastZstdRepository(context.Background(), conf.Auditlogs[0].Recording.Directory, firstIdentity, recording.CastZstdVerifyOptions{})
	require.NoError(t, openErr, "the first repository lock must be released when the second open fails")
	require.NoError(t, firstRepository.Close())
}

func TestPrepareRecordingRecoversActiveCastZstdAsIncomplete(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	identity, err := audit.EnsureIdentity(&conf.Auditlogs[0])
	require.NoError(t, err)
	repository, err := recording.NewLocalCastZstdRepository(context.Background(), conf.Auditlogs[0].Recording.Directory, identity, recording.CastZstdVerifyOptions{})
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
	active, err := repository.CreateActive(context.Background(), header, metadata, 300)
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
