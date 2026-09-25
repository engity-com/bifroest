package service

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
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
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

func recordingOnlyConfiguration(t *testing.T, root string) configuration.Configuration {
	t.Helper()
	conf := sessionRecordingTestConfiguration(t, root)
	conf.Auditlogs[0].Enabled = false
	conf.Auditlogs[0].Recording.Enabled = true
	return conf
}

func requireRecordingOnlyState(t *testing.T, conf configuration.Configuration) {
	t.Helper()
	require.NoDirExists(t, conf.Auditlogs[0].Directory)
	require.NoError(t, filepath.WalkDir(conf.Auditlogs[0].Recording.Directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(entry.Name(), "receipt.lifecycle") {
			t.Errorf("unexpected audit lifecycle state: %s", path)
		}
		if entry.Name() == "receipt.json" {
			payload, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			require.Contains(t, string(payload), `"unaudited":true`)
		}
		return nil
	}))
}

func TestRecordingOnlyShellExecAndRestart(t *testing.T) {
	for _, task := range []string{"shell", "exec"} {
		t.Run(task, func(t *testing.T) {
			root := t.TempDir()
			server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
				_, err := task.SshSession().Write([]byte("recorded output"))
				return 0, err
			}}, func(conf *configuration.Configuration) {
				conf.Auditlogs[0].Enabled = false
				conf.Auditlogs[0].Recording.Enabled = true
				conf.Auditlogs[0].IdentityFile = filepath.Join(root, "identity")
				conf.Auditlogs[0].Directory = filepath.Join(root, "journal")
				conf.Auditlogs[0].Recording.Directory = filepath.Join(root, "recordings")
			})
			name := server.service.Configuration.Auditlogs[0].Name
			require.NotNil(t, server.service.auditIdentities[name])
			require.NotNil(t, server.service.recordingRepositories[name])
			spy := &recordingAuditRecorder{}
			server.service.flowAuditRecorders[server.service.Configuration.Flows[0].Name] = spy
			client := server.mustDial(t)
			sshSession, err := client.NewSession()
			require.NoError(t, err)
			var output bytes.Buffer
			sshSession.Stdout = &output
			if task == "shell" {
				require.NoError(t, sshSession.Shell())
				err = sshSession.Wait()
			} else {
				err = sshSession.Run("capture")
			}
			require.NoError(t, err)
			require.Contains(t, output.String(), "recorded output")
			verification := verifyOnlySessionRecording(t, server.service, root)
			require.Equal(t, recording.CastStatusCompleted, verification.Cast.Result.Status)
			pending, err := server.service.recordingRepositories[name].receipts.PendingLifecycle(t.Context())
			require.NoError(t, err)
			require.Empty(t, pending)
			for _, event := range spy.eventsSnapshot() {
				require.NotContains(t, event.Name, "recording")
			}
			requireRecordingOnlyState(t, server.service.Configuration)

			// Close the original service before reopening its exclusive repository lock.
			require.NoError(t, server.service.Close())
			restarted, err := (&Service{Configuration: server.service.Configuration, Version: serviceTestVersion{}}).prepare()
			require.NoError(t, err)
			require.Len(t, restarted.recordingRepositories[name].startupRecoveries(), 0)
			require.NoError(t, restarted.Close())
			requireRecordingOnlyState(t, server.service.Configuration)
		})
	}
}

func TestRecordingOnlyEncryptedRecoveryAndIdentityLoss(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%t", encrypted), func(t *testing.T) {
			root := t.TempDir()
			conf := recordingOnlyConfiguration(t, root)
			if encrypted {
				conf.Auditlogs[0].EncryptionPublicKey = sessionRecordingEncryptionPublicKey(t)
			}
			first, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
			require.NoError(t, err)
			repository := first.recordingRepositories[conf.Auditlogs[0].Name]
			require.False(t, repository.audited)
			marker := "bcast-recording-only/v1\n"
			if encrypted {
				marker = "becast-cbor-recording-only/v1\n"
			}
			requireRecordingFormat(t, conf.Auditlogs[0].Recording.Directory, marker)
			// The helper stages events only for audited repositories; unaudited
			// lifecycle calls are inert, including across an interrupted seal.
			fileName := sealRemoteDeliveryTestRecordingOnly(t, first, conf)
			require.NoError(t, first.Close())
			restarted, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
			require.NoError(t, err)
			artifact, err := restarted.recordingRepositories[conf.Auditlogs[0].Name].OpenSealedArtifact(t.Context(), fileName)
			require.NoError(t, err)
			require.NoError(t, artifact.Close())
			require.NoError(t, restarted.Close())
			requireRecordingOnlyState(t, conf)

			require.NoError(t, os.Remove(conf.Auditlogs[0].IdentityFile))
			missing, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
			require.Nil(t, missing)
			require.ErrorContains(t, err, "Recording directory")
			require.NoFileExists(t, conf.Auditlogs[0].IdentityFile)
		})
	}
}

func TestRecordingOnlyRecoversActiveWithoutLifecycleReplay(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%t", encrypted), func(t *testing.T) {
			root := t.TempDir()
			conf := recordingOnlyConfiguration(t, root)
			if encrypted {
				conf.Auditlogs[0].EncryptionPublicKey = sessionRecordingEncryptionPublicKey(t)
			}
			first, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
			require.NoError(t, err)
			repository := first.recordingRepositories[conf.Auditlogs[0].Name]
			id, err := recording.NewId()
			require.NoError(t, err)
			connectionId, err := bfconnection.NewId()
			require.NoError(t, err)
			sessionId, err := session.NewId()
			require.NoError(t, err)
			startedAt := time.Now().UTC().Add(-time.Second)
			active, err := repository.createActive(t.Context(), recording.CastHeader{
				Version: recording.CastVersion, Terminal: recording.CastTerminal{Columns: 80, Rows: 24}, Timestamp: startedAt.Unix(),
			}, recording.CastMetadata{
				RecordingId: id, ConnectionId: connectionId, SessionId: sessionId, OperationId: uuid.New(),
				Flow: conf.Flows[0].Name, Task: audit.SessionTaskShell, Pty: true, ProducerId: repository.producerId, StartedAt: startedAt,
			}, 300)
			require.NoError(t, err)
			require.NoError(t, active.WriteOutput(time.Millisecond, recording.OutputStreamTerminal, []byte("recover me")))
			require.NoError(t, first.Close())

			restarted, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
			require.NoError(t, err)
			recoveries := restarted.recordingRepositories[conf.Auditlogs[0].Name].startupRecoveries()
			require.Len(t, recoveries, 1)
			require.Equal(t, id, recoveries[0].recordingId)
			require.Equal(t, recording.CastStatusIncomplete, recoveries[0].status)
			name, err := restarted.recordingRepositories[conf.Auditlogs[0].Name].artifactName(id)
			require.NoError(t, err)
			artifact, err := restarted.recordingRepositories[conf.Auditlogs[0].Name].OpenSealedArtifact(t.Context(), name)
			require.NoError(t, err)
			require.NoError(t, artifact.Close())
			pending, err := restarted.recordingRepositories[conf.Auditlogs[0].Name].receipts.PendingLifecycle(t.Context())
			require.NoError(t, err)
			require.Empty(t, pending)
			requireRecordingOnlyState(t, conf)
			require.NoError(t, restarted.Close())
		})
	}
}

func sealRemoteDeliveryTestRecordingOnly(t *testing.T, svc *service, conf configuration.Configuration) string {
	t.Helper()
	repository := svc.recordingRepositories[conf.Auditlogs[0].Name]
	id, err := recording.NewId()
	require.NoError(t, err)
	connectionId, err := bfconnection.NewId()
	require.NoError(t, err)
	sessionId, err := session.NewId()
	require.NoError(t, err)
	startedAt := time.Now().UTC().Truncate(time.Second)
	metadata := recording.CastMetadata{
		RecordingId: id, ConnectionId: connectionId, SessionId: sessionId, OperationId: uuid.New(),
		Flow: conf.Flows[0].Name, Task: audit.SessionTaskExec, ProducerId: repository.producerId, StartedAt: startedAt,
	}
	active, err := repository.createActive(t.Context(), recording.CastHeader{
		Version: recording.CastVersion, Terminal: recording.CastTerminal{Columns: 80, Rows: 24}, Timestamp: startedAt.Unix(),
	}, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, recording.OutputStreamStdout, []byte("recorded\n")))
	exitCode := uint32(0)
	_, err = active.Seal(2*time.Second, recording.CastResult{Status: recording.CastStatusCompleted, EndedAt: startedAt.Add(2 * time.Second)}, &exitCode)
	require.NoError(t, err)
	require.NoError(t, active.Close())
	name, err := repository.artifactName(id)
	require.NoError(t, err)
	artifact, err := repository.OpenSealedArtifact(t.Context(), name)
	require.NoError(t, err)
	remote, err := artifact.RemoteArtifact()
	require.NoError(t, err)
	require.NoError(t, repository.receipts.Require(t.Context(), remote))
	require.NoError(t, artifact.Close())
	return name
}

func TestRecordingOnlyRemoteAckAndRetention(t *testing.T) {
	root := t.TempDir()
	conf := recordingOnlyConfiguration(t, root)
	conf.Auditlogs[0].Recording.RetainFor.SetNative(time.Hour)
	target := &serviceRemoteDeliveryTestTarget{publishedArtifact: make(chan string, 1)}
	conf.Auditlogs[0].Recording.Targets.Mode = configuration.AuditlogRecordingTargetsModeCustom
	conf.Auditlogs[0].Recording.Targets.Targets = configuration.AuditlogTargets{{Name: "archive", V: &serviceRemoteDeliveryTestConfiguration{target: target}}}
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	defer func() { require.NoError(t, svc.Close()) }()
	spy := &recordingAuditRecorder{}
	svc.auditRecorders[conf.Auditlogs[0].Name] = spy
	name := sealRemoteDeliveryTestRecordingOnly(t, svc, conf)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, svc.recordingDeliveries[conf.Auditlogs[0].Name].Flush(ctx))
	require.Equal(t, name, <-target.publishedArtifact)
	requireRecordingOnlyState(t, conf)
	cutoff := time.Now().UTC().Add(2 * time.Hour)
	require.NoError(t, svc.houseKeeper.cleanupRecordings(svc.houseKeeper.logger(), t.Context(), cutoff))
	_, err = svc.recordingRepositories[conf.Auditlogs[0].Name].OpenSealedArtifact(t.Context(), name)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Empty(t, spy.eventsSnapshot())
	requireRecordingOnlyState(t, conf)
}

func TestRecordingOnlyRejectsModeSwitchWithSealedState(t *testing.T) {
	root := t.TempDir()
	conf := recordingOnlyConfiguration(t, root)
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	sealRemoteDeliveryTestRecordingOnly(t, svc, conf)
	require.NoError(t, svc.Close())
	conf.Auditlogs[0].Enabled = true
	changed, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.Nil(t, changed)
	require.Error(t, err)
	require.NoDirExists(t, conf.Auditlogs[0].Directory)
}

func TestRecordingOnlyRejectsModeSwitchWithEmptyRepository(t *testing.T) {
	root := t.TempDir()
	conf := recordingOnlyConfiguration(t, root)
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	require.NoError(t, svc.Close())
	conf.Auditlogs[0].Enabled = true
	changed, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.Nil(t, changed)
	require.Error(t, err)
	require.NoDirExists(t, conf.Auditlogs[0].Directory)
}

func TestRecordingOnlyRejectsModeSwitchWithActiveState(t *testing.T) {
	root := t.TempDir()
	conf := recordingOnlyConfiguration(t, root)
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	repository := svc.recordingRepositories[conf.Auditlogs[0].Name]
	id, err := recording.NewId()
	require.NoError(t, err)
	connectionId, err := bfconnection.NewId()
	require.NoError(t, err)
	sessionId, err := session.NewId()
	require.NoError(t, err)
	now := time.Now().UTC()
	active, err := repository.createActive(t.Context(), recording.CastHeader{
		Version: recording.CastVersion, Terminal: recording.CastTerminal{Columns: 80, Rows: 24}, Timestamp: now.Unix(),
	}, recording.CastMetadata{
		RecordingId: id, ConnectionId: connectionId, SessionId: sessionId, OperationId: uuid.New(),
		Flow: conf.Flows[0].Name, Task: audit.SessionTaskExec, ProducerId: repository.producerId, StartedAt: now,
	}, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Millisecond, recording.OutputStreamStdout, []byte("active")))
	require.NoError(t, svc.Close())
	conf.Auditlogs[0].Enabled = true
	changed, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.Nil(t, changed)
	require.Error(t, err)
	require.NoDirExists(t, conf.Auditlogs[0].Directory)
}

func TestRecordingOnlyCanShareAnotherAuditlogJournalDirectory(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	first := conf.Auditlogs[0]
	second := first
	second.Name = "recording-only"
	second.Enabled = false
	second.Recording.Enabled = true
	second.IdentityFile = filepath.Join(root, "recording-only-key")
	second.Recording.Directory = filepath.Join(root, "recording-only-repository")
	conf.Auditlogs = append(conf.Auditlogs, second)

	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	defer func() { require.NoError(t, svc.Close()) }()
	require.FileExists(t, second.IdentityFile)
	require.NotNil(t, svc.recordingRepositories[second.Name])
	require.NotEqual(t, svc.auditIdentities[first.Name].ProducerId(), svc.auditIdentities[second.Name].ProducerId())
	require.NoDirExists(t, filepath.Join(first.Directory, svc.auditIdentities[second.Name].ProducerId().String()))
}

func TestRecordingOnlyFailurePolicies(t *testing.T) {
	for _, policy := range []configuration.AuditlogFailurePolicy{configuration.AuditlogFailurePolicyStrict, configuration.AuditlogFailurePolicyBestEffort} {
		t.Run(string(policy), func(t *testing.T) {
			root := t.TempDir()
			conf := recordingOnlyConfiguration(t, root)
			conf.Auditlogs[0].FailurePolicy = policy
			// A pre-existing Recording directory must not be silently replaced
			// when its signing identity has disappeared.
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

func TestRecordingOnlyRuntimePathsProtectActiveKeysAndStorage(t *testing.T) {
	for _, test := range []struct {
		name      string
		change    func(*configuration.Configuration, string)
		errorPart string
	}{
		{"identity in session storage", func(conf *configuration.Configuration, root string) {
			conf.Auditlogs[0].IdentityFile = filepath.Join(root, "session-storage", "identity")
		}, "identity file"},
		{"recording in session storage", func(conf *configuration.Configuration, root string) {
			conf.Auditlogs[0].Recording.Directory = filepath.Join(root, "session-storage", "recordings")
		}, "recording directory"},
		{"identity in recording", func(conf *configuration.Configuration, root string) {
			conf.Auditlogs[0].IdentityFile = filepath.Join(root, "recording-storage", "identity")
		}, "identity file"},
		{"recipient in recording", func(conf *configuration.Configuration, root string) {
			conf.Auditlogs[0].EncryptionPublicKeyFile = crypto.PublicKeysFile(filepath.Join(root, "recording-storage", "recipient.pub"))
		}, "encryption public key file"},
		{"host key in recording", func(conf *configuration.Configuration, root string) {
			conf.Auditlogs[0].Recording.Directory = filepath.Join(root, "ssh")
		}, "SSH host key"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			conf := recordingOnlyConfiguration(t, root)
			test.change(&conf, root)
			require.ErrorContains(t, validateRuntimePaths(&conf), test.errorPart)
		})
	}
}

func TestRecordingOnlyRejectsSigningIdentityAsEncryptionRecipient(t *testing.T) {
	root := t.TempDir()
	conf := recordingOnlyConfiguration(t, root)
	first, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	identity := first.auditIdentities[conf.Auditlogs[0].Name]
	require.NoError(t, first.Close())
	conf.Auditlogs[0].EncryptionPublicKey = crypto.PublicKeys(strings.TrimSpace(string(gossh.MarshalAuthorizedKey(identity.PublicKey().ToSsh()))))
	restarted, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.Nil(t, restarted)
	require.ErrorContains(t, err, "encryption")
	requireRecordingFormat(t, conf.Auditlogs[0].Recording.Directory, "bcast-recording-only/v1\n")
	require.NoDirExists(t, conf.Auditlogs[0].Directory)
}

func TestRecordingOnlyRetentionPreservesUnacknowledgedAndBrokenReceipts(t *testing.T) {
	root := t.TempDir()
	conf := recordingOnlyConfiguration(t, root)
	conf.Auditlogs[0].Recording.RetainFor.SetNative(time.Nanosecond)
	gate := make(chan struct{})
	target := &serviceRemoteDeliveryTestTarget{artifactStarted: make(chan struct{}, 1), artifactGate: gate, publishedArtifact: make(chan string, 1)}
	conf.Auditlogs[0].Recording.Targets.Mode = configuration.AuditlogRecordingTargetsModeCustom
	conf.Auditlogs[0].Recording.Targets.Targets = configuration.AuditlogTargets{{Name: "archive", V: &serviceRemoteDeliveryTestConfiguration{target: target}}}
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	defer func() {
		select {
		case <-gate:
		default:
			close(gate)
		}
		require.NoError(t, svc.Close())
	}()
	name := sealRemoteDeliveryTestRecordingOnly(t, svc, conf)
	select {
	case <-target.artifactStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("Recording delivery did not start")
	}
	repository := svc.recordingRepositories[conf.Auditlogs[0].Name]
	cutoff := time.Now().UTC().Add(time.Hour)
	require.NoError(t, svc.houseKeeper.cleanupRecordings(svc.houseKeeper.logger(), t.Context(), cutoff))
	artifact, err := repository.OpenSealedArtifact(t.Context(), name)
	require.NoError(t, err)
	require.NoError(t, artifact.Close())
	close(gate)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, svc.recordingDeliveries[conf.Auditlogs[0].Name].Flush(ctx))
	require.Equal(t, name, <-target.publishedArtifact)
	// Tampering must not cause an unverified artifact to be deleted.
	path := filepath.Join(conf.Auditlogs[0].Recording.Directory, "sealed", name)
	require.NoError(t, os.WriteFile(path, []byte("corrupted"), 0o600))
	require.NoError(t, svc.houseKeeper.cleanupRecordings(svc.houseKeeper.logger(), t.Context(), cutoff))
	require.FileExists(t, path)
	requireRecordingOnlyState(t, conf)
}
