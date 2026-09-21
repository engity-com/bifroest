package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfconnection "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

var _ = audit.RegisterRemoteTarget(
	func() configuration.AuditlogTargetV { return &serviceRemoteDeliveryTestConfiguration{} },
	func(_ context.Context, _ audit.RemoteTargetScope, conf *serviceRemoteDeliveryTestConfiguration) (audit.RemoteTarget, audit.RemoteTargetSettings, error) {
		target := conf.target
		if conf.newTarget != nil {
			target = conf.newTarget()
		}
		return target, audit.RemoteTargetSettings{DestinationIdentity: "service-test-destination", PublishAttemptTimeout: time.Minute}, nil
	},
)

type serviceRemoteDeliveryTestConfiguration struct {
	target    audit.RemoteTarget
	newTarget func() audit.RemoteTarget
}

func (this *serviceRemoteDeliveryTestConfiguration) SetDefaults() error { return nil }
func (this *serviceRemoteDeliveryTestConfiguration) Trim() error        { return this.Validate() }
func (this *serviceRemoteDeliveryTestConfiguration) Validate() error {
	if this == nil || this.target == nil && this.newTarget == nil {
		return fmt.Errorf("missing service delivery test target")
	}
	return nil
}
func (*serviceRemoteDeliveryTestConfiguration) UnmarshalYAML(*yaml.Node) error { return nil }
func (*serviceRemoteDeliveryTestConfiguration) IsEqualTo(other any) bool {
	_, ok := other.(*serviceRemoteDeliveryTestConfiguration)
	return ok
}
func (*serviceRemoteDeliveryTestConfiguration) Types() []string {
	return []string{"service-runtime-test"}
}
func (*serviceRemoteDeliveryTestConfiguration) FeatureFlags() []string { return nil }

type serviceRemoteDeliveryTestTarget struct {
	published         chan uint64
	publishedArtifact chan string
	artifactStarted   chan struct{}
	artifactGate      <-chan struct{}
	artifactFailures  atomic.Int32
	closed            atomic.Bool
	closeErr          error
}

func (this *serviceRemoteDeliveryTestTarget) Publish(_ context.Context, segment audit.SealedSegment) error {
	this.published <- segment.Sequence()
	return nil
}

func (this *serviceRemoteDeliveryTestTarget) PublishArtifact(ctx context.Context, artifact audit.RemoteArtifact) error {
	if err := artifact.ValidateContext(ctx); err != nil {
		return err
	}
	if this.artifactStarted != nil {
		this.artifactStarted <- struct{}{}
	}
	for remaining := this.artifactFailures.Load(); remaining > 0; remaining = this.artifactFailures.Load() {
		if this.artifactFailures.CompareAndSwap(remaining, remaining-1) {
			return fmt.Errorf("injected Recording artifact publication failure")
		}
	}
	if this.artifactGate != nil {
		select {
		case <-this.artifactGate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if this.publishedArtifact != nil {
		select {
		case this.publishedArtifact <- artifact.FileName():
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (this *serviceRemoteDeliveryTestTarget) Close() error {
	this.closed.Store(true)
	return this.closeErr
}

type serviceJournalOnlyTestTarget struct {
	closed atomic.Bool
}

func (*serviceJournalOnlyTestTarget) Publish(context.Context, audit.SealedSegment) error { return nil }
func (this *serviceJournalOnlyTestTarget) Close() error {
	this.closed.Store(true)
	return nil
}

func TestServiceShutdownSealsAndFlushesAuditTail(t *testing.T) {
	directory := t.TempDir()
	target := &serviceRemoteDeliveryTestTarget{published: make(chan uint64, 1)}
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		auditlog := &conf.Auditlogs[0]
		auditlog.Enabled = true
		auditlog.IdentityFile = filepath.Join(directory, "auditlog-key")
		auditlog.Journal.Directory = filepath.Join(directory, "auditlog")
		auditlog.Targets = configuration.AuditlogTargets{{
			Name: "archive",
			V:    &serviceRemoteDeliveryTestConfiguration{target: target},
		}}
	})
	recorder := server.service.auditRecorders[configuration.DefaultAuditlogName]
	require.NoError(t, recorder.Record(context.Background(), audit.Event{Name: "test.shutdown"}))
	require.NoError(t, server.stop())

	select {
	case sequence := <-target.published:
		require.Equal(t, uint64(1), sequence)
	case <-time.After(time.Second):
		t.Fatal("shutdown did not flush the sealed audit tail")
	}
	require.True(t, target.closed.Load())
}

func TestServiceDeliversSealedRecordingArtifacts(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%t", encrypted), func(t *testing.T) {
			root := t.TempDir()
			conf := sessionRecordingTestConfiguration(t, root)
			enableSessionRecording(&conf.Auditlogs[0])
			if encrypted {
				conf.Auditlogs[0].EncryptionPublicKey = sessionRecordingEncryptionPublicKey(t)
			}
			target := &serviceRemoteDeliveryTestTarget{publishedArtifact: make(chan string, 1)}
			conf.Auditlogs[0].Recording.Targets.Mode = configuration.AuditlogRecordingTargetsModeCustom
			conf.Auditlogs[0].Recording.Targets.Targets = configuration.AuditlogTargets{{
				Name: "recordings",
				V:    &serviceRemoteDeliveryTestConfiguration{target: target},
			}}

			svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
			require.NoError(t, err)
			defer func() { require.NoError(t, svc.Close()) }()
			name := sealRemoteDeliveryTestRecording(t, svc, conf)

			flushContext, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			require.NoError(t, svc.recordingDeliveries[configuration.DefaultAuditlogName].Flush(flushContext))
			require.Equal(t, name, <-target.publishedArtifact)
		})
	}
}

func TestServiceShutdownFlushesRecordingArtifacts(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	gate := make(chan struct{})
	target := &serviceRemoteDeliveryTestTarget{
		publishedArtifact: make(chan string, 1),
		artifactStarted:   make(chan struct{}, 2),
		artifactGate:      gate,
	}
	target.artifactFailures.Store(1)
	conf.Auditlogs[0].Recording.Targets.Mode = configuration.AuditlogRecordingTargetsModeCustom
	conf.Auditlogs[0].Recording.Targets.Targets = configuration.AuditlogTargets{{
		Name: "recordings",
		V:    &serviceRemoteDeliveryTestConfiguration{target: target},
	}}
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	name := sealRemoteDeliveryTestRecording(t, svc, conf)
	select {
	case <-target.artifactStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("initial Recording delivery attempt did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- svc.Close() }()
	select {
	case <-target.artifactStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown flush did not wake Recording delivery from failure backoff")
	}
	select {
	case err := <-closed:
		t.Fatalf("service shutdown completed before blocked Recording delivery: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(gate)
	require.NoError(t, <-closed)
	require.Equal(t, name, <-target.publishedArtifact)
	require.True(t, target.closed.Load())

	restartedTarget := &serviceRemoteDeliveryTestTarget{publishedArtifact: make(chan string, 1)}
	conf.Auditlogs[0].Recording.Targets.Targets[0].V = &serviceRemoteDeliveryTestConfiguration{target: restartedTarget}
	restarted, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	require.NoError(t, restarted.Close())
	select {
	case republished := <-restartedTarget.publishedArtifact:
		t.Fatalf("acknowledged Recording artifact was republished as %q", republished)
	default:
	}
}

func TestHouseKeeperDeletesAcknowledgedRecordingAfterRetentionAndAudits(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%t", encrypted), func(t *testing.T) {
			root := t.TempDir()
			conf := sessionRecordingTestConfiguration(t, root)
			enableSessionRecording(&conf.Auditlogs[0])
			conf.Auditlogs[0].Recording.RetainFor.SetNative(time.Hour)
			if encrypted {
				conf.Auditlogs[0].EncryptionPublicKey = sessionRecordingEncryptionPublicKey(t)
			}
			target := &serviceRemoteDeliveryTestTarget{publishedArtifact: make(chan string, 1)}
			conf.Auditlogs[0].Recording.Targets.Mode = configuration.AuditlogRecordingTargetsModeCustom
			conf.Auditlogs[0].Recording.Targets.Targets = configuration.AuditlogTargets{{
				Name: "recordings",
				V:    &serviceRemoteDeliveryTestConfiguration{target: target},
			}}
			svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
			require.NoError(t, err)
			defer func() { require.NoError(t, svc.Close()) }()
			name := sealRemoteDeliveryTestRecording(t, svc, conf)
			flushContext, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			require.NoError(t, svc.recordingDeliveries[configuration.DefaultAuditlogName].Flush(flushContext))
			require.Equal(t, name, <-target.publishedArtifact)

			repository := svc.recordingRepositories[configuration.DefaultAuditlogName]
			id, err := repository.recordingIdFromArtifactName(name)
			require.NoError(t, err)
			originalRecorder := svc.auditRecorders[configuration.DefaultAuditlogName]
			recorder := &recordingAuditRecorder{}
			svc.auditRecorders[configuration.DefaultAuditlogName] = recorder
			require.NoError(t, svc.houseKeeper.cleanupRecordings(svc.houseKeeper.logger(), t.Context(), time.Now().UTC().Add(2*time.Hour)))
			svc.auditRecorders[configuration.DefaultAuditlogName] = originalRecorder

			_, err = repository.OpenSealedArtifact(t.Context(), name)
			require.ErrorIs(t, err, os.ErrNotExist)
			candidates, err := repository.retentionCandidates(t.Context(), time.Now().UTC().Add(2*time.Hour))
			require.NoError(t, err)
			require.Empty(t, candidates)
			events := recorder.eventsSnapshot()
			require.Len(t, events, 2)
			require.Equal(t, audit.EventNameHousekeepingRecordingDeleteStarted, events[0].Name)
			require.Equal(t, audit.EventNameHousekeepingRecordingDeleteCompleted, events[1].Name)
			require.Equal(t, id.String(), events[0].RecordingId)
			require.Equal(t, events[0].OperationId, events[1].OperationId)
			require.Equal(t, audit.EventReasonRetentionElapsed, events[0].Reason)
			require.Equal(t, audit.EventOutcomeSuccess, events[1].Outcome)
		})
	}
}

func TestHouseKeeperContinuesRecordingRetentionAfterEarlierAuditlogStoreFailure(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	conf.Auditlogs[0].Recording.RetainFor.SetNative(time.Hour)
	working := conf.Auditlogs[0]
	broken := working
	broken.Name = "broken"
	broken.IdentityFile = filepath.Join(root, "audit-broken", "identity")
	broken.Journal.Directory = filepath.Join(root, "audit-broken", "journal")
	broken.Recording.Directory = filepath.Join(root, "recording-broken")
	conf.Auditlogs = configuration.Auditlogs{broken, working}

	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	brokenRepository := svc.recordingRepositories["broken"]
	brokenReceipts := brokenRepository.receipts
	brokenRepository.receipts = nil
	t.Cleanup(func() {
		brokenRepository.receipts = brokenReceipts
		require.NoError(t, svc.Close())
	})
	name := sealRemoteDeliveryTestRecording(t, svc, conf)

	err = svc.houseKeeper.cleanupRecordings(svc.houseKeeper.logger(), t.Context(), time.Now().UTC().Add(2*time.Hour))
	require.ErrorContains(t, err, "cannot inspect Recording retention of auditlog \"broken\"")
	_, err = svc.recordingRepositories[configuration.DefaultAuditlogName].OpenSealedArtifact(t.Context(), name)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestHouseKeeperPreservesRecordingWhenRetentionDisabled(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	conf.Auditlogs[0].Recording.RetainFor.SetNative(0)
	target := &serviceRemoteDeliveryTestTarget{publishedArtifact: make(chan string, 1)}
	conf.Auditlogs[0].Recording.Targets.Mode = configuration.AuditlogRecordingTargetsModeCustom
	conf.Auditlogs[0].Recording.Targets.Targets = configuration.AuditlogTargets{{
		Name: "recordings",
		V:    &serviceRemoteDeliveryTestConfiguration{target: target},
	}}
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	defer func() { require.NoError(t, svc.Close()) }()
	name := sealRemoteDeliveryTestRecording(t, svc, conf)
	flushContext, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, svc.recordingDeliveries[configuration.DefaultAuditlogName].Flush(flushContext))
	require.Equal(t, name, <-target.publishedArtifact)
	require.NoError(t, svc.houseKeeper.cleanupRecordings(svc.houseKeeper.logger(), t.Context(), time.Now().UTC().Add(100*365*24*time.Hour)))

	repository := svc.recordingRepositories[configuration.DefaultAuditlogName]
	artifact, err := repository.OpenSealedArtifact(t.Context(), name)
	require.NoError(t, err)
	require.NoError(t, artifact.Close())
	candidates, err := repository.retentionCandidates(t.Context(), time.Now().UTC().Add(100*365*24*time.Hour))
	require.NoError(t, err)
	require.Len(t, candidates, 1)
}

func TestHouseKeeperDeletesRecordingWithoutTargetsFromSealTime(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%t", encrypted), func(t *testing.T) {
			root := t.TempDir()
			conf := sessionRecordingTestConfiguration(t, root)
			enableSessionRecording(&conf.Auditlogs[0])
			conf.Auditlogs[0].Recording.RetainFor.SetNative(time.Hour)
			if encrypted {
				conf.Auditlogs[0].EncryptionPublicKey = sessionRecordingEncryptionPublicKey(t)
			}
			svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
			require.NoError(t, err)
			defer func() { require.NoError(t, svc.Close()) }()
			name := sealRemoteDeliveryTestRecording(t, svc, conf)
			require.NoError(t, svc.houseKeeper.cleanupRecordings(svc.houseKeeper.logger(), t.Context(), time.Now().UTC().Add(2*time.Hour)))
			_, err = svc.recordingRepositories[configuration.DefaultAuditlogName].OpenSealedArtifact(t.Context(), name)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestServiceRestartRejectsRemovedOutstandingRecordingTarget(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	target := &serviceRemoteDeliveryTestTarget{artifactStarted: make(chan struct{}, 1), artifactGate: make(chan struct{})}
	conf.Auditlogs[0].Recording.Targets.Mode = configuration.AuditlogRecordingTargetsModeCustom
	conf.Auditlogs[0].Recording.Targets.Targets = configuration.AuditlogTargets{{
		Name: "recordings",
		V:    &serviceRemoteDeliveryTestConfiguration{target: target},
	}}
	first, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	name := sealRemoteDeliveryTestRecording(t, first, conf)
	select {
	case <-target.artifactStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("Recording delivery did not start")
	}
	require.NoError(t, first.Close())

	conf.Auditlogs[0].Recording.Targets.Mode = configuration.AuditlogRecordingTargetsModeDisabled
	conf.Auditlogs[0].Recording.Targets.Targets = nil
	restarted, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.Nil(t, restarted)
	require.ErrorContains(t, err, fmt.Sprintf("remote artifact %q selects unconfigured target %q", name, "recordings"))
}

func TestHouseKeeperPreservesUnacknowledgedRecording(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	conf.Auditlogs[0].Recording.RetainFor.SetNative(time.Nanosecond)
	gate := make(chan struct{})
	target := &serviceRemoteDeliveryTestTarget{artifactStarted: make(chan struct{}, 1), artifactGate: gate}
	conf.Auditlogs[0].Recording.Targets.Mode = configuration.AuditlogRecordingTargetsModeCustom
	conf.Auditlogs[0].Recording.Targets.Targets = configuration.AuditlogTargets{{
		Name: "recordings",
		V:    &serviceRemoteDeliveryTestConfiguration{target: target},
	}}
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	name := sealRemoteDeliveryTestRecording(t, svc, conf)
	select {
	case <-target.artifactStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("Recording delivery did not start")
	}
	require.NoError(t, svc.houseKeeper.cleanupRecordings(svc.houseKeeper.logger(), t.Context(), time.Now().UTC().Add(time.Hour)))
	artifact, err := svc.recordingRepositories[configuration.DefaultAuditlogName].OpenSealedArtifact(t.Context(), name)
	require.NoError(t, err)
	require.NoError(t, artifact.Close())
	close(gate)
	require.NoError(t, svc.Close())
}

func TestServiceRestartAppliesRecordingRetentionBeforeDelivery(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	conf.Auditlogs[0].Recording.RetainFor.SetNative(time.Nanosecond)
	firstTarget := &serviceRemoteDeliveryTestTarget{publishedArtifact: make(chan string, 1)}
	conf.Auditlogs[0].Recording.Targets.Mode = configuration.AuditlogRecordingTargetsModeCustom
	conf.Auditlogs[0].Recording.Targets.Targets = configuration.AuditlogTargets{{
		Name: "recordings",
		V:    &serviceRemoteDeliveryTestConfiguration{target: firstTarget},
	}}
	first, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	name := sealRemoteDeliveryTestRecording(t, first, conf)
	flushContext, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	require.NoError(t, first.recordingDeliveries[configuration.DefaultAuditlogName].Flush(flushContext))
	cancel()
	require.Equal(t, name, <-firstTarget.publishedArtifact)
	require.NoError(t, first.Close())

	restartedTarget := &serviceRemoteDeliveryTestTarget{publishedArtifact: make(chan string, 1)}
	conf.Auditlogs[0].Recording.Targets.Targets[0].V = &serviceRemoteDeliveryTestConfiguration{target: restartedTarget}
	restarted, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	defer func() { require.NoError(t, restarted.Close()) }()
	_, err = restarted.recordingRepositories[configuration.DefaultAuditlogName].OpenSealedArtifact(t.Context(), name)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Never(t, func() bool {
		select {
		case <-restartedTarget.publishedArtifact:
			return true
		default:
			return false
		}
	}, 100*time.Millisecond, 10*time.Millisecond)
}

func TestHouseKeeperPreservesReceiptWhenArtifactWasNotPublished(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	conf.Auditlogs[0].Recording.RetainFor.SetNative(time.Hour)
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	defer func() { require.NoError(t, svc.Close()) }()
	repository := svc.recordingRepositories[configuration.DefaultAuditlogName]
	recordingId, err := recording.NewId()
	require.NoError(t, err)
	payload := []byte("receipt prepared before publication")
	name := recordingId.String() + sessionRecordingCastZstdSuffix
	remoteArtifact, err := audit.NewRemoteArtifact(repository.producerId, name, audit.ArtifactDigest(sha256.Sum256(payload)), int64(len(payload)), bytes.NewReader(payload))
	require.NoError(t, err)
	sealedAt := time.Now().UTC().Add(-2 * time.Hour)
	require.NoError(t, repository.receipts.Prepare(t.Context(), remoteArtifact, sealedAt))
	originalRecorder := svc.auditRecorders[configuration.DefaultAuditlogName]
	recorder := &recordingAuditRecorder{}
	svc.auditRecorders[configuration.DefaultAuditlogName] = recorder
	require.NoError(t, svc.houseKeeper.cleanupRecordings(svc.houseKeeper.logger(), t.Context(), time.Now().UTC()))
	svc.auditRecorders[configuration.DefaultAuditlogName] = originalRecorder

	candidates, err := repository.retentionCandidates(t.Context(), time.Now().UTC())
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.False(t, candidates[0].receipt.DeletionStarted)
	events := recorder.eventsSnapshot()
	require.Len(t, events, 2)
	require.Equal(t, audit.EventOutcomeFailure, events[1].Outcome)
}

func TestHouseKeeperResumesMarkedRecordingDeletionAfterRestart(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecording(&conf.Auditlogs[0])
	conf.Auditlogs[0].Recording.RetainFor.SetNative(time.Hour)
	first, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	name := sealRemoteDeliveryTestRecording(t, first, conf)
	repository := first.recordingRepositories[configuration.DefaultAuditlogName]
	cutoff := time.Now().UTC().Add(2 * time.Hour)
	candidates, err := repository.retentionCandidates(t.Context(), cutoff)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	artifact, err := repository.OpenSealedArtifact(t.Context(), name)
	require.NoError(t, err)
	require.NoError(t, artifact.Close())
	require.NoError(t, repository.receipts.MarkRetentionDeleting(t.Context(), candidates[0].receipt, cutoff))
	candidates[0].receipt.DeletionStarted = true
	deleted, err := repository.castZstd.DeleteSealed(t.Context(), candidates[0].recordingId, candidates[0].receipt.ArtifactDigest, candidates[0].receipt.Size)
	require.NoError(t, err)
	require.True(t, deleted)
	require.NoError(t, first.Close())

	conf.Auditlogs[0].Recording.RetainFor.SetNative(0)
	restarted, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	defer func() { require.NoError(t, restarted.Close()) }()
	candidates, err = restarted.recordingRepositories[configuration.DefaultAuditlogName].retentionCandidates(t.Context(), time.Now().UTC().Add(time.Hour))
	require.NoError(t, err)
	require.Empty(t, candidates)
}

func sealRemoteDeliveryTestRecording(t *testing.T, svc *service, conf configuration.Configuration) string {
	t.Helper()
	repository := svc.recordingRepositories[configuration.DefaultAuditlogName]
	recordingId, err := recording.NewId()
	require.NoError(t, err)
	connectionId, err := bfconnection.NewId()
	require.NoError(t, err)
	sessionId, err := session.NewId()
	require.NoError(t, err)
	startedAt := time.Now().UTC().Truncate(time.Second)
	active, err := repository.createActive(t.Context(), recording.CastHeader{
		Version: 3, Terminal: recording.CastTerminal{Columns: 80, Rows: 24}, Timestamp: startedAt.Unix(),
	}, recording.CastMetadata{
		RecordingId: recordingId, ConnectionId: connectionId, SessionId: sessionId, OperationId: uuid.New(),
		Flow: conf.Flows[0].Name, Task: audit.SessionTaskExec, ProducerId: repository.producerId, StartedAt: startedAt,
	}, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, recording.OutputStreamStdout, []byte("delivered\n")))
	exitStatus := uint32(0)
	_, err = active.seal(2*time.Second, recording.CastResult{Status: recording.CastStatusCompleted, EndedAt: startedAt.Add(2 * time.Second)}, &exitStatus)
	require.NoError(t, err)
	require.NoError(t, active.close())
	suffix := sessionRecordingCastZstdSuffix
	if repository.format == sessionRecordingRepositoryFormatBECast {
		suffix = sessionRecordingBECastSuffix
	}
	return recordingId.String() + suffix
}
