package service

import (
	"bytes"
	"context"
	goerrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/recording"
)

func TestSessionRecordingCoordinatorCheckpointsBySizeAndStopsOnce(t *testing.T) {
	sink := &coordinatorTestSink{}
	active := sink.active()
	coordinator, err := newSessionRecordingCoordinator(active, time.Hour, 5)
	require.NoError(t, err)
	require.NoError(t, coordinator.Start(func(error) { t.Error("unexpected Recording failure callback") }))

	require.NoError(t, coordinator.WriteOutput(time.Second, recording.OutputStreamStdout, []byte("ab")))
	require.Zero(t, sink.checkpoints)
	require.NoError(t, coordinator.WriteOutput(2*time.Second, recording.OutputStreamStdout, []byte("cde")))
	require.Equal(t, 1, sink.checkpoints)
	require.NoError(t, coordinator.WriteResize(3*time.Second, 100, 30))
	exitStatus := uint32(7)
	result := recording.CastResult{Status: recording.CastStatusCompleted, EndedAt: time.Now().UTC()}
	require.NoError(t, coordinator.Stop(4*time.Second, result, &exitStatus))
	require.NoError(t, coordinator.Stop(4*time.Second, result, &exitStatus))

	require.Equal(t, 1, sink.seals)
	require.Equal(t, 1, sink.closes)
	require.Equal(t, result, sink.result)
	require.Equal(t, &exitStatus, sink.exitStatus)
	require.ErrorContains(t, coordinator.WriteOutput(5*time.Second, recording.OutputStreamStdout, []byte("late")), "not running")
}

func TestSessionRecordingCoordinatorIntervalFailureNotifiesAndSkipsSeal(t *testing.T) {
	checkpointErr := bferrors.System.Newf("checkpoint failed")
	sink := &coordinatorTestSink{checkpointErr: checkpointErr}
	coordinator, err := newSessionRecordingCoordinator(sink.active(), time.Millisecond, 1<<20)
	require.NoError(t, err)
	failures := make(chan error, 2)
	require.NoError(t, coordinator.Start(func(err error) { failures <- err }))
	require.NoError(t, coordinator.WriteOutput(0, recording.OutputStreamStdout, []byte("dirty")))

	select {
	case failure := <-failures:
		require.ErrorIs(t, failure, checkpointErr)
	case <-time.After(time.Second):
		t.Fatal("interval checkpoint did not fail")
	}
	stopErr := coordinator.Stop(time.Second, recording.CastResult{
		Status:  recording.CastStatusCompleted,
		EndedAt: time.Now().UTC(),
	}, commonUint32(0))
	require.ErrorIs(t, stopErr, checkpointErr)
	require.Zero(t, sink.seals)
	require.Equal(t, 1, sink.closes)
	select {
	case unexpected := <-failures:
		t.Fatalf("failure callback invoked more than once: %v", unexpected)
	default:
	}
}

func TestSessionRecordingFailureMarkerSurvivesJoinedCancellation(t *testing.T) {
	recordingErr := markSessionRecordingFailure(bferrors.System.Newf("Recording failed"))
	joined := goerrors.Join(context.Canceled, recordingErr)

	require.True(t, isSessionRecordingFailure(joined))
	require.ErrorIs(t, joined, context.Canceled)
	require.True(t, bferrors.System.IsErr(joined))
}

func TestExecuteSessionRecordingSealsShellAndExec(t *testing.T) {
	tests := []struct {
		name         string
		pty          bool
		expectedTask audit.SessionTask
	}{
		{name: "shell with unspecified PTY dimensions", pty: true, expectedTask: audit.SessionTaskShell},
		{name: "non-PTY exec", expectedTask: audit.SessionTaskExec},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			testEnvironment := &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
				if _, err := task.SshSession().Write([]byte("stdout")); err != nil {
					return -1, err
				}
				if _, err := task.SshSession().Stderr().Write([]byte("stderr")); err != nil {
					return -1, err
				}
				return 7, nil
			}}
			server := newAuthorizedKeysTestServerWithConfiguration(t, "", testEnvironment, func(conf *configuration.Configuration) {
				enableSessionRecordingForLifecycleTest(conf, root)
			})
			client := server.mustDial(t)
			sshSession, err := client.NewSession()
			require.NoError(t, err)
			var stdout, stderr bytes.Buffer
			sshSession.Stdout = &stdout
			sshSession.Stderr = &stderr
			if test.pty {
				require.NoError(t, sshSession.RequestPty("xterm", 0, 0, nil))
				require.NoError(t, sshSession.Shell())
				err = sshSession.Wait()
			} else {
				err = sshSession.Run("record-me")
			}
			var exitErr *gossh.ExitError
			require.ErrorAs(t, err, &exitErr)
			require.Equal(t, 7, exitErr.ExitStatus())

			verification := verifyOnlySessionRecording(t, server.service, root)
			require.Equal(t, recording.CastStatusCompleted, verification.Cast.Result.Status)
			require.Equal(t, uint32(7), *verification.Cast.ExitStatus)
			require.Equal(t, test.expectedTask, verification.Cast.Metadata.Task)
			require.Equal(t, test.pty, verification.Cast.Metadata.Pty)
			require.Equal(t, uint32(defaultSessionRecordingColumns), verification.Cast.Header.Terminal.Columns)
			require.Equal(t, uint32(defaultSessionRecordingRows), verification.Cast.Header.Terminal.Rows)
			require.Equal(t, uint64(2), verification.Cast.OutputEvents)
		})
	}
}

func TestExecuteSessionRecordingExcludesSftp(t *testing.T) {
	runCalled := make(chan struct{}, 1)
	server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{run: func(environment.Task) (int, error) {
		runCalled <- struct{}{}
		return 0, nil
	}})
	auditlog := server.service.flowAuditlogs[server.service.Configuration.Flows[0].Name]
	server.service.recordingRepositories[auditlog] = &sessionRecordingRepository{}
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sshSession.RequestSubsystem("sftp"))
	select {
	case <-runCalled:
	case <-time.After(time.Second):
		t.Fatal("SFTP environment did not run")
	}
	_ = sshSession.Close()
}

func TestExecuteSessionRecordingCreateFailurePreventsEnvironmentRun(t *testing.T) {
	var runCalled atomic.Bool
	server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{run: func(environment.Task) (int, error) {
		runCalled.Store(true)
		return 0, nil
	}})
	auditlog := server.service.flowAuditlogs[server.service.Configuration.Flows[0].Name]
	server.service.recordingRepositories[auditlog] = &sessionRecordingRepository{}
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.Error(t, sshSession.Run("must-not-run"))
	require.False(t, runCalled.Load())
}

func TestExecuteSessionRecordingWriteFailureIsFailClosed(t *testing.T) {
	root := t.TempDir()
	var repository *sessionRecordingRepository
	testEnvironment := &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
		if err := repository.Close(); err != nil {
			return -1, fmt.Errorf("cannot close test Recording repository: %w", err)
		}
		_, err := task.SshSession().Write([]byte("cannot-persist"))
		return -1, err
	}}
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", testEnvironment, func(conf *configuration.Configuration) {
		enableSessionRecordingForLifecycleTest(conf, root)
	})
	auditlog := server.service.flowAuditlogs[server.service.Configuration.Flows[0].Name]
	repository = server.service.recordingRepositories[auditlog]
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.Error(t, sshSession.Run("fail-closed"))
	activeEntries, err := os.ReadDir(filepath.Join(root, "recordings", "active"))
	require.NoError(t, err)
	require.Len(t, activeEntries, 1)
	sealedEntries, err := os.ReadDir(filepath.Join(root, "recordings", "sealed"))
	require.NoError(t, err)
	require.Empty(t, sealedEntries)
}

func enableSessionRecordingForLifecycleTest(conf *configuration.Configuration, root string) {
	auditlog := &conf.Auditlogs[0]
	auditlog.Enabled = true
	auditlog.IdentityFile = filepath.Join(root, "audit", "identity")
	auditlog.Journal.Directory = filepath.Join(root, "audit", "journal")
	auditlog.Recording.Enabled = true
	auditlog.Recording.Directory = filepath.Join(root, "recordings")
}

func verifyOnlySessionRecording(t *testing.T, service *service, root string) *recording.CastZstdVerification {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "recordings", "sealed"))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	path := filepath.Join(root, "recordings", "sealed", entries[0].Name())
	file, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	info, err := file.Stat()
	require.NoError(t, err)
	auditlog := service.flowAuditlogs[service.Configuration.Flows[0].Name]
	verification, err := recording.VerifyCastZstd(file, info.Size(), recording.CastZstdVerifyOptions{
		ExpectedProducerId: service.auditIdentities[auditlog].ProducerId(),
	})
	require.NoError(t, err)
	return verification
}

type coordinatorTestSink struct {
	mu            sync.Mutex
	checkpoints   int
	seals         int
	closes        int
	checkpointErr error
	sealErr       error
	closeErr      error
	result        recording.CastResult
	exitStatus    *uint32
}

func (this *coordinatorTestSink) active() *activeSessionRecording {
	return &activeSessionRecording{
		recordingSink: this,
		checkpoint: func() error {
			this.mu.Lock()
			defer this.mu.Unlock()
			this.checkpoints++
			return this.checkpointErr
		},
		seal: func(_ time.Duration, result recording.CastResult, exitStatus *uint32) error {
			this.mu.Lock()
			defer this.mu.Unlock()
			this.seals++
			this.result = result
			this.exitStatus = exitStatus
			return this.sealErr
		},
		close: func() error {
			this.mu.Lock()
			defer this.mu.Unlock()
			this.closes++
			return this.closeErr
		},
	}
}

func (*coordinatorTestSink) WriteOutput(time.Duration, recording.OutputStream, []byte) error {
	return nil
}

func (*coordinatorTestSink) WriteResize(time.Duration, uint32, uint32) error {
	return nil
}

func commonUint32(value uint32) *uint32 { return &value }

var _ recordingSink = (*coordinatorTestSink)(nil)
