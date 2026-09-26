package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	goerrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/template"
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
	firstSummary, firstPhase, err := coordinator.Stop(4*time.Second, result, &exitStatus)
	require.NoError(t, err)
	secondSummary, secondPhase, err := coordinator.Stop(4*time.Second, result, &exitStatus)
	require.NoError(t, err)
	require.Equal(t, firstSummary, secondSummary)
	require.Equal(t, firstPhase, secondPhase)
	require.Equal(t, sessionRecordingFailurePhaseNone, firstPhase)

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
	_, phase, stopErr := coordinator.Stop(time.Second, recording.CastResult{
		Status:  recording.CastStatusCompleted,
		EndedAt: time.Now().UTC(),
	}, commonUint32(0))
	require.ErrorIs(t, stopErr, checkpointErr)
	require.Equal(t, sessionRecordingFailurePhaseCapture, phase)
	require.Zero(t, sink.seals)
	require.Equal(t, 1, sink.closes)
	select {
	case unexpected := <-failures:
		t.Fatalf("failure callback invoked more than once: %v", unexpected)
	default:
	}
}

func TestSessionRecordingCoordinatorClassifiesSealAndCloseFailures(t *testing.T) {
	sealErr := bferrors.System.Newf("seal failed")
	closeErr := bferrors.System.Newf("close failed")
	for _, test := range []struct {
		name     string
		sealErr  error
		closeErr error
	}{
		{name: "seal", sealErr: sealErr},
		{name: "close", closeErr: closeErr},
		{name: "seal and close", sealErr: sealErr, closeErr: closeErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			sink := &coordinatorTestSink{sealErr: test.sealErr, closeErr: test.closeErr}
			coordinator, err := newSessionRecordingCoordinator(sink.active(), time.Hour, 1<<20)
			require.NoError(t, err)
			require.NoError(t, coordinator.Start(func(error) {}))
			_, phase, stopErr := coordinator.Stop(time.Second, recording.CastResult{
				Status:  recording.CastStatusCompleted,
				EndedAt: time.Now().UTC(),
			}, commonUint32(0))
			require.Equal(t, sessionRecordingFailurePhaseSeal, phase)
			if test.sealErr != nil {
				require.ErrorIs(t, stopErr, test.sealErr)
			}
			if test.closeErr != nil {
				require.ErrorIs(t, stopErr, test.closeErr)
			}
			require.Equal(t, 1, sink.seals)
			require.Equal(t, 1, sink.closes)
		})
	}
}

func TestSessionRecordingFailureMarkerSurvivesJoinedCancellation(t *testing.T) {
	recordingErr := markSessionRecordingFailure(bferrors.System.Newf("Recording failed"))
	joined := goerrors.Join(context.Canceled, recordingErr)

	require.True(t, isSessionRecordingFailure(joined))
	require.ErrorIs(t, joined, context.Canceled)
	require.True(t, bferrors.System.IsErr(joined))
}

func TestSessionRecordingStopFailurePreservesPreparedLifecycle(t *testing.T) {
	for _, promoted := range []bool{false, true} {
		t.Run(fmt.Sprintf("promoted=%t", promoted), func(t *testing.T) {
			root := t.TempDir()
			auditlog := configuration.Auditlog{
				Name:         "security",
				Enabled:      true,
				IdentityFile: filepath.Join(root, "identity"),
				Directory:    filepath.Join(root, "journal"),
			}
			identity, err := audit.EnsureIdentity(&auditlog)
			require.NoError(t, err)
			require.NoError(t, os.Mkdir(filepath.Join(root, "recordings"), 0o700))
			receipts, err := audit.NewRemoteArtifactReceipts(filepath.Join(root, "recordings"), identity, auditlog.Name, nil, sessionRecordingLifecycleTestQuota{})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, receipts.Close()) })
			repository := &sessionRecordingRepository{format: sessionRecordingRepositoryFormatBCast, receipts: receipts}
			recordingId, err := recording.NewId()
			require.NoError(t, err)
			fileName, err := repository.artifactName(recordingId)
			require.NoError(t, err)
			pty := true
			started := audit.Event{
				Name:         audit.EventNameSessionRecordingStarted,
				Domain:       audit.EventDomainSession,
				Flow:         "recording-test",
				ConnectionId: "6ba7b842-9dad-4d1f-80b4-00c04fd430c8",
				SessionId:    "6ba7b843-9dad-4d1f-80b4-00c04fd430c8",
				OperationId:  "6ba7b844-9dad-4d1f-80b4-00c04fd430c8",
				RecordingId:  recordingId.String(),
				SessionTask:  audit.SessionTaskShell,
				Pty:          &pty,
			}
			startedAt := time.Now().UTC()
			require.NoError(t, receipts.BeginLifecycle(t.Context(), fileName, startedAt, started))
			duration := int64(1000)
			exitCode := 0
			terminal := started
			terminal.Name = audit.EventNameSessionRecordingCompleted
			terminal.Outcome = audit.EventOutcomeSuccess
			terminal.Pty = nil
			terminal.DurationMillis = &duration
			terminal.ExitCode = &exitCode
			require.NoError(t, receipts.StageLifecycle(t.Context(), fileName, terminal))
			content := []byte("outer artifact")
			artifactDigest := audit.ArtifactDigest(sha256.Sum256(content))
			artifact, err := audit.NewRemoteArtifact(identity.ProducerId(), fileName, artifactDigest, int64(len(content)), bytes.NewReader(content))
			require.NoError(t, err)
			castDigest := recording.CastDigest(sha256.Sum256([]byte("canonical Cast")))
			require.NoError(t, receipts.PrepareLifecycle(t.Context(), artifact, startedAt.Add(time.Second), castDigest.String(), false))
			expectedPending := 0
			if promoted {
				require.NoError(t, receipts.PromoteLifecycle(t.Context(), artifact))
				expectedPending = 1
			}
			pendingBefore, err := receipts.PendingLifecycle(t.Context())
			require.NoError(t, err)
			require.Len(t, pendingBefore, expectedPending)

			recorder := &recordingAuditRecorder{}
			flow := configuration.FlowName(started.Flow)
			svc := &service{flowAuditRecorders: map[configuration.FlowName]audit.Recorder{flow: recorder}}
			failure := terminal
			failure.Name = audit.EventNameSessionRecordingFailed
			failure.Outcome = audit.EventOutcomeFailure
			failure.Reason = audit.EventReasonRecordingSeal
			failure.ExitCode = nil
			require.NoError(t, svc.recordSessionRecordingStopFailure(t.Context(), t.Context(), repository, recordingId, flow, failure, true, sessionRecordingFailurePhaseSeal))
			require.Empty(t, recorder.eventsSnapshot())
			pendingAfter, err := receipts.PendingLifecycle(t.Context())
			require.NoError(t, err)
			require.Equal(t, pendingBefore, pendingAfter)
		})
	}
}

func TestExecuteSessionRecordingSealsShellAndExec(t *testing.T) {
	tests := []struct {
		name           string
		pty            bool
		exec           bool
		malformedExec  bool
		command        string
		expectedTask   audit.SessionTask
		expectedNotice bool
	}{
		{name: "shell with unspecified PTY dimensions", pty: true, expectedTask: audit.SessionTaskShell, expectedNotice: true},
		{name: "PTY shell after malformed exec", pty: true, malformedExec: true, expectedTask: audit.SessionTaskShell, expectedNotice: true},
		{name: "non-PTY shell", expectedTask: audit.SessionTaskShell},
		{name: "PTY exec", pty: true, exec: true, command: "record-me", expectedTask: audit.SessionTaskExec},
		{name: "PTY empty exec", pty: true, exec: true, expectedTask: audit.SessionTaskExec},
		{name: "non-PTY exec", exec: true, command: "record-me", expectedTask: audit.SessionTaskExec},
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
				conf.Auditlogs[0].Recording.Notice = template.MustNewString("NOTICE: {{.recording.id}}\n")
			})
			auditRecorder := &recordingAuditRecorder{}
			flow := server.service.Configuration.Flows[0].Name
			server.service.flowAuditRecorders[flow] = auditRecorder
			client := server.mustDial(t)
			sshSession, err := client.NewSession()
			require.NoError(t, err)
			var stdout, stderr bytes.Buffer
			sshSession.Stdout = &stdout
			sshSession.Stderr = &stderr
			if test.pty {
				require.NoError(t, sshSession.RequestPty("xterm", 0, 0, nil))
			}
			if test.malformedExec {
				accepted, requestErr := sshSession.SendRequest("exec", true, nil)
				require.NoError(t, requestErr)
				require.False(t, accepted)
			}
			if test.exec {
				err = sshSession.Run(test.command)
			} else {
				require.NoError(t, sshSession.Shell())
				err = sshSession.Wait()
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
			expectedOutputEvents := uint64(2)
			if test.expectedNotice {
				expectedOutputEvents++
				notice := "NOTICE: " + verification.Cast.Metadata.RecordingId.String()
				require.Contains(t, stdout.String(), notice)
				require.Contains(t, exportOnlySessionRecording(t, server.service, root), notice)
			} else {
				require.NotContains(t, stdout.String(), "NOTICE:")
			}
			require.Equal(t, expectedOutputEvents, verification.Cast.OutputEvents)

			requireAuditEventsNamedEventually(t, auditRecorder, audit.EventNameSessionTaskCompleted, 1)
			auditEvents := auditRecorder.eventsSnapshot()
			startedEvents := auditEventsNamed(auditEvents, audit.EventNameSessionRecordingStarted)
			completedEvents := auditEventsNamed(auditEvents, audit.EventNameSessionRecordingCompleted)
			require.Len(t, startedEvents, 1)
			require.Len(t, completedEvents, 1)
			require.Empty(t, auditEventsNamed(auditEvents, audit.EventNameSessionRecordingIncomplete))
			require.Empty(t, auditEventsNamed(auditEvents, audit.EventNameSessionRecordingFailed))
			requireSessionRecordingAuditCorrelation(t, verification, startedEvents[0], completedEvents[0])
			require.Equal(t, audit.EventOutcomeSuccess, completedEvents[0].Outcome)
			require.Equal(t, sessionRecordingCastDigest(t, server.service, root), completedEvents[0].RecordingDigest)
			require.Equal(t, 7, *completedEvents[0].ExitCode)
			require.Less(t, auditEventIndex(t, auditEvents, audit.EventNameSessionTaskStarted), auditEventIndex(t, auditEvents, audit.EventNameSessionRecordingStarted))
			require.Less(t, auditEventIndex(t, auditEvents, audit.EventNameSessionRecordingStarted), auditEventIndex(t, auditEvents, audit.EventNameSessionRecordingCompleted))
			require.Less(t, auditEventIndex(t, auditEvents, audit.EventNameSessionRecordingCompleted), auditEventIndex(t, auditEvents, audit.EventNameSessionTaskCompleted))
		})
	}
}

func TestSessionRecordingRejectsInvalidPtyWithoutDisablingBestEffortAuditlog(t *testing.T) {
	tests := []struct {
		name     string
		terminal string
		height   int
		width    int
	}{
		{name: "width exceeds Cast range", terminal: "xterm", height: 24, width: int(recording.MaximumCastTerminalDimension) + 1},
		{name: "height exceeds Cast range", terminal: "xterm", height: int(recording.MaximumCastTerminalDimension) + 1, width: 80},
		{name: "terminal type exceeds Cast range", terminal: string(bytes.Repeat([]byte{'x'}, 256)), height: 24, width: 80},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
				_, err := task.SshSession().Write([]byte("recorded"))
				return 0, err
			}}, func(conf *configuration.Configuration) {
				enableSessionRecordingForLifecycleTest(conf, root)
				conf.Auditlogs[0].FailurePolicy = configuration.AuditlogFailurePolicyBestEffort
			})
			auditRecorder := &recordingAuditRecorder{}
			flow := server.service.Configuration.Flows[0].Name
			auditlog := server.service.flowAuditlogs[flow]
			server.service.flowAuditRecorders[flow] = auditRecorder
			client := server.mustDial(t)

			invalid, err := client.NewSession()
			require.NoError(t, err)
			require.Error(t, invalid.RequestPty(test.terminal, test.height, test.width, nil))
			require.NoError(t, invalid.Close())
			require.False(t, server.service.auditlogDisabled(auditlog))
			ptyEvents := auditEventsNamed(auditRecorder.eventsSnapshot(), audit.EventNameSessionPtyDecided)
			require.Len(t, ptyEvents, 1)
			require.Equal(t, audit.EventOutcomeDenied, ptyEvents[0].Outcome)
			require.Equal(t, audit.EventReasonInvalidRequest, ptyEvents[0].Reason)

			healthy, err := client.NewSession()
			require.NoError(t, err)
			require.NoError(t, healthy.RequestPty("xterm", 24, 80, nil))
			require.NoError(t, healthy.Run("record-after-invalid-pty"))
			require.False(t, server.service.auditlogDisabled(auditlog))
			verification := verifyOnlySessionRecording(t, server.service, root)
			require.Equal(t, recording.CastStatusCompleted, verification.Cast.Result.Status)
		})
	}
}

func TestSessionRecordingRejectsInvalidResizeWithoutDisablingBestEffortAuditlog(t *testing.T) {
	root := t.TempDir()
	firstRunStarted := make(chan struct{})
	var runs atomic.Int32
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
		if runs.Add(1) == 1 {
			close(firstRunStarted)
			<-task.SshSession().Context().Done()
			return -1, task.SshSession().Context().Err()
		}
		_, err := task.SshSession().Write([]byte("recorded"))
		return 0, err
	}}, func(conf *configuration.Configuration) {
		enableSessionRecordingForLifecycleTest(conf, root)
		conf.Auditlogs[0].FailurePolicy = configuration.AuditlogFailurePolicyBestEffort
	})
	auditRecorder := &recordingAuditRecorder{}
	flow := server.service.Configuration.Flows[0].Name
	auditlog := server.service.flowAuditlogs[flow]
	server.service.flowAuditRecorders[flow] = auditRecorder
	client := server.mustDial(t)

	invalid, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, invalid.RequestPty("xterm", 24, 80, nil))
	require.NoError(t, invalid.Start("invalid-resize"))
	select {
	case <-firstRunStarted:
	case <-time.After(time.Second):
		t.Fatal("environment run did not start")
	}
	require.NoError(t, invalid.WindowChange(24, int(recording.MaximumCastTerminalDimension)+1))
	require.Error(t, invalid.Wait())
	require.False(t, server.service.auditlogDisabled(auditlog))

	healthy, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, healthy.RequestPty("xterm", 24, 80, nil))
	require.NoError(t, healthy.Run("record-after-invalid-resize"))
	require.False(t, server.service.auditlogDisabled(auditlog))
	requireAuditEventsNamedEventually(t, auditRecorder, audit.EventNameSessionRecordingCompleted, 1)
	requireAuditEventsNamedEventually(t, auditRecorder, audit.EventNameSessionRecordingFailed, 1)
}

func TestExecuteSessionRecordingNoticeRenderFailurePreventsEnvironmentRun(t *testing.T) {
	root := t.TempDir()
	var runCalled atomic.Bool
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{run: func(environment.Task) (int, error) {
		runCalled.Store(true)
		return 0, nil
	}}, func(conf *configuration.Configuration) {
		enableSessionRecordingForLifecycleTest(conf, root)
		conf.Auditlogs[0].Recording.Notice = template.MustNewString("{{.unsupported}}")
	})
	auditRecorder := &recordingAuditRecorder{}
	flow := server.service.Configuration.Flows[0].Name
	server.service.flowAuditRecorders[flow] = auditRecorder
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sshSession.RequestPty("xterm", 24, 80, nil))
	require.NoError(t, sshSession.Shell())
	require.Error(t, sshSession.Wait())
	require.False(t, runCalled.Load())

	verification := verifyOnlySessionRecording(t, server.service, root)
	require.Equal(t, recording.CastStatusIncomplete, verification.Cast.Result.Status)
	require.Equal(t, "session-error", verification.Cast.Result.Reason)
	incompleteEvents := requireAuditEventsNamedEventually(t, auditRecorder, audit.EventNameSessionRecordingIncomplete, 1)
	startedEvents := auditEventsNamed(auditRecorder.eventsSnapshot(), audit.EventNameSessionRecordingStarted)
	require.Len(t, startedEvents, 1)
	require.Len(t, incompleteEvents, 1)
	requireSessionRecordingAuditCorrelation(t, verification, startedEvents[0], incompleteEvents[0])
	require.Equal(t, audit.EventOutcomeFailure, incompleteEvents[0].Outcome)
	require.Equal(t, audit.EventReasonSessionError, incompleteEvents[0].Reason)
	require.Equal(t, audit.ErrorCategorySystem, incompleteEvents[0].ErrorCategory)
	require.Equal(t, sessionRecordingCastDigest(t, server.service, root), incompleteEvents[0].RecordingDigest)
}

func TestExecuteSessionRecordingExcludesSftp(t *testing.T) {
	runCalled := make(chan struct{}, 1)
	server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{run: func(environment.Task) (int, error) {
		runCalled <- struct{}{}
		return 0, nil
	}})
	auditlog := server.service.flowAuditlogs[server.service.Configuration.Flows[0].Name]
	server.service.recordingRepositories[auditlog] = &sessionRecordingRepository{}
	auditRecorder := &recordingAuditRecorder{}
	flow := server.service.Configuration.Flows[0].Name
	server.service.flowAuditRecorders[flow] = auditRecorder
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
	require.Empty(t, auditEventsNamed(auditRecorder.eventsSnapshot(), audit.EventNameSessionRecordingStarted))
	require.Empty(t, auditEventsNamed(auditRecorder.eventsSnapshot(), audit.EventNameSessionRecordingCompleted))
	require.Empty(t, auditEventsNamed(auditRecorder.eventsSnapshot(), audit.EventNameSessionRecordingIncomplete))
	require.Empty(t, auditEventsNamed(auditRecorder.eventsSnapshot(), audit.EventNameSessionRecordingFailed))
}

func TestExecuteSessionRecordingCapturesForcedCommandRequestedAsSftp(t *testing.T) {
	root := t.TempDir()
	type executedTask struct {
		taskType environment.TaskType
		command  string
	}
	executed := make(chan executedTask, 1)
	server := newAuthorizedKeysTestServerWithConfiguration(t, `command="forced-command"`, &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
		executed <- executedTask{taskType: task.TaskType(), command: task.SshSession().RawCommand()}
		return 0, nil
	}}, func(conf *configuration.Configuration) {
		enableSessionRecordingForLifecycleTest(conf, root)
	})
	auditRecorder := &recordingAuditRecorder{}
	flow := server.service.Configuration.Flows[0].Name
	server.service.flowAuditRecorders[flow] = auditRecorder
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sshSession.RequestSubsystem("sftp"))

	select {
	case actual := <-executed:
		require.Equal(t, executedTask{taskType: environment.TaskTypeShell, command: "forced-command"}, actual)
	case <-time.After(time.Second):
		t.Fatal("forced command did not run")
	}
	require.Eventually(t, func() bool {
		entries, readErr := os.ReadDir(filepath.Join(root, "recordings", "sealed"))
		return readErr == nil && len(entries) == 1
	}, time.Second, 10*time.Millisecond)
	verification := verifyOnlySessionRecording(t, server.service, root)
	require.Equal(t, recording.CastStatusCompleted, verification.Cast.Result.Status)
	require.Equal(t, audit.SessionTaskExec, verification.Cast.Metadata.Task)
	requireAuditEventsNamedEventually(t, auditRecorder, audit.EventNameSessionTaskCompleted, 1)
	events := auditRecorder.eventsSnapshot()
	taskStarted := auditEventsNamed(events, audit.EventNameSessionTaskStarted)
	taskCompleted := auditEventsNamed(events, audit.EventNameSessionTaskCompleted)
	recordingStarted := auditEventsNamed(events, audit.EventNameSessionRecordingStarted)
	recordingCompleted := auditEventsNamed(events, audit.EventNameSessionRecordingCompleted)
	require.Len(t, taskStarted, 1)
	require.Len(t, taskCompleted, 1)
	require.Len(t, recordingStarted, 1)
	require.Len(t, recordingCompleted, 1)
	require.Equal(t, audit.SessionTaskSftp, taskStarted[0].SessionTask)
	require.Equal(t, audit.SessionTaskSftp, taskCompleted[0].SessionTask)
	require.NotNil(t, taskStarted[0].ForcedCommand)
	require.True(t, *taskStarted[0].ForcedCommand)
	require.Equal(t, audit.SessionTaskExec, recordingStarted[0].SessionTask)
	require.Equal(t, audit.SessionTaskExec, recordingCompleted[0].SessionTask)
	requireSessionRecordingAuditCorrelation(t, verification, recordingStarted[0], recordingCompleted[0])
	require.Equal(t, taskStarted[0].OperationId, taskCompleted[0].OperationId)
	require.Equal(t, taskStarted[0].OperationId, recordingStarted[0].OperationId)
}

func TestExecuteSessionRecordingCreateFailurePreventsEnvironmentRun(t *testing.T) {
	var runCalled atomic.Bool
	server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{run: func(environment.Task) (int, error) {
		runCalled.Store(true)
		return 0, nil
	}})
	auditlog := server.service.flowAuditlogs[server.service.Configuration.Flows[0].Name]
	server.service.recordingRepositories[auditlog] = &sessionRecordingRepository{}
	auditRecorder := &recordingAuditRecorder{}
	flow := server.service.Configuration.Flows[0].Name
	server.service.flowAuditRecorders[flow] = auditRecorder
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.Error(t, sshSession.Run("must-not-run"))
	require.False(t, runCalled.Load())
	failedEvents := requireAuditEventsNamedEventually(t, auditRecorder, audit.EventNameSessionRecordingFailed, 1)
	require.Empty(t, auditEventsNamed(auditRecorder.eventsSnapshot(), audit.EventNameSessionRecordingStarted))
	require.Len(t, failedEvents, 1)
	require.Equal(t, audit.EventReasonRecordingCreate, failedEvents[0].Reason)
	require.Equal(t, audit.EventOutcomeFailure, failedEvents[0].Outcome)
	require.Empty(t, failedEvents[0].RecordingDigest)
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
	auditRecorder := &recordingAuditRecorder{}
	flow := server.service.Configuration.Flows[0].Name
	server.service.flowAuditRecorders[flow] = auditRecorder
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	var stdout bytes.Buffer
	sshSession.Stdout = &stdout
	require.Error(t, sshSession.Run("fail-closed"))
	failedEvents := requireAuditEventsNamedEventually(t, auditRecorder, audit.EventNameSessionRecordingFailed, 1)
	require.NotContains(t, stdout.String(), "cannot-persist")
	activeEntries, err := os.ReadDir(filepath.Join(root, "recordings", "active"))
	require.NoError(t, err)
	require.Len(t, activeEntries, 1)
	sealedEntries, err := os.ReadDir(filepath.Join(root, "recordings", "sealed"))
	require.NoError(t, err)
	require.Empty(t, sealedEntries)
	require.Len(t, auditEventsNamed(auditRecorder.eventsSnapshot(), audit.EventNameSessionRecordingStarted), 1)
	require.Len(t, failedEvents, 1)
	require.Equal(t, audit.EventReasonRecordingCapture, failedEvents[0].Reason)
	require.Equal(t, audit.EventOutcomeFailure, failedEvents[0].Outcome)
	require.Equal(t, audit.ErrorCategorySystem, failedEvents[0].ErrorCategory)
	require.Empty(t, failedEvents[0].RecordingDigest)
}

func TestExecuteSessionRecordingWriteFailureBestEffortContinues(t *testing.T) {
	root := t.TempDir()
	var repository *sessionRecordingRepository
	testEnvironment := &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
		if err := repository.Close(); err != nil {
			return -1, fmt.Errorf("cannot close test Recording repository: %w", err)
		}
		_, err := task.SshSession().Write([]byte("cannot-persist"))
		return 0, err
	}}
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", testEnvironment, func(conf *configuration.Configuration) {
		enableSessionRecordingForLifecycleTest(conf, root)
		conf.Auditlogs[0].FailurePolicy = configuration.AuditlogFailurePolicyBestEffort
	})
	auditlog := server.service.flowAuditlogs[server.service.Configuration.Flows[0].Name]
	repository = server.service.recordingRepositories[auditlog]
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	var stdout bytes.Buffer
	sshSession.Stdout = &stdout

	require.NoError(t, sshSession.Run("best-effort"))
	require.Equal(t, "cannot-persist", stdout.String())
	require.True(t, server.service.auditlogDisabled(auditlog))
}

func TestExecuteSessionRecordingStartedAuditFailurePreventsEnvironmentRun(t *testing.T) {
	for _, test := range []struct {
		name             string
		failBeforeRecord bool
		expectedStarted  int
	}{
		{name: "before commit", failBeforeRecord: true},
		{name: "after commit", expectedStarted: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			var runCalled atomic.Bool
			server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{run: func(environment.Task) (int, error) {
				runCalled.Store(true)
				return 0, nil
			}}, func(conf *configuration.Configuration) {
				enableSessionRecordingForLifecycleTest(conf, root)
			})
			auditRecorder := &recordingAuditRecorder{}
			auditRecorder.setRejectCanceled(true)
			startedErr := goerrors.New("started audit failed")
			if test.failBeforeRecord {
				auditRecorder.setErrorBeforeRecordForName(audit.EventNameSessionRecordingStarted, startedErr)
			} else {
				auditRecorder.setErrorForName(audit.EventNameSessionRecordingStarted, startedErr)
			}
			flow := server.service.Configuration.Flows[0].Name
			server.service.flowAuditRecorders[flow] = auditRecorder
			client := server.mustDial(t)
			sshSession, err := client.NewSession()
			require.NoError(t, err)
			require.Error(t, sshSession.Run("must-not-run"))
			require.False(t, runCalled.Load())
			require.Eventually(t, func() bool {
				entries, readErr := os.ReadDir(filepath.Join(root, "recordings", "sealed"))
				return readErr == nil && len(entries) == 1
			}, time.Second, 10*time.Millisecond)

			verification := verifyOnlySessionRecording(t, server.service, root)
			require.Equal(t, recording.CastStatusFailed, verification.Cast.Result.Status)
			require.Equal(t, "audit-start-failed", verification.Cast.Result.Reason)
			failedEvents := requireAuditEventsNamedEventually(t, auditRecorder, audit.EventNameSessionRecordingFailed, 1)
			require.Len(t, auditEventsNamed(auditRecorder.eventsSnapshot(), audit.EventNameSessionRecordingStarted), test.expectedStarted)
			require.Len(t, failedEvents, 1)
			require.Equal(t, audit.EventReasonAuditWrite, failedEvents[0].Reason)
			require.Equal(t, audit.ErrorCategorySystem, failedEvents[0].ErrorCategory)
			require.Equal(t, sessionRecordingCastDigest(t, server.service, root), failedEvents[0].RecordingDigest)
			require.Equal(t, verification.Cast.Metadata.RecordingId.String(), failedEvents[0].RecordingId)
		})
	}
}

func TestExecuteSessionRecordingCompletionAuditFailurePreservesCompletedArtifact(t *testing.T) {
	for _, test := range []struct {
		name       string
		failBefore bool
		before     int
		after      int
	}{
		{name: "before commit", failBefore: true, after: 1},
		{name: "after commit", before: 1, after: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
				enableSessionRecordingForLifecycleTest(conf, root)
			})
			auditRecorder := &recordingAuditRecorder{}
			injected := goerrors.New("completion audit failed")
			if test.failBefore {
				auditRecorder.setErrorBeforeRecordForName(audit.EventNameSessionRecordingCompleted, injected)
			} else {
				auditRecorder.setErrorForName(audit.EventNameSessionRecordingCompleted, injected)
			}
			flow := server.service.Configuration.Flows[0].Name
			server.service.flowAuditRecorders[flow] = auditRecorder
			healthyClient := server.mustDial(t)
			client := server.mustDial(t)
			sshSession, err := client.NewSession()
			require.NoError(t, err)
			require.Error(t, sshSession.Run("complete-before-audit-fails"))
			closed := make(chan struct{})
			go func() {
				_ = client.Wait()
				close(closed)
			}()
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				_ = client.Close()
				t.Fatal("SSH connection remained open after the completion audit failed")
			}
			_, err = client.NewSession()
			require.Error(t, err)
			healthySession, err := healthyClient.NewSession()
			require.NoError(t, err)
			require.NoError(t, healthySession.Close())

			verification := verifyOnlySessionRecording(t, server.service, root)
			require.Equal(t, recording.CastStatusCompleted, verification.Cast.Result.Status)
			before := auditEventsNamed(auditRecorder.eventsSnapshot(), audit.EventNameSessionRecordingCompleted)
			require.Len(t, before, test.before)
			auditlog := server.service.flowAuditlogs[flow]
			pending, err := server.service.recordingRepositories[auditlog].receipts.PendingLifecycle(t.Context())
			require.NoError(t, err)
			require.Len(t, pending, 1)
			expected := pending[0].Event
			require.NoError(t, server.service.recordingRepositories[auditlog].Close())
			restarted, err := newSessionRecordingRepository(t.Context(), server.service.Configuration.Auditlogs[0].Recording, server.service.auditIdentities[auditlog], server.service.Configuration.Auditlogs[0].EncryptionPublicKey, auditlog, server.service.recordingTargets[auditlog], true)
			require.NoError(t, err)
			server.service.recordingRepositories[auditlog] = restarted
			auditRecorder.setError(nil)
			server.service.auditRecorders[auditlog] = auditRecorder
			require.NoError(t, server.service.replaySessionRecordingLifecycles(t.Context()))
			completedEvents := auditEventsNamed(auditRecorder.eventsSnapshot(), audit.EventNameSessionRecordingCompleted)
			require.Len(t, completedEvents, test.after)
			for _, event := range completedEvents {
				require.Equal(t, expected, event)
			}
			require.Equal(t, sessionRecordingCastDigest(t, server.service, root), expected.RecordingDigest)
			pending, err = server.service.recordingRepositories[auditlog].receipts.PendingLifecycle(t.Context())
			require.NoError(t, err)
			require.Empty(t, pending)
			require.Empty(t, auditEventsNamed(auditRecorder.eventsSnapshot(), audit.EventNameSessionRecordingFailed))
		})
	}
}

func TestExecuteSessionRecordingCompletionAuditFailureBestEffortKeepsConnection(t *testing.T) {
	root := t.TempDir()
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		enableSessionRecordingForLifecycleTest(conf, root)
		conf.Auditlogs[0].FailurePolicy = configuration.AuditlogFailurePolicyBestEffort
	})
	delegate := &recordingAuditRecorder{}
	delegate.setErrorBeforeRecordForName(audit.EventNameSessionRecordingCompleted, goerrors.New("completion audit failed"))
	flow := server.service.Configuration.Flows[0].Name
	auditlog := server.service.flowAuditlogs[flow]
	server.service.flowAuditRecorders[flow] = &failurePolicyAuditRecorder{
		service:  server.service,
		auditlog: auditlog,
		delegate: delegate,
	}
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)

	require.NoError(t, sshSession.Run("complete-before-audit-fails"))
	require.True(t, server.service.auditlogDisabled(auditlog))

	healthy, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, healthy.Run("still-alive"))
}

func TestExecuteSessionRecordingInvalidExitStatusIsIncomplete(t *testing.T) {
	tests := []struct {
		name     string
		exitCode int
	}{
		{name: "negative", exitCode: -2},
	}
	if strconv.IntSize > 32 {
		tooLarge := uint64(recording.MaximumCastExitStatus) + 1
		tests = append(tests, struct {
			name     string
			exitCode int
		}{name: "above asciinema range", exitCode: int(tooLarge)})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{run: func(environment.Task) (int, error) {
				return test.exitCode, nil
			}}, func(conf *configuration.Configuration) {
				enableSessionRecordingForLifecycleTest(conf, root)
			})
			auditRecorder := &recordingAuditRecorder{}
			flow := server.service.Configuration.Flows[0].Name
			server.service.flowAuditRecorders[flow] = auditRecorder
			client := server.mustDial(t)
			sshSession, err := client.NewSession()
			require.NoError(t, err)
			require.Error(t, sshSession.Run("invalid-exit"))

			verification := verifyOnlySessionRecording(t, server.service, root)
			require.Equal(t, recording.CastStatusIncomplete, verification.Cast.Result.Status)
			require.Equal(t, "invalid-exit-status", verification.Cast.Result.Reason)
			events := requireAuditEventsNamedEventually(t, auditRecorder, audit.EventNameSessionRecordingIncomplete, 1)
			require.Len(t, events, 1)
			require.Equal(t, audit.EventReasonInvalidExitCode, events[0].Reason)
			require.Equal(t, audit.EventOutcomeFailure, events[0].Outcome)
			require.Empty(t, events[0].ErrorCategory)
			require.Equal(t, sessionRecordingCastDigest(t, server.service, root), events[0].RecordingDigest)
		})
	}
}

func TestExecuteSessionRecordingCancellationAuditsWithDetachedContext(t *testing.T) {
	root := t.TempDir()
	runStarted := make(chan struct{})
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
		close(runStarted)
		<-task.SshSession().Context().Done()
		return -1, task.SshSession().Context().Err()
	}}, func(conf *configuration.Configuration) {
		enableSessionRecordingForLifecycleTest(conf, root)
	})
	auditRecorder := &recordingAuditRecorder{}
	auditRecorder.setRejectCanceled(true)
	flow := server.service.Configuration.Flows[0].Name
	server.service.flowAuditRecorders[flow] = auditRecorder
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sshSession.Start("cancel-recording"))
	select {
	case <-runStarted:
	case <-time.After(time.Second):
		t.Fatal("environment run did not start")
	}
	require.NoError(t, sshSession.Close())
	events := requireAuditEventsNamedEventually(t, auditRecorder, audit.EventNameSessionRecordingIncomplete, 1)
	verification := verifyOnlySessionRecording(t, server.service, root)
	require.Equal(t, recording.CastStatusIncomplete, verification.Cast.Result.Status)
	require.Len(t, events, 1)
	require.Equal(t, audit.EventOutcomeCanceled, events[0].Outcome)
	require.Equal(t, audit.EventReasonContextCanceled, events[0].Reason)
	require.Empty(t, events[0].ErrorCategory)
}

func TestExecuteSessionRecordingDeadlineExceededIsIncomplete(t *testing.T) {
	root := t.TempDir()
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{run: func(environment.Task) (int, error) {
		return -1, context.DeadlineExceeded
	}}, func(conf *configuration.Configuration) {
		enableSessionRecordingForLifecycleTest(conf, root)
	})
	auditRecorder := &recordingAuditRecorder{}
	flow := server.service.Configuration.Flows[0].Name
	server.service.flowAuditRecorders[flow] = auditRecorder
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.Error(t, sshSession.Run("deadline-recording"))

	verification := verifyOnlySessionRecording(t, server.service, root)
	require.Equal(t, recording.CastStatusIncomplete, verification.Cast.Result.Status)
	events := requireAuditEventsNamedEventually(t, auditRecorder, audit.EventNameSessionRecordingIncomplete, 1)
	require.Len(t, events, 1)
	require.Equal(t, audit.EventOutcomeCanceled, events[0].Outcome)
	require.Equal(t, audit.EventReasonDeadlineExceeded, events[0].Reason)
	require.Empty(t, events[0].ErrorCategory)
}

func TestExecuteSessionRecordingIncompletePreservesValidExitStatus(t *testing.T) {
	root := t.TempDir()
	var closeCalls atomic.Int32
	testEnvironment := &authorizedKeysTestEnvironment{
		run: func(environment.Task) (int, error) { return 7, nil },
		close: func() error {
			if closeCalls.Add(1) == 1 {
				return bferrors.System.Newf("environment close failed")
			}
			return nil
		},
	}
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", testEnvironment, func(conf *configuration.Configuration) {
		enableSessionRecordingForLifecycleTest(conf, root)
	})
	auditRecorder := &recordingAuditRecorder{}
	flow := server.service.Configuration.Flows[0].Name
	server.service.flowAuditRecorders[flow] = auditRecorder
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.Error(t, sshSession.Run("close-failure"))

	verification := verifyOnlySessionRecording(t, server.service, root)
	require.Equal(t, recording.CastStatusIncomplete, verification.Cast.Result.Status)
	require.NotNil(t, verification.Cast.ExitStatus)
	require.Equal(t, uint32(7), *verification.Cast.ExitStatus)
	events := requireAuditEventsNamedEventually(t, auditRecorder, audit.EventNameSessionRecordingIncomplete, 1)
	require.Len(t, events, 1)
	require.Equal(t, audit.EventReasonSessionError, events[0].Reason)
	require.NotNil(t, events[0].ExitCode)
	require.Equal(t, 7, *events[0].ExitCode)
}

func TestExecuteSessionRecordingSealFailureAuditsSealFailure(t *testing.T) {
	root := t.TempDir()
	var repository *sessionRecordingRepository
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{run: func(environment.Task) (int, error) {
		if err := repository.Close(); err != nil {
			return -1, err
		}
		return 0, nil
	}}, func(conf *configuration.Configuration) {
		enableSessionRecordingForLifecycleTest(conf, root)
	})
	auditlog := server.service.flowAuditlogs[server.service.Configuration.Flows[0].Name]
	repository = server.service.recordingRepositories[auditlog]
	auditRecorder := &recordingAuditRecorder{}
	flow := server.service.Configuration.Flows[0].Name
	server.service.flowAuditRecorders[flow] = auditRecorder
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.Error(t, sshSession.Run("seal-failure"))

	failedEvents := requireAuditEventsNamedEventually(t, auditRecorder, audit.EventNameSessionRecordingFailed, 1)
	require.Len(t, failedEvents, 1)
	require.Equal(t, audit.EventReasonRecordingSeal, failedEvents[0].Reason)
	require.Equal(t, audit.EventOutcomeFailure, failedEvents[0].Outcome)
	require.Equal(t, audit.ErrorCategorySystem, failedEvents[0].ErrorCategory)
	require.Empty(t, failedEvents[0].RecordingDigest)
}

func TestExecuteSessionRecordingIntervalCheckpointFailureAuditsCaptureFailure(t *testing.T) {
	root := t.TempDir()
	var repository *sessionRecordingRepository
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
		if _, err := task.SshSession().Write([]byte("dirty")); err != nil {
			return -1, err
		}
		if err := repository.Close(); err != nil {
			return -1, err
		}
		<-task.SshSession().Context().Done()
		return -1, task.SshSession().Context().Err()
	}}, func(conf *configuration.Configuration) {
		enableSessionRecordingForLifecycleTest(conf, root)
		conf.Auditlogs[0].Recording.FlushInterval = common.DurationOf(5 * time.Millisecond)
	})
	auditlog := server.service.flowAuditlogs[server.service.Configuration.Flows[0].Name]
	repository = server.service.recordingRepositories[auditlog]
	auditRecorder := &recordingAuditRecorder{}
	flow := server.service.Configuration.Flows[0].Name
	server.service.flowAuditRecorders[flow] = auditRecorder
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.Error(t, sshSession.Run("checkpoint-failure"))
	failedEvents := requireAuditEventsNamedEventually(t, auditRecorder, audit.EventNameSessionRecordingFailed, 1)
	require.Len(t, failedEvents, 1)
	require.Equal(t, audit.EventReasonRecordingCapture, failedEvents[0].Reason)
	require.Equal(t, audit.EventOutcomeFailure, failedEvents[0].Outcome)
	require.Empty(t, failedEvents[0].RecordingDigest)
}

func requireAuditEventsNamedEventually(t *testing.T, recorder *recordingAuditRecorder, name audit.EventName, count int) []audit.Event {
	t.Helper()
	var events []audit.Event
	require.Eventually(t, func() bool {
		events = auditEventsNamed(recorder.eventsSnapshot(), name)
		return len(events) == count
	}, time.Second, 10*time.Millisecond)
	return events
}

func enableSessionRecordingForLifecycleTest(conf *configuration.Configuration, root string) {
	auditlog := &conf.Auditlogs[0]
	auditlog.Enabled = true
	auditlog.IdentityFile = filepath.Join(root, "audit", "identity")
	auditlog.Directory = filepath.Join(root, "audit", "journal")
	auditlog.Recording.Enabled = true
	auditlog.Recording.Directory = filepath.Join(root, "recordings")
}

type sessionRecordingTestVerification struct {
	Cast    *recording.CastVerification
	Summary recording.NativeRecordingSummary
}

func verifyOnlySessionRecording(t *testing.T, service *service, root string) *sessionRecordingTestVerification {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "recordings", "sealed"))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, ".bcast", filepath.Ext(entries[0].Name()))
	path := filepath.Join(root, "recordings", "sealed", entries[0].Name())
	file, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	info, err := file.Stat()
	require.NoError(t, err)
	auditlog := service.flowAuditlogs[service.Configuration.Flows[0].Name]
	var output bytes.Buffer
	verification, err := recording.ExportNativeRecordingCast(file, info.Size(), nil, &output, recording.NativeRecordingVerifyOptions{
		ExpectedProducerId: service.auditIdentities[auditlog].ProducerId(),
	})
	require.NoError(t, err)
	cast, err := recording.VerifyCast(bytes.NewReader(output.Bytes()), recording.CastVerifyOptions{
		ExpectedProducerId: service.auditIdentities[auditlog].ProducerId(),
	})
	require.NoError(t, err)
	require.Equal(t, cast.Digest, recording.CastDigest(verification.Seal.CastDigest))
	return &sessionRecordingTestVerification{Cast: cast, Summary: recording.NativeRecordingSummary{
		RecordingId: recording.Id(verification.Header.RecordingId), Status: cast.Result.Status, Digest: cast.Digest,
	}}
}

func sessionRecordingCastDigest(t *testing.T, service *service, root string) string {
	t.Helper()
	return verifyOnlySessionRecording(t, service, root).Summary.Digest.String()
}

func exportOnlySessionRecording(t *testing.T, service *service, root string) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "recordings", "sealed"))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	path := filepath.Join(root, "recordings", "sealed", entries[0].Name())
	file, err := os.Open(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	info, err := file.Stat()
	require.NoError(t, err)
	auditlog := service.flowAuditlogs[service.Configuration.Flows[0].Name]
	var output bytes.Buffer
	_, err = recording.ExportNativeRecordingCast(file, info.Size(), nil, &output, recording.NativeRecordingVerifyOptions{
		ExpectedProducerId: service.auditIdentities[auditlog].ProducerId(),
	})
	require.NoError(t, err)
	return output.String()
}

func requireSessionRecordingAuditCorrelation(t *testing.T, verification *sessionRecordingTestVerification, started, completed audit.Event) {
	t.Helper()
	metadata := verification.Cast.Metadata
	require.Equal(t, metadata.RecordingId.String(), started.RecordingId)
	require.Equal(t, started.RecordingId, completed.RecordingId)
	require.Equal(t, metadata.ConnectionId.String(), started.ConnectionId)
	require.Equal(t, started.ConnectionId, completed.ConnectionId)
	require.Equal(t, metadata.SessionId.String(), started.SessionId)
	require.Equal(t, started.SessionId, completed.SessionId)
	require.Equal(t, metadata.OperationId.String(), started.OperationId)
	require.Equal(t, started.OperationId, completed.OperationId)
	require.Equal(t, metadata.Flow.String(), started.Flow)
	require.Equal(t, started.Flow, completed.Flow)
	require.Equal(t, metadata.Task, started.SessionTask)
	require.Equal(t, started.SessionTask, completed.SessionTask)
	require.NotNil(t, started.Pty)
	require.Equal(t, metadata.Pty, *started.Pty)
	require.NotNil(t, completed.DurationMillis)
}

func auditEventIndex(t *testing.T, events []audit.Event, name audit.EventName) int {
	t.Helper()
	for index, event := range events {
		if event.Name == name {
			return index
		}
	}
	t.Fatalf("audit event %q not found", name)
	return -1
}

type coordinatorTestSink struct {
	mu            sync.Mutex
	checkpoints   int
	seals         int
	closes        int
	checkpointErr error
	sealErr       error
	closeErr      error
	digest        recording.CastDigest
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
		seal: func(_ time.Duration, result recording.CastResult, exitStatus *uint32) (sessionRecordingSealSummary, error) {
			this.mu.Lock()
			defer this.mu.Unlock()
			this.seals++
			this.result = result
			this.exitStatus = exitStatus
			return sessionRecordingSealSummary{status: result.Status, digest: this.digest}, this.sealErr
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

type sessionRecordingLifecycleTestQuota struct{}

func (sessionRecordingLifecycleTestQuota) Reserve(uint64) error                 { return nil }
func (sessionRecordingLifecycleTestQuota) Reconcile(uint64, int64, int64) error { return nil }
