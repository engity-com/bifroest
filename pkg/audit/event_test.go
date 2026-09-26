package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestLegacyAuditEventEncodingRemainsCanonical(t *testing.T) {
	payload, err := json.Marshal(Event{Name: "test.legacy"})
	require.NoError(t, err)
	require.Equal(t, `{"name":"test.legacy"}`, string(payload))

	var decoded Event
	require.NoError(t, decodeCanonicalJournalPayload(payload, &decoded))
	require.Equal(t, Event{Name: "test.legacy"}, decoded)
}

func TestAuditEventEncodingIncludesStructuredFields(t *testing.T) {
	exitCode := 0
	bytesRead := int64(1)
	bytesWritten := int64(2)
	duration := int64(3)
	count := uint64(4)
	pty := true
	agentForwarding := false
	forcedCommand := true
	event := Event{
		Name:                 EventNameSessionTaskCompleted,
		Domain:               EventDomainSession,
		Outcome:              EventOutcomeSuccess,
		Flow:                 "main",
		ConnectionId:         "34e34ab8-7457-4d88-a5e4-c57791775c3a",
		SessionId:            "82d8fdda-4730-43b7-bfde-72733c217bde",
		OperationId:          "6d05798f-b877-4191-8aa0-4576a30411ad",
		AuthenticationMethod: AuthenticationMethodPublicKey,
		AuthenticationPhase:  AuthenticationPhaseVerified,
		AuthorizationKind:    "local",
		SessionTask:          SessionTaskShell,
		Reason:               "completed",
		ErrorCategory:        ErrorCategoryNetwork,
		ExitCode:             &exitCode,
		BytesRead:            &bytesRead,
		BytesWritten:         &bytesWritten,
		DurationMillis:       &duration,
		Count:                &count,
		Pty:                  &pty,
		AgentForwarding:      &agentForwarding,
		ForcedCommand:        &forcedCommand,
	}

	payload, err := json.Marshal(event)
	require.NoError(t, err)
	require.Equal(t, `{"name":"session.task.completed","domain":"session","outcome":"success","flow":"main","connectionId":"34e34ab8-7457-4d88-a5e4-c57791775c3a","sessionId":"82d8fdda-4730-43b7-bfde-72733c217bde","operationId":"6d05798f-b877-4191-8aa0-4576a30411ad","authenticationMethod":"public-key","authenticationPhase":"verified","authorizationKind":"local","sessionTask":"shell","reason":"completed","errorCategory":"network","exitCode":0,"bytesRead":1,"bytesWritten":2,"durationMillis":3,"count":4,"pty":true,"agentForwarding":false,"forcedCommand":true}`, string(payload))
	require.NoError(t, validateAuditEventForWrite(event))
}

func TestSessionRecordingAuditEventEncoding(t *testing.T) {
	exitCode := 0
	durationMillis := int64(1)
	event := Event{
		Name:            EventNameSessionRecordingCompleted,
		Domain:          EventDomainSession,
		Outcome:         EventOutcomeSuccess,
		Flow:            "main",
		ConnectionId:    "34e34ab8-7457-4d88-a5e4-c57791775c3a",
		SessionId:       "82d8fdda-4730-43b7-bfde-72733c217bde",
		OperationId:     "6d05798f-b877-4191-8aa0-4576a30411ad",
		RecordingId:     "fd70203b-ea19-4288-8ec2-577b623e92d0",
		RecordingDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		SessionTask:     SessionTaskShell,
		ExitCode:        &exitCode,
		DurationMillis:  &durationMillis,
	}

	payload, err := json.Marshal(event)
	require.NoError(t, err)
	require.Equal(t, `{"name":"session.recording.completed","domain":"session","outcome":"success","flow":"main","connectionId":"34e34ab8-7457-4d88-a5e4-c57791775c3a","sessionId":"82d8fdda-4730-43b7-bfde-72733c217bde","operationId":"6d05798f-b877-4191-8aa0-4576a30411ad","recordingId":"fd70203b-ea19-4288-8ec2-577b623e92d0","recordingDigest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","sessionTask":"shell","exitCode":0,"durationMillis":1}`, string(payload))
	require.NoError(t, validateAuditEventForWrite(event))
}

func TestSessionRecordingDeliveryAuditEventEncodingAndValidation(t *testing.T) {
	base := Event{
		Domain:      EventDomainSession,
		OperationId: "6d05798f-b877-4191-8aa0-4576a30411ad",
		RecordingId: "fd70203b-ea19-4288-8ec2-577b623e92d0",
		Target:      "archive",
	}
	failed := base
	failed.Name = EventNameSessionRecordingDeliveryFailed
	failed.Outcome = EventOutcomeFailure
	failed.ErrorCategory = ErrorCategoryNetwork
	payload, err := json.Marshal(failed)
	require.NoError(t, err)
	require.Equal(t, `{"name":"session.recording.delivery.failed","domain":"session","outcome":"failure","operationId":"6d05798f-b877-4191-8aa0-4576a30411ad","recordingId":"fd70203b-ea19-4288-8ec2-577b623e92d0","target":"archive","errorCategory":"network"}`, string(payload))
	require.NoError(t, validateAuditEventForWrite(failed))

	succeeded := base
	succeeded.Name = EventNameSessionRecordingDeliverySucceeded
	succeeded.Outcome = EventOutcomeSuccess
	require.NoError(t, validateAuditEventForWrite(succeeded))

	invalid := []Event{
		{Name: failed.Name, Domain: failed.Domain, Outcome: failed.Outcome, OperationId: failed.OperationId, RecordingId: failed.RecordingId, ErrorCategory: failed.ErrorCategory},
		{Name: failed.Name, Domain: failed.Domain, Outcome: failed.Outcome, RecordingId: failed.RecordingId, Target: failed.Target, ErrorCategory: failed.ErrorCategory},
		{Name: failed.Name, Domain: failed.Domain, Outcome: failed.Outcome, OperationId: failed.OperationId, Target: failed.Target, ErrorCategory: failed.ErrorCategory},
		{Name: failed.Name, Domain: failed.Domain, Outcome: failed.Outcome, OperationId: failed.OperationId, RecordingId: failed.RecordingId, Target: failed.Target},
		succeededWithError(succeeded),
	}
	for index, event := range invalid {
		t.Run(fmt.Sprintf("invalid-%d", index), func(t *testing.T) {
			require.Error(t, validateAuditEventForWrite(event))
		})
	}
}

func succeededWithError(event Event) Event {
	event.ErrorCategory = ErrorCategorySystem
	return event
}

func TestKnownAuditEventNamesAreValidAndUnique(t *testing.T) {
	seen := make(map[EventName]struct{}, len(knownEventNames))
	for _, name := range knownEventNames {
		require.NotContains(t, seen, name)
		seen[name] = struct{}{}
		require.NoError(t, validateAuditToken("name", name))
		require.NoError(t, validateAuditEvent(Event{Name: name}))
	}
}

func TestKnownAuditEventReasonsAreValidAndUnique(t *testing.T) {
	seen := make(map[EventReason]struct{}, len(knownEventReasons))
	for _, reason := range knownEventReasons {
		require.NotContains(t, seen, reason)
		seen[reason] = struct{}{}
		require.NoError(t, validateAuditToken("reason", reason))
	}
}

func TestAuditEventValidationRejectsInvalidStructuredFields(t *testing.T) {
	negativeInt := -1
	negativeInt64 := int64(-1)
	zeroUint64 := uint64(0)
	validId := uuid.NewString()
	tests := map[string]Event{
		"domain":                {Name: "test.event", Domain: "other"},
		"outcome":               {Name: "test.event", Outcome: "other"},
		"authentication method": {Name: "test.event", AuthenticationMethod: "other"},
		"authentication phase":  {Name: "test.event", AuthenticationPhase: "other"},
		"session task":          {Name: "test.event", SessionTask: "other"},
		"error category":        {Name: "test.event", ErrorCategory: "other"},
		"target":                {Name: "test.event", Target: "invalid/target"},
		"flow":                  {Name: "test.event", Flow: "invalid/flow"},
		"authorization kind":    {Name: "test.event", AuthorizationKind: "invalid kind"},
		"reason":                {Name: "test.event", Reason: "invalid reason"},
		"connection ID":         {Name: "test.event", ConnectionId: "not-an-id"},
		"nil connection ID":     {Name: "test.event", ConnectionId: uuid.Nil.String()},
		"noncanonical ID":       {Name: "test.event", ConnectionId: "34E34AB8-7457-4D88-A5E4-C57791775C3A"},
		"session ID":            {Name: "test.event", SessionId: "not-an-id"},
		"operation ID":          {Name: "test.event", OperationId: "not-an-id"},
		"exit code":             {Name: "test.event", ExitCode: &negativeInt},
		"bytes read":            {Name: "test.event", BytesRead: &negativeInt64},
		"bytes written":         {Name: "test.event", BytesWritten: &negativeInt64},
		"duration":              {Name: "test.event", DurationMillis: &negativeInt64},
		"count":                 {Name: "test.event", Count: &zeroUint64},
	}

	for name, event := range tests {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validateAuditEvent(event))
		})
	}

	require.NoError(t, validateAuditEvent(Event{Name: "test.event", ConnectionId: validId, SessionId: validId, OperationId: validId}))
}

func TestAuditEventFlowEnforcesConfiguredByteLengthLimit(t *testing.T) {
	require.NoError(t, validateAuditEvent(Event{Name: "test.event", Flow: strings.Repeat("a", configuration.MaxFlowNameBytes)}))
	require.ErrorContains(t, validateAuditEvent(Event{Name: "test.event", Flow: strings.Repeat("a", configuration.MaxFlowNameBytes+1)}), "flow exceeds 255 bytes")
}

func TestAuditEventRecordingIdValidation(t *testing.T) {
	valid := "fd70203b-ea19-4288-8ec2-577b623e92d0"
	require.NoError(t, validateAuditEvent(Event{Name: "test.event", RecordingId: valid}))

	invalid := []string{
		"not-an-id",
		uuid.Nil.String(),
		"FD70203B-EA19-4288-8EC2-577B623E92D0",
		"fd70203bea1942888ec2577b623e92d0",
		"fd70203b-ea19-1288-8ec2-577b623e92d0",
		"fd70203b-ea19-4288-6ec2-577b623e92d0",
	}
	for _, value := range invalid {
		t.Run(value, func(t *testing.T) {
			err := validateAuditEvent(Event{Name: "test.event", RecordingId: value})
			require.ErrorContains(t, err, "illegal audit event recording ID")
		})
	}
}

func TestAuditEventRecordingDigestValidation(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	require.NoError(t, validateAuditEvent(Event{Name: "test.event", RecordingDigest: valid}))

	invalid := []string{
		valid[:len(valid)-1],
		"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		"g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	for _, value := range invalid {
		t.Run(value, func(t *testing.T) {
			err := validateAuditEvent(Event{Name: "test.event", RecordingDigest: value})
			require.ErrorContains(t, err, "illegal audit event recording digest")
		})
	}
}

func TestSessionRecordingAuditEventRequiresLifecycleFields(t *testing.T) {
	pty := true
	duration := int64(1)
	exitCode := 0
	base := Event{
		Domain:       EventDomainSession,
		Flow:         "main",
		ConnectionId: "34e34ab8-7457-4d88-a5e4-c57791775c3a",
		SessionId:    "82d8fdda-4730-43b7-bfde-72733c217bde",
		OperationId:  "6d05798f-b877-4191-8aa0-4576a30411ad",
		RecordingId:  "fd70203b-ea19-4288-8ec2-577b623e92d0",
		SessionTask:  SessionTaskShell,
	}
	started := base
	started.Name = EventNameSessionRecordingStarted
	started.Pty = &pty
	require.NoError(t, validateAuditEventForWrite(started))
	completed := base
	completed.Name = EventNameSessionRecordingCompleted
	completed.Outcome = EventOutcomeSuccess
	completed.RecordingDigest = strings.Repeat("a", 64)
	completed.DurationMillis = &duration
	completed.ExitCode = &exitCode
	require.NoError(t, validateAuditEventForWrite(completed))
	incomplete := base
	incomplete.Name = EventNameSessionRecordingIncomplete
	incomplete.Outcome = EventOutcomeFailure
	incomplete.Reason = EventReasonSessionError
	incomplete.RecordingDigest = strings.Repeat("b", 64)
	incomplete.DurationMillis = &duration
	incomplete.ErrorCategory = ErrorCategorySystem
	require.NoError(t, validateAuditEventForWrite(incomplete))
	failed := base
	failed.Name = EventNameSessionRecordingFailed
	failed.Outcome = EventOutcomeFailure
	failed.Reason = EventReasonRecordingCreate
	failed.ErrorCategory = ErrorCategorySystem
	require.NoError(t, validateAuditEventForWrite(failed))

	for name, mutate := range map[string]func(*Event){
		"missing flow":       func(event *Event) { event.Flow = "" },
		"missing connection": func(event *Event) { event.ConnectionId = "" },
		"missing session":    func(event *Event) { event.SessionId = "" },
		"missing operation":  func(event *Event) { event.OperationId = "" },
		"missing recording":  func(event *Event) { event.RecordingId = "" },
		"SFTP task":          func(event *Event) { event.SessionTask = SessionTaskSftp },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := started
			mutate(&candidate)
			require.Error(t, validateAuditEventForWrite(candidate))
		})
	}
	completed.RecordingDigest = ""
	require.Error(t, validateAuditEventForWrite(completed))
	incomplete.DurationMillis = nil
	require.Error(t, validateAuditEventForWrite(incomplete))
	failed.Reason = ""
	require.Error(t, validateAuditEventForWrite(failed))
}

func TestSessionRecordingAuditEventRejectsContradictoryLifecycleFields(t *testing.T) {
	duration := int64(1)
	exitCode := 1
	bytesRead := int64(1)
	base := Event{
		Domain:          EventDomainSession,
		Flow:            "main",
		ConnectionId:    "34e34ab8-7457-4d88-a5e4-c57791775c3a",
		SessionId:       "82d8fdda-4730-43b7-bfde-72733c217bde",
		OperationId:     "6d05798f-b877-4191-8aa0-4576a30411ad",
		RecordingId:     "fd70203b-ea19-4288-8ec2-577b623e92d0",
		RecordingDigest: strings.Repeat("c", 64),
		SessionTask:     SessionTaskExec,
		DurationMillis:  &duration,
	}
	for name, event := range map[string]Event{
		"canceled session error": {
			Name: EventNameSessionRecordingIncomplete, Outcome: EventOutcomeCanceled, Reason: EventReasonSessionError,
		},
		"failed cancellation": {
			Name: EventNameSessionRecordingIncomplete, Outcome: EventOutcomeFailure, Reason: EventReasonContextCanceled,
		},
		"session error without category": {
			Name: EventNameSessionRecordingIncomplete, Outcome: EventOutcomeFailure, Reason: EventReasonSessionError,
		},
		"failed arbitrary reason": {
			Name: EventNameSessionRecordingFailed, Outcome: EventOutcomeFailure, Reason: EventReasonSessionError, ErrorCategory: ErrorCategorySystem,
		},
		"invalid exit with exit code": {
			Name: EventNameSessionRecordingIncomplete, Outcome: EventOutcomeFailure, Reason: EventReasonInvalidExitCode, ExitCode: &exitCode,
		},
		"create failure with digest": {
			Name: EventNameSessionRecordingFailed, Outcome: EventOutcomeFailure, Reason: EventReasonRecordingCreate, ErrorCategory: ErrorCategorySystem,
		},
		"audit write failure with exit code": {
			Name: EventNameSessionRecordingFailed, Outcome: EventOutcomeFailure, Reason: EventReasonAuditWrite, ErrorCategory: ErrorCategorySystem, ExitCode: &exitCode,
		},
		"unrelated bytes": {
			Name: EventNameSessionRecordingIncomplete, Outcome: EventOutcomeFailure, Reason: EventReasonSessionError, ErrorCategory: ErrorCategorySystem, BytesRead: &bytesRead,
		},
	} {
		t.Run(name, func(t *testing.T) {
			event.Domain = base.Domain
			event.Flow = base.Flow
			event.ConnectionId = base.ConnectionId
			event.SessionId = base.SessionId
			event.OperationId = base.OperationId
			event.RecordingId = base.RecordingId
			event.RecordingDigest = base.RecordingDigest
			event.SessionTask = base.SessionTask
			event.DurationMillis = base.DurationMillis
			require.Error(t, validateAuditEventForWrite(event))
		})
	}
}

func TestSessionRecordingAuditWriteValidationDoesNotRejectExistingCustomEvents(t *testing.T) {
	event := Event{Name: EventNameSessionRecordingStarted}
	require.NoError(t, validateAuditEvent(event))
	require.Error(t, validateAuditEventForWrite(event))
}
