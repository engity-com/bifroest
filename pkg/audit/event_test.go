package audit

import (
	"encoding/json"
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
		Name:                 "session.task.completed",
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
	require.NoError(t, validateAuditEvent(event))
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
