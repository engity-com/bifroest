package service

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestSessionRecordingDeliveryAuditorRecordsPersistentTransitions(t *testing.T) {
	recorder := &recordingAuditRecorder{}
	svc := &service{auditRecorders: map[configuration.AuditlogName]audit.Recorder{"security": recorder}}
	auditor := &sessionRecordingDeliveryAuditor{
		service:    svc,
		auditlog:   "security",
		repository: &sessionRecordingRepository{format: sessionRecordingRepositoryFormatCastZstd},
	}
	base := audit.RemoteArtifactDeliveryAuditEvent{
		Scope:       audit.RemoteTargetScope{Auditlog: "security", Target: "archive"},
		FileName:    "fd70203b-ea19-4288-8ec2-577b623e92d0.cast.zst",
		OperationId: "6d05798f-b877-4191-8aa0-4576a30411ad",
	}
	failed := base
	failed.State = audit.RemoteArtifactDeliveryAuditFailed
	failed.ErrorCategory = audit.ErrorCategoryNetwork
	require.NoError(t, auditor.RecordRemoteArtifactDelivery(t.Context(), failed))
	succeeded := base
	succeeded.State = audit.RemoteArtifactDeliveryAuditSucceeded
	require.NoError(t, auditor.RecordRemoteArtifactDelivery(t.Context(), succeeded))

	events := recorder.eventsSnapshot()
	require.Equal(t, []audit.Event{
		{
			Name: audit.EventNameSessionRecordingDeliveryFailed, Domain: audit.EventDomainSession, Outcome: audit.EventOutcomeFailure,
			OperationId: base.OperationId, RecordingId: "fd70203b-ea19-4288-8ec2-577b623e92d0", Target: "archive", ErrorCategory: audit.ErrorCategoryNetwork,
		},
		{
			Name: audit.EventNameSessionRecordingDeliverySucceeded, Domain: audit.EventDomainSession, Outcome: audit.EventOutcomeSuccess,
			OperationId: base.OperationId, RecordingId: "fd70203b-ea19-4288-8ec2-577b623e92d0", Target: "archive",
		},
	}, events)
}
