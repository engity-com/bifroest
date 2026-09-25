package service

import (
	"context"
	goerrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestHouseKeeperOIDCFinalRetentionClearsLocalTokenWithoutRestore(t *testing.T) {
	for name, restoreErr := range map[string]error{
		"invalid signature": goerrors.New("persistent OIDC ID token signature failure"),
		"UserInfo network":  errors.Network.Newf("UserInfo endpoint unavailable"),
	} {
		t.Run(name, func(t *testing.T) {
			recorder := &recordingAuditRecorder{}
			repository := &houseKeeperTestSessionRepository{}
			authorizer := &houseKeeperTestAuthorizer{restoreErr: restoreErr}
			sess := &houseKeeperTestSession{
				flow: "current", id: session.MustNewId(),
				validUntil: time.Now().Add(-2 * time.Hour), authorizationToken: []byte("oidc-token"),
			}
			hk := newHouseKeeperForTest(repository, authorizer)
			hk.service.Configuration.Flows = configuration.Flows{{Name: sess.flow, Authorization: configuration.Authorization{V: &configuration.AuthorizationOidcDeviceAuth{}}}}
			hk.service.Configuration.HouseKeeping.KeepExpiredFor.SetNative(time.Hour)
			hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: "security", Enabled: true}}
			hk.service.flowAuditRecorders[sess.flow] = recorder

			canContinue, err := hk.inspectSession(context.Background(), sess)
			require.NoError(t, err)
			require.True(t, canContinue)
			require.Zero(t, authorizer.restoreCalls)
			require.Equal(t, 1, sess.authorizationTokenCalls)
			require.Equal(t, 1, sess.setAuthorizationTokenCalls)
			require.Empty(t, sess.authorizationToken)
			require.Equal(t, 1, repository.deleteCalls)

			events := recorder.eventsSnapshot()
			require.Len(t, events, 4)
			require.Equal(t, audit.EventNameHousekeepingSessionDisposeStarted, events[0].Name)
			require.Equal(t, audit.EventNameHousekeepingSessionDisposeCompleted, events[1].Name)
			require.Equal(t, audit.EventNameHousekeepingSessionDeleteStarted, events[2].Name)
			require.Equal(t, audit.EventNameHousekeepingSessionDeleteCompleted, events[3].Name)
			require.Equal(t, audit.EventReasonRetentionElapsed, events[0].Reason)
			require.Equal(t, audit.EventReasonRetentionElapsed, events[2].Reason)
			require.Equal(t, audit.EventOutcomeSuccess, events[1].Outcome)
			require.Equal(t, audit.EventOutcomeSuccess, events[3].Outcome)
			require.Equal(t, events[0].OperationId, events[1].OperationId)
			require.Equal(t, events[2].OperationId, events[3].OperationId)
		})
	}
}

func TestHouseKeeperOIDCOnlyBypassesRestoreAfterRetentionAndSuccessfulTokenAccess(t *testing.T) {
	for _, tc := range []struct {
		name            string
		beforeRetention bool
		disposed        bool
		nonOIDC         bool
		readErr         error
		writeErr        error
		wantReadCalls   int
		wantSetCalls    int
		wantRestores    int
		wantReason      audit.EventReason
	}{
		{name: "temporary failure before retention", beforeRetention: true, wantRestores: 1, wantReason: audit.EventReasonExpired},
		{name: "already disposed before retention", beforeRetention: true, disposed: true, wantRestores: 1, wantReason: audit.EventReasonExpired},
		{name: "write failure at final retention", writeErr: goerrors.New("storage unavailable"), wantReadCalls: 1, wantSetCalls: 1, wantReason: audit.EventReasonRetentionElapsed},
		{name: "read failure at final retention", readErr: goerrors.New("storage unavailable"), wantReadCalls: 1, wantReason: audit.EventReasonRetentionElapsed},
		{name: "non-OIDC at final retention", nonOIDC: true, wantRestores: 1, wantReason: audit.EventReasonRetentionElapsed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &recordingAuditRecorder{}
			repository := &houseKeeperTestSessionRepository{}
			authorizer := &houseKeeperTestAuthorizer{restoreErr: errors.Network.Newf("UserInfo temporarily unavailable")}
			sess := &houseKeeperTestSession{
				flow: "current", id: session.MustNewId(), validUntil: time.Now().Add(-2 * time.Hour),
				authorizationToken: []byte("oidc-token"), authorizationTokenError: tc.readErr,
				setAuthorizationTokenError: tc.writeErr,
			}
			if tc.beforeRetention {
				sess.validUntil = time.Now().Add(-time.Minute)
			}
			if tc.disposed {
				sess.state = session.StateDisposed
			}
			hk := newHouseKeeperForTest(repository, authorizer)
			authConfig := configuration.Authorization{V: &configuration.AuthorizationOidcDeviceAuth{}}
			if tc.nonOIDC {
				authConfig = configuration.Authorization{V: &configuration.AuthorizationNone{}}
			}
			hk.service.Configuration.Flows = configuration.Flows{{Name: sess.flow, Authorization: authConfig}}
			hk.service.Configuration.HouseKeeping.KeepExpiredFor.SetNative(time.Hour)
			hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: "security", Enabled: true}}
			hk.service.flowAuditRecorders[sess.flow] = recorder

			canContinue, err := hk.inspectSession(context.Background(), sess)
			require.NoError(t, err)
			require.True(t, canContinue)
			require.Equal(t, tc.wantRestores, authorizer.restoreCalls)
			require.Equal(t, tc.wantReadCalls, sess.authorizationTokenCalls)
			require.Equal(t, tc.wantSetCalls, sess.setAuthorizationTokenCalls)
			require.Equal(t, []byte("oidc-token"), sess.authorizationToken)
			require.Zero(t, repository.deleteCalls)

			events := recorder.eventsSnapshot()
			require.Len(t, events, 2)
			require.Equal(t, audit.EventNameHousekeepingSessionDisposeStarted, events[0].Name)
			require.Equal(t, audit.EventNameHousekeepingSessionDisposeCompleted, events[1].Name)
			require.Equal(t, tc.wantReason, events[0].Reason)
			require.Equal(t, audit.EventOutcomeFailure, events[1].Outcome)
			require.Equal(t, events[0].OperationId, events[1].OperationId)
		})
	}
}
