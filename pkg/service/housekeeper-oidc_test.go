package service

import (
	"context"
	goerrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

type housekeepingWritingAuthorizer struct {
	authorization.CloseableAuthorizer
	restoreCalls int
}

func (this *housekeepingWritingAuthorizer) RestoreFromSession(ctx context.Context, sess session.Session, _ *authorization.RestoreOpts) (authorization.Authorization, error) {
	this.restoreCalls++
	return nil, sess.SetAuthorizationToken(ctx, []byte("refreshed-token"))
}

type housekeepingDisposedTokenSession struct {
	*houseKeeperTestSession
	rejectedWrites int
}

func (this *housekeepingDisposedTokenSession) Dispose(ctx context.Context) (bool, error) {
	disposed, err := this.houseKeeperTestSession.Dispose(ctx)
	if err == nil {
		this.state = session.StateDisposed
	}
	return disposed, err
}

func (this *housekeepingDisposedTokenSession) SetAuthorizationToken(ctx context.Context, token []byte) error {
	if this.state == session.StateDisposed && len(token) != 0 {
		this.rejectedWrites++
		return goerrors.New("cannot write authorization token to disposed session")
	}
	return this.houseKeeperTestSession.SetAuthorizationToken(ctx, token)
}

func TestHouseKeeperOIDCCleanupBeforeRetentionWithDisposedSession(t *testing.T) {
	recorder := &recordingAuditRecorder{}
	repository := &houseKeeperTestSessionRepository{}
	authorizer := &housekeepingWritingAuthorizer{}
	sess := &housekeepingDisposedTokenSession{houseKeeperTestSession: &houseKeeperTestSession{
		flow: "current", id: session.MustNewId(), validUntil: time.Now().Add(-time.Minute),
		authorizationToken: []byte("oidc-token"),
	}}
	hk := newHouseKeeperForTest(repository, nil)
	hk.service.authorizer = authorizer
	hk.service.Configuration.Flows = configuration.Flows{{Name: sess.flow, Authorization: configuration.Authorization{V: &configuration.AuthorizationOidcDeviceAuth{}}}}
	hk.service.Configuration.HouseKeeping.KeepExpiredFor.SetNative(time.Hour)
	hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: "security", Enabled: true}}
	hk.service.flowAuditRecorders[sess.flow] = recorder

	for range 2 {
		canContinue, err := hk.inspectSession(t.Context(), sess)
		require.NoError(t, err)
		require.True(t, canContinue)
	}
	require.Equal(t, session.StateDisposed, sess.state)
	require.Empty(t, sess.authorizationToken)
	require.Equal(t, 2, sess.authorizationTokenCalls)
	require.Equal(t, 1, sess.setAuthorizationTokenCalls)
	require.Zero(t, sess.rejectedWrites)
	require.Zero(t, authorizer.restoreCalls)
	require.Zero(t, repository.deleteCalls)
	events := recorder.eventsSnapshot()
	require.Len(t, events, 4)
	for i := 0; i < len(events); i += 2 {
		require.Equal(t, audit.EventNameHousekeepingSessionDisposeStarted, events[i].Name)
		require.Equal(t, audit.EventNameHousekeepingSessionDisposeCompleted, events[i+1].Name)
		require.Equal(t, audit.EventReasonExpired, events[i].Reason)
		require.Equal(t, audit.EventOutcomeSuccess, events[i+1].Outcome)
		require.Equal(t, events[i].OperationId, events[i+1].OperationId)
	}
	require.ErrorContains(t, sess.SetAuthorizationToken(t.Context(), []byte("refreshed-token")), "disposed session")
	require.Equal(t, 1, sess.rejectedWrites)
}

func TestHouseKeeperOIDCCleanupWaitsForAuditAndEnvironment(t *testing.T) {
	for _, name := range []string{"audit start failure", "environment token mismatch", "environment disposal failure"} {
		t.Run(name, func(t *testing.T) {
			recorder := &recordingAuditRecorder{}
			authorizer := &houseKeeperTestAuthorizer{restoreErr: errors.Network.Newf("provider unavailable")}
			sess := &houseKeeperTestSession{
				flow: "current", id: session.MustNewId(), validUntil: time.Now().Add(-time.Minute),
				authorizationToken: []byte("oidc-token"),
			}
			hk := newHouseKeeperForTest(&houseKeeperTestSessionRepository{}, authorizer)
			hk.service.Configuration.Flows = configuration.Flows{{Name: sess.flow, Authorization: configuration.Authorization{V: &configuration.AuthorizationOidcDeviceAuth{}}}}
			hk.service.Configuration.HouseKeeping.KeepExpiredFor.SetNative(time.Hour)
			hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: "security", Enabled: true}}
			hk.service.flowAuditRecorders[sess.flow] = recorder
			environments := hk.service.environments.(*houseKeeperTestEnvironmentRepository)
			switch name {
			case "audit start failure":
				recorder.setErrorBeforeRecordForName(audit.EventNameHousekeepingSessionDisposeStarted, goerrors.New("audit unavailable"))
			case "environment token mismatch":
				environments.checkToken = true
				environments.tokenMatches = false
			case "environment disposal failure":
				environments.findResult = &houseKeeperTestEnvironment{disposeErr: goerrors.New("environment unavailable")}
			}

			_, err := hk.inspectSession(t.Context(), sess)
			require.NoError(t, err)
			require.Equal(t, []byte("oidc-token"), sess.authorizationToken)
			require.Zero(t, sess.authorizationTokenCalls)
			require.Zero(t, sess.setAuthorizationTokenCalls)
			require.Zero(t, authorizer.restoreCalls)
			if name == "environment disposal failure" {
				require.Equal(t, audit.EventOutcomeFailure, recorder.eventsSnapshot()[1].Outcome)
				environments.findResult.(*houseKeeperTestEnvironment).disposeErr = nil
				_, err = hk.inspectSession(t.Context(), sess)
				require.NoError(t, err)
				require.Empty(t, sess.authorizationToken)
				require.Equal(t, 1, sess.setAuthorizationTokenCalls)
				require.Zero(t, authorizer.restoreCalls)
				require.Equal(t, audit.EventOutcomeSuccess, recorder.eventsSnapshot()[3].Outcome)
			} else {
				require.Zero(t, sess.disposeCalls)
				require.Zero(t, environments.findCalls)
			}
		})
	}
}

func TestHouseKeeperForgetsOIDCRevocationAfterFinalDeleteEvenIfAuditCompletionFails(t *testing.T) {
	repository := &houseKeeperTestSessionRepository{}
	hk := newHouseKeeperForTest(repository, &houseKeeperTestAuthorizer{restoreErr: authorization.ErrNoSuchAuthorization})
	sess := &houseKeeperTestSession{
		flow: "current", id: session.MustNewId(), validUntil: time.Now().Add(-2 * time.Hour), authorizationToken: []byte("oidc-token"),
	}
	hk.service.Configuration.Flows = configuration.Flows{{Name: sess.flow, Authorization: configuration.Authorization{V: &configuration.AuthorizationOidcDeviceAuth{}}}}
	hk.service.Configuration.HouseKeeping.KeepExpiredFor.SetNative(time.Hour)
	hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: "security", Enabled: true}}
	recorder := &recordingAuditRecorder{}
	recorder.setErrorBeforeRecordForName(audit.EventNameHousekeepingSessionDeleteCompleted, goerrors.New("audit completion unavailable"))
	hk.service.flowAuditRecorders[sess.flow] = recorder
	key := sessionConnectionKey{flow: sess.flow, id: sess.id}
	hk.service.oidcRefresh.invalidating = map[sessionConnectionKey]struct{}{key: {}}
	hk.service.sessionConnections.revoke(sess.flow, sess.id)

	_, err := hk.inspectSession(context.Background(), sess)
	require.NoError(t, err) // Housekeeping reports audit failures and continues.
	require.Equal(t, 1, repository.deleteCalls)
	require.NotContains(t, hk.service.oidcRefresh.invalidating, key)
	require.NotContains(t, hk.service.sessionConnections.sessions, key)
	require.Empty(t, sess.authorizationToken)
}

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

func TestHouseKeeperOIDCOnlyBypassesRestoreAndSuccessfulTokenAccess(t *testing.T) {
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
		{name: "write failure before retention", beforeRetention: true, writeErr: goerrors.New("storage unavailable"), wantReadCalls: 1, wantSetCalls: 1, wantReason: audit.EventReasonExpired},
		{name: "read failure before retention", beforeRetention: true, disposed: true, readErr: goerrors.New("storage unavailable"), wantReadCalls: 1, wantReason: audit.EventReasonExpired},
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
