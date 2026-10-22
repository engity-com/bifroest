package service

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/https"
	"github.com/engity-com/bifroest/pkg/template"
)

func webOidcLoginFixture(t *testing.T, holdDevice ...bool) (*service, http.Handler, *oidcAssociationProvider, *recordingAuditRecorder) {
	t.Helper()
	provider := newOidcAssociationProviderWithDeviceHold(t, len(holdDevice) > 0 && holdDevice[0])
	conf := sessionRecordingTestConfiguration(t, t.TempDir())
	settings := &configuration.AuthorizationOidcDeviceAuth{}
	require.NoError(t, settings.SetDefaults())
	settings.Issuer = template.MustNewUrl(provider.server.URL)
	settings.ClientId = template.MustNewString("client")
	settings.ClientSecret = template.MustNewString("secret")
	conf.Flows[0].Authorization.V = settings
	conf.Flows[0].Http.RequestUser = commonBool(false)
	conf.Flows[0].DiscoverAsSlug = "Work"
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, provider.server.Client())
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepareContext(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, svc.Close()) })
	svc.web = newWebService(svc)
	recorder := &recordingAuditRecorder{}
	svc.flowAuditRecorders[conf.Flows[0].Name] = recorder
	boundary, err := https.Boundary(configuration.HttpDomains{"app.example.org"}, svc.web)
	require.NoError(t, err)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		boundary.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), oauth2.HTTPClient, provider.server.Client())))
	})
	return svc, handler, provider, recorder
}

func TestWebOidcDeviceLoginKeepsVerifiedIdentityAndRotatedGrant(t *testing.T) {
	svc, handler, provider, recorder := webOidcLoginFixture(t)
	login := func() string {
		token := startWebAttempt(t, handler, "interactive", "", "Work", nil)
		step := waitWebLoginStep(t, handler, token, "Work")
		require.Equal(t, "info", step.Kind)
		require.Contains(t, step.Message, provider.server.URL+"/verify")
		require.Contains(t, step.Message, "test-code")
		require.Equal(t, http.StatusAccepted, answerWebStep(handler, token, "Work", step, "").Code)
		return webTestToken(t, finishWebAttempt(t, handler, token, "Work"))
	}
	first := webTestAccess(t, svc, login(), "Work")
	require.Equal(t, "verified-subject", first.identity.Principal)
	require.Equal(t, provider.server.URL, first.identity.Issuer)
	require.Empty(t, first.user)
	stored := oidcAssociationStoredToken(t, first.auth.FindSession())
	stored["expiry"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(stored)
	require.NoError(t, err)
	require.NoError(t, first.auth.FindSession().SetAuthorizationToken(t.Context(), raw))
	provider.release()
	authorizer := svc.authorizer.(*authorization.AuthorizerFacade).OidcRefreshAuthorizer(first.auth.Flow())
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, provider.server.Client())
	_, lost, err := authorizer.RefreshSession(ctx, first.auth.FindSession())
	require.NoError(t, err)
	require.False(t, lost)
	second := webTestAccess(t, svc, login(), "Work")
	require.Equal(t, first.auth.FindSession().Id(), second.auth.FindSession().Id())
	retained := oidcAssociationStoredToken(t, second.auth.FindSession())
	require.Contains(t, retained["access_token"], "rotated-access-")
	require.Contains(t, retained["refresh_token"], "rotated-refresh-")
	require.EqualValues(t, 2, provider.logins.Load())
	require.Equal(t, 1, webSessionCount(t, svc))
	events := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted)
	require.Len(t, events, 2)
	for _, event := range events {
		require.Equal(t, audit.AuthenticationMethodKeyboardInteractive, event.AuthenticationMethod)
		require.Equal(t, "oidc-device-auth", event.AuthorizationKind)
	}
}

func TestWebOidcCancelInterruptsOutstandingProviderRequest(t *testing.T) {
	svc, handler, provider, recorder := webOidcLoginFixture(t, true)
	token := startWebAttempt(t, handler, "interactive", "", "Work", nil)
	step := waitWebLoginStep(t, handler, token, "Work")
	require.Equal(t, http.StatusAccepted, answerWebStep(handler, token, "Work", step, "").Code)
	select {
	case <-provider.deviceTokenStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("provider request did not start")
	}
	require.Equal(t, http.StatusNoContent, webAttemptRequest(handler, "cancel", token, map[string]string{"slug": "Work"}).Code)
	select {
	case <-provider.deviceTokenCanceled:
	case <-time.After(time.Second):
		t.Fatal("provider request ignored attempt cancellation")
	}
	require.NoError(t, svc.web.Close())
	require.Empty(t, svc.web.access)
	require.Zero(t, webSessionCount(t, svc))
	require.Empty(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted))
}
