package service

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/session"
)

func TestIndependentInstancesDoNotShareBrowserAccessOrPendingLogins(t *testing.T) {
	first, firstHandler, _ := webTestFixture(t)
	second, secondHandler, _ := webTestFixture(t)
	firstToken := webTestToken(t, webTestPassword(firstHandler, "alice", "correct", "Work"))
	secondToken := webTestToken(t, webTestPassword(secondHandler, "alice", "correct", "Work"))
	firstSession := webTestAccess(t, first, firstToken, "Work").auth.FindSession().Id()
	secondSession := webTestAccess(t, second, secondToken, "Work").auth.FindSession().Id()
	require.NotEqual(t, firstSession, secondSession)

	for _, test := range []struct {
		name         string
		owner, other http.Handler
		token        string
	}{
		{"first", firstHandler, secondHandler, firstToken},
		{"second", secondHandler, firstHandler, secondToken},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, http.StatusOK, webTestRequest(test.owner, http.MethodPost, "app.example.org", webAPI+"access", `{"slug":"Work"}`, test.token).Code)
			require.Equal(t, http.StatusUnauthorized, webTestRequest(test.other, http.MethodPost, "app.example.org", webAPI+"access", `{"slug":"Work"}`, test.token).Code)

			pending := startWebAttempt(t, test.owner, "interactive", "alice", "Work", nil)
			step := waitWebLoginStep(t, test.owner, pending, "Work")
			require.Equal(t, http.StatusUnauthorized, answerWebStep(test.other, pending, "Work", step, "correct").Code)
			require.Equal(t, http.StatusUnauthorized, webAttemptRequest(test.other, "poll", pending, map[string]string{"slug": "Work"}).Code)
			require.Equal(t, http.StatusAccepted, answerWebStep(test.owner, pending, "Work", step, "correct").Code)
			webTestToken(t, finishWebAttempt(t, test.owner, pending, "Work"))
		})
	}
	require.Equal(t, 1, webSessionCount(t, first))
	require.Equal(t, 1, webSessionCount(t, second))
}

func TestIndependentInstancesDoNotShareRememberMeRegistrations(t *testing.T) {
	first, firstHandler, _ := webTestFixture(t)
	second, secondHandler, _ := webTestFixture(t)
	key, public := rememberTestKey(t)
	token := webTestToken(t, webTestPassword(firstHandler, "alice", "correct", "Work"))
	binding := rememberTestEnroll(t, firstHandler, token, public, key)

	response := rememberTestRequest(secondHandler, "resume", "", binding.selector())
	require.Equal(t, http.StatusUnauthorized, response.Code, response.Body.String())
	require.Zero(t, webSessionCount(t, second), "same origin, login policy and browser key do not replicate a saved session")
	resumed := rememberTestResume(t, firstHandler, binding, key)
	require.Equal(t, binding.SessionID, webTestAccess(t, first, resumed, "Work").auth.FindSession().Id().String())
	require.Equal(t, 1, webSessionCount(t, first))
}

func TestIndependentInstancesDoNotShareOidcTransactions(t *testing.T) {
	first, firstHandler, provider, _ := oidcCodeFixture(t)
	second, secondHandler, otherProvider, _ := oidcCodeFixture(t)
	token, link, initiatingBrowser := startOidcWeb(t, firstHandler)
	browser := openOidcBrowser(t, initiatingBrowser, provider, link)

	require.Equal(t, http.StatusUnauthorized, oidcCallbackRequest(secondHandler, browser.callback, browser.cookie).Code)
	require.Zero(t, provider.logins.Load())
	require.Zero(t, otherProvider.logins.Load())
	require.Zero(t, webSessionCount(t, second))
	require.Equal(t, http.StatusOK, oidcCallbackRequest(initiatingBrowser, browser.callback, browser.cookie).Code)
	webTestToken(t, finishWebAttempt(t, initiatingBrowser, token, "Work"))
	require.EqualValues(t, 1, provider.logins.Load())
	require.Equal(t, 1, webSessionCount(t, first))
}

func TestIndependentInstancesKeepManagementInventoryAndConfirmationsLocal(t *testing.T) {
	first, firstHandler, _, firstManager, _, firstTarget := managementActionFixture(t)
	second, secondHandler, _, secondManager, _, secondTarget := managementActionFixture(t)
	for _, test := range []struct {
		name    string
		handler http.Handler
		manager string
		local   session.Session
		foreign session.Session
	}{
		{"first", firstHandler, firstManager, firstTarget, secondTarget},
		{"second", secondHandler, secondManager, secondTarget, firstTarget},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, page, body := managementWebRead(t, test.handler, test.manager, "sessions/list", map[string]string{"flow": "worker", "state": "all"})
			require.Equal(t, http.StatusOK, code, body)
			require.Len(t, page.Sessions.Items, 1)
			require.Equal(t, test.local.Id().String(), page.Sessions.Items[0].ID)
			code, _, body = managementWebRead(t, test.handler, test.manager, "sessions/show", map[string]string{"flow": "worker", "id": test.foreign.Id().String()})
			require.Equal(t, http.StatusNotFound, code, body)
			response := managementActionRequest(test.handler, test.manager, "prepare", map[string]string{"flow": "worker", "id": test.foreign.Id().String(), "action": "dispose"})
			require.Equal(t, http.StatusServiceUnavailable, response.Code, response.Body.String())
			require.NotContains(t, response.Body.String(), "confirmationToken")
			info, err := test.foreign.Info(t.Context())
			require.NoError(t, err)
			require.NotEqual(t, session.StateDisposed, info.State())
		})
	}

	prepared := prepareManagementAction(t, firstHandler, firstManager, "disconnect", firstTarget)
	response := managementActionRequest(secondHandler, secondManager, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken})
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	response = managementActionRequest(firstHandler, firstManager, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	for _, svc := range []*service{first, second} {
		require.Equal(t, 2, webSessionCount(t, svc))
	}
}
