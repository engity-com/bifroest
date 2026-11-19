package service

import (
	"crypto/sha256"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOidcCodeWebForwardedTicketCannotAuthorizeItsSender(t *testing.T) {
	svc, raw, provider, _ := oidcCodeFixture(t)
	attackerToken, forwardedLink, attacker := startOidcWeb(t, raw)
	link, err := url.Parse(forwardedLink)
	require.NoError(t, err)
	ticket := strings.TrimPrefix(link.Fragment, "start/")
	// A second profile follows only the URL. Document GET remains public and
	// side-effect free, but cannot plant an initiating-browser cookie in it.
	page := oidcRequest(raw, http.MethodGet, link.Path, "")
	require.Equal(t, http.StatusOK, page.Code)
	require.Empty(t, page.Result().Cookies())
	victim := oidcAPI(raw, "start", map[string]string{"ticket": ticket})
	require.Equal(t, http.StatusUnauthorized, victim.Code, "a forwarded WebUI ticket must not yield an IdP redirect")
	require.Empty(t, victim.Result().Cookies())
	require.NotContains(t, victim.Body.String(), "url")
	require.Zero(t, provider.logins.Load())
	svc.web.oidcMutex.Lock()
	tx := svc.web.oidcTickets[sha256.Sum256([]byte(ticket))]
	phase, id := tx.phase, tx.id
	svc.web.oidcMutex.Unlock()
	require.Equal(t, "created", phase, "a foreign browser must not consume or cancel the original ticket")
	require.Empty(t, id)
	svc.web.mutex.Lock()
	accessCount := len(svc.web.access)
	svc.web.mutex.Unlock()
	require.Zero(t, accessCount)
	// The actual initiator can still use its own login normally.
	browser := openOidcBrowser(t, attacker, provider, forwardedLink)
	require.Equal(t, http.StatusOK, oidcCallbackRequest(attacker, browser.callback, browser.cookie).Code)
	require.Equal(t, http.StatusOK, finishWebAttempt(t, attacker, attackerToken, "Work").Code)
}

func TestOidcCodeWebInitiatorBindingProtectsStartCallbackAndClaim(t *testing.T) {
	svc, raw, provider, _ := oidcCodeFixture(t)
	token, link, owner := startOidcWeb(t, raw)
	cookie := owner.(*oidcTestInitiatingBrowser).cookie
	wrong := *cookie
	var err error
	wrong.Value, err = oidcRandom()
	require.NoError(t, err)
	malformed := *cookie
	malformed.Value = "not-a-binding"
	duplicate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.AddCookie(cookie)
		r.AddCookie(cookie)
		raw.ServeHTTP(w, r)
	})
	foreign := map[string]http.Handler{
		"missing":   raw,
		"wrong":     oidcTestInitiator(raw, &wrong),
		"malformed": oidcTestInitiator(raw, &malformed),
		"duplicate": duplicate,
	}
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	start := map[string]string{"ticket": strings.TrimPrefix(parsed.Fragment, "start/")}
	for name, browser := range foreign {
		t.Run("start/"+name, func(t *testing.T) {
			require.Equal(t, http.StatusUnauthorized, oidcAPI(browser, "start", start).Code)
		})
	}
	browser := openOidcBrowser(t, owner, provider, link)
	for name, client := range foreign {
		t.Run("callback/"+name, func(t *testing.T) {
			// Even possession of the later callback-binding cookie cannot replace
			// the browser binding established BEFORE the IdP redirect.
			require.Equal(t, http.StatusUnauthorized, oidcCallbackRequest(client, browser.callback, browser.cookie).Code)
		})
	}
	require.Zero(t, provider.logins.Load(), "foreign callbacks must never exchange the provider code")
	require.Equal(t, http.StatusOK, oidcCallbackRequest(owner, browser.callback, browser.cookie).Code)
	awaitOidcPrimary(t, svc, token)
	for name, client := range foreign {
		t.Run("control/"+name, func(t *testing.T) {
			// These requests use the SAME direct peer and a valid attempt bearer,
			// isolating the browser binding from the existing peer/bearer checks.
			for _, route := range []string{"poll", "cancel"} {
				require.Equal(t, http.StatusUnauthorized, webAttemptRequest(client, route, token, map[string]string{"slug": "Work"}).Code)
			}
			require.Equal(t, http.StatusUnauthorized, webAttemptRequest(client, "reply", token, map[string]string{"slug": "Work", "sequence": "1"}).Code)
			require.Equal(t, http.StatusUnauthorized, oidcAPI(client, "status", map[string]string{"id": browser.id}, browser.cookie).Code)
		})
	}
	// The cookie alone is not authentication, and foreign controls did not consume
	// the legitimate owner's one-time claim or turn cancellation into a DoS.
	require.Equal(t, http.StatusUnauthorized, webAttemptRequest(owner, "poll", "", map[string]string{"slug": "Work"}).Code)
	svc.web.mutex.Lock()
	accessCount := len(svc.web.access)
	svc.web.mutex.Unlock()
	require.Zero(t, accessCount)
	access := webTestAccess(t, svc, webTestToken(t, finishWebAttempt(t, owner, token, "Work")), "Work")
	require.Equal(t, "verified-subject", access.identity.Subject)
	require.Equal(t, "accepted", oidcView(t, oidcAPI(owner, "status", map[string]string{"id": browser.id}, browser.cookie)).Status)
}
