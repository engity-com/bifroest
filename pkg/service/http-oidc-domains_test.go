package service

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestOidcCodeWebDomainSelectionMatchesDiscovery(t *testing.T) {
	for _, test := range []struct {
		name          string
		matchingFirst bool
		explicitHost  bool
	}{
		{name: "matching-domain-first", matchingFirst: true},
		{name: "foreign-domain-first"},
		{name: "foreign-domain-first-with-host-filter", explicitHost: true},
	} {
		for _, named := range []bool{false, true} {
			mode, user := "nameless", ""
			if named {
				mode, user = "named", "alice"
			}
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				svc, handler, provider, _ := oidcCodeFixture(t, func(conf *configuration.Configuration, _ *oidcCodeProvider) {
					conf.Http.Domains = configuration.HttpDomains{"app.example.org", "other.example.org"}
					foreign := conf.Flows[0]
					foreign.DiscoverAsSlug = ""
					foreign.Http.RequestUser = commonBool(named)
					foreignCode := *foreign.Authorization.V.(*configuration.AuthorizationOidcAuthorizationCode)
					foreignCode.Domain = "other.example.org"
					foreign.Authorization.V = &foreignCode
					matching := foreign
					matching.Name = "matching-domain"
					matchingCode := foreignCode
					matchingCode.Domain = "app.example.org"
					matching.Authorization.V = &matchingCode
					if test.explicitHost {
						foreign.Requirement.Http.IncludedHost = common.MustNewRegexp(`^other\.example\.org$`)
					}
					conf.Flows = configuration.Flows{foreign, matching}
					if test.matchingFirst {
						conf.Flows[0], conf.Flows[1] = conf.Flows[1], conf.Flows[0]
					}
				})
				discovery := webTestDiscovery(handler, "Work")
				require.Equal(t, http.StatusOK, discovery.Code, discovery.Body.String())
				require.Contains(t, discovery.Body.String(), `"method":"oidc"`)
				started := webAttemptRequest(handler, "oidc", "", map[string]string{"slug": "Work", "user": user})
				require.Equal(t, http.StatusAccepted, started.Code, started.Body.String())
				var pending webLoginPending
				require.NoError(t, json.Unmarshal(started.Body.Bytes(), &pending))
				cookies := started.Result().Cookies()
				require.Len(t, cookies, 1)
				owner := oidcTestInitiator(handler, cookies[0])
				t.Cleanup(func() { webAttemptRequest(owner, "cancel", pending.AttemptToken, map[string]string{"slug": "Work"}) })
				step := waitWebLoginStep(t, owner, pending.AttemptToken, "Work")
				require.Contains(t, step.Message, "https://app.example.org/login/#start/")
				require.Zero(t, provider.logins.Load())
				// The skipped domain must not allocate a transaction or send an IdP URL.
				svc.web.oidcMutex.Lock()
				flows := make([]configuration.FlowName, 0, len(svc.web.oidcTickets))
				for _, tx := range svc.web.oidcTickets {
					flows = append(flows, tx.client.CodeFlow())
				}
				svc.web.oidcMutex.Unlock()
				require.Equal(t, []configuration.FlowName{"matching-domain"}, flows)
				require.Equal(t, http.StatusAccepted, answerWebStep(owner, pending.AttemptToken, "Work", step, "").Code)
				link := strings.TrimPrefix(step.Message, "Open the following URL in your browser to login: ")
				browser := openOidcBrowser(t, owner, provider, link)
				require.Equal(t, http.StatusOK, oidcCallbackRequest(owner, browser.callback, browser.cookie).Code)
				granted := webTestAccess(t, svc, webTestToken(t, finishWebAttempt(t, owner, pending.AttemptToken, "Work")), "Work")
				require.Equal(t, configuration.FlowName("matching-domain"), granted.auth.Flow())
				require.Equal(t, user, granted.user)
			})
		}
	}
}

func TestOidcCodeWebDomainFilteringDoesNotBypassPublishedSlugPinning(t *testing.T) {
	for _, published := range []bool{false, true} {
		name := "no-matching-domain"
		if published {
			name = "published-foreign-domain-with-matching-fallback"
		}
		t.Run(name, func(t *testing.T) {
			svc, handler, provider, _ := oidcCodeFixture(t, func(conf *configuration.Configuration, _ *oidcCodeProvider) {
				conf.Http.Domains = configuration.HttpDomains{"app.example.org", "other.example.org"}
				foreign := &conf.Flows[0]
				foreign.Authorization.V.(*configuration.AuthorizationOidcAuthorizationCode).Domain = "other.example.org"
				if !published {
					foreign.DiscoverAsSlug = ""
					return
				}
				matching := *foreign
				matching.Name, matching.DiscoverAsSlug = "matching-domain", ""
				matchingCode := *foreign.Authorization.V.(*configuration.AuthorizationOidcAuthorizationCode)
				matchingCode.Domain = "app.example.org"
				matching.Authorization.V = &matchingCode
				conf.Flows = append(conf.Flows, matching)
			})
			discovery := webTestDiscovery(handler, "Work")
			require.Equal(t, http.StatusOK, discovery.Code, discovery.Body.String())
			require.NotContains(t, discovery.Body.String(), `"method":"oidc"`)
			// A forged method selection must neither cross domains nor escape a
			// published flow into an otherwise matching hidden fallback.
			started := webAttemptRequest(handler, "oidc", "", map[string]string{"slug": "Work", "user": ""})
			require.Equal(t, http.StatusAccepted, started.Code, started.Body.String())
			var pending webLoginPending
			require.NoError(t, json.Unmarshal(started.Body.Bytes(), &pending))
			cookies := started.Result().Cookies()
			require.Len(t, cookies, 1)
			owner := oidcTestInitiator(handler, cookies[0])
			require.Equal(t, http.StatusUnauthorized, finishWebAttempt(t, owner, pending.AttemptToken, "Work").Code)
			require.Zero(t, provider.logins.Load())
			require.Zero(t, webSessionCount(t, svc))
			svc.web.oidcMutex.Lock()
			count := len(svc.web.oidcTickets)
			svc.web.oidcMutex.Unlock()
			require.Zero(t, count)
		})
	}
}
