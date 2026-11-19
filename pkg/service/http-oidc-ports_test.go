package service

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

func TestOidcCodeWebPortSelectionMatchesDiscovery(t *testing.T) {
	for _, test := range []struct {
		name      string
		primary   string
		authority string
		origin    string
		eligible  bool
	}{
		{"primary-port", "8443", "app.example.org:8443", "https://app.example.org:8443", true},
		{"secondary-port", "8443", "app.example.org:9443", "https://app.example.org:8443", false},
		{"normalized-primary-port", "8443", "APP.EXAMPLE.ORG.:08443", "https://app.example.org:8443", true},
		{"default-port", "443", "app.example.org", "https://app.example.org", true},
		{"explicit-default-port", "443", "app.example.org:443", "https://app.example.org", true},
		{"normalized-default-port", "443", "APP.EXAMPLE.ORG.:00443", "https://app.example.org", true},
		{"secondary-port-with-default-primary", "443", "app.example.org:9443", "https://app.example.org", false},
	} {
		for _, named := range []bool{false, true} {
			mode, user := "nameless", ""
			if named {
				mode, user = "named", "alice"
			}
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				svc, raw, provider, _ := oidcCodeFixture(t, func(conf *configuration.Configuration, _ *oidcCodeProvider) {
					conf.Http.Addresses = bnet.NetAddresses{bnet.MustNewAddress("127.0.0.1:" + test.primary), bnet.MustNewAddress("127.0.0.1:9443")}
					conf.Flows[0].Http.RequestUser = commonBool(named)
					// Requirements still receive a canonical hostname, never a port.
					conf.Flows[0].Requirement.Http.IncludedHost = common.MustNewRegexp(`^app\.example\.org$`)
					conf.Flows[0].Requirement.Http.IncludedSlug = common.MustNewRegexp(`^(|Work)$`)
				})
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					r = r.Clone(r.Context())
					r.Host = test.authority
					if r.Header.Get("Origin") != "" {
						r.Header.Set("Origin", "https://"+test.authority)
					}
					raw.ServeHTTP(w, r)
				})
				for _, slug := range []string{"", "Work"} {
					discovery := webTestDiscovery(handler, slug)
					require.Equal(t, http.StatusOK, discovery.Code, discovery.Body.String())
					require.Equal(t, test.eligible, containsOidcLoginOption(t, discovery.Body.Bytes()), "slug=%q: %s", slug, discovery.Body.String())
				}
				started := webAttemptRequest(handler, "oidc", "", map[string]string{"slug": "Work", "user": user})
				require.Equal(t, http.StatusAccepted, started.Code, started.Body.String())
				var pending webLoginPending
				require.NoError(t, json.Unmarshal(started.Body.Bytes(), &pending))
				cookies := started.Result().Cookies()
				require.Len(t, cookies, 1)
				owner := oidcTestInitiator(handler, cookies[0])
				t.Cleanup(func() { webAttemptRequest(owner, "cancel", pending.AttemptToken, map[string]string{"slug": "Work"}) })
				if !test.eligible {
					// Even a forged method choice must fail before allocating a ticket.
					require.Equal(t, http.StatusUnauthorized, finishWebAttempt(t, owner, pending.AttemptToken, "Work").Code)
					require.Zero(t, provider.logins.Load())
					require.Zero(t, webSessionCount(t, svc))
					svc.web.oidcMutex.Lock()
					count := len(svc.web.oidcTickets)
					svc.web.oidcMutex.Unlock()
					require.Zero(t, count)
					return
				}
				step := waitWebLoginStep(t, owner, pending.AttemptToken, "Work")
				require.Contains(t, step.Message, test.origin+"/login/#start/")
				svc.web.oidcMutex.Lock()
				count := len(svc.web.oidcTickets)
				svc.web.oidcMutex.Unlock()
				require.Equal(t, 1, count)
				require.Zero(t, provider.logins.Load())
				require.Equal(t, http.StatusAccepted, answerWebStep(owner, pending.AttemptToken, "Work", step, "").Code)
				link := strings.TrimPrefix(step.Message, "Open the following URL in your browser to login: ")
				browser := openOidcBrowser(t, owner, provider, link)
				require.Equal(t, http.StatusOK, oidcCallbackRequest(owner, browser.callback, browser.cookie).Code)
				token := webTestToken(t, finishWebAttempt(t, owner, pending.AttemptToken, "Work"))
				granted, err := svc.web.lookup(webScope{Origin: test.origin, Slug: "Work"}, token, false)
				require.NoError(t, err)
				require.Equal(t, user, granted.user)
				require.Equal(t, int32(1), provider.logins.Load())
			})
		}
	}
}

func containsOidcLoginOption(t *testing.T, body []byte) bool {
	t.Helper()
	var description struct {
		LoginOptions []struct {
			Method string `json:"method"`
		} `json:"loginOptions"`
	}
	require.NoError(t, json.Unmarshal(body, &description))
	for _, option := range description.LoginOptions {
		if option.Method == "oidc" {
			return true
		}
	}
	return false
}
