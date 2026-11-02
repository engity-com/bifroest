package service

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
)

func webTestLoginOptions(t *testing.T, handler http.Handler, slug string) []authorization.LoginOption {
	t.Helper()
	response := webTestRequest(handler, http.MethodGet, "app.example.org", "/"+slug, "", "")
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var body struct {
		Options []authorization.LoginOption `json:"loginOptions"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	require.NotNil(t, body.Options, "the method list is always an explicit array")
	require.NotContains(t, response.Body.String(), "passwordLogin", "unconditional endpoint hints have been replaced")
	return body.Options
}

func TestWebRootPublishedDirectoryDoesNotEnableRootAuthentication(t *testing.T) {
	svc, handler, recorder := webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].DiscoverAsSlug = "Work"
		conf.Flows[0].Requirement.Http.IncludedSlug = common.MustNewRegexp("^Work$")
	})
	require.Empty(t, webTestLoginOptions(t, handler, ""))
	response := webTestRequest(handler, http.MethodGet, "app.example.org", "/", "", "")
	require.Contains(t, response.Body.String(), `"publishedSlugs":["Work"]`)
	require.Empty(t, svc.web.access)
	require.Empty(t, recorder.eventsSnapshot(), "discovery must not authenticate or audit a task")
	require.Equal(t, http.StatusUnauthorized, webTestPassword(handler, "alice", "correct", "").Code)
	require.Empty(t, svc.web.access)
	require.Equal(t, http.StatusOK, webTestPassword(handler, "alice", "correct", "Work").Code)
}

func TestWebLoginOptionsReflectConfiguredPrimaryMethodsOnly(t *testing.T) {
	key := ssh.MarshalAuthorizedKey(webLoginTestSigner(t).PublicKey())
	for _, test := range []struct {
		name      string
		configure func(*configuration.Flow)
		options   []authorization.LoginOption
	}{
		{name: "password without primary keys", options: []authorization.LoginOption{
			{Method: authorization.LoginMethodPassword, RequestUser: true},
			{Method: authorization.LoginMethodKeyboardInteractive, RequestUser: true},
		}},
		{name: "keys only", configure: func(flow *configuration.Flow) {
			entry := &flow.Authorization.V.(*configuration.AuthorizationSimple).Entries[0]
			entry.Password = nil
			entry.AuthorizedKeys = crypto.AuthorizedKeys(key)
		}, options: []authorization.LoginOption{{Method: authorization.LoginMethodPublicKey, RequestUser: true}}},
		{name: "CA only requires a certificate", configure: func(flow *configuration.Flow) {
			settings := flow.Authorization.V.(*configuration.AuthorizationSimple)
			settings.Entries[0].Password = nil
			settings.TrustedUserCAs = crypto.PublicKeys(key)
		}, options: []authorization.LoginOption{{Method: authorization.LoginMethodPublicKey, RequestUser: true, CertificateRequired: true}}},
		{name: "no primary methods", configure: func(flow *configuration.Flow) {
			flow.Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = nil
		}, options: []authorization.LoginOption{}},
		{name: "nameless anonymous entry", configure: func(flow *configuration.Flow) {
			flow.Http.RequestUser = commonBool(false)
			flow.Authorization.V = &configuration.AuthorizationNone{}
		}, options: []authorization.LoginOption{{Method: authorization.LoginMethodNone}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc, handler, recorder := webTestFixture(t, func(conf *configuration.Configuration) {
				if test.configure != nil {
					test.configure(&conf.Flows[0])
				}
			})
			require.Equal(t, test.options, webTestLoginOptions(t, handler, "Work"))
			require.Empty(t, svc.web.access)
			require.Empty(t, recorder.eventsSnapshot())
			response := webTestRequest(handler, http.MethodGet, "app.example.org", "/Work", "", "")
			require.NotContains(t, response.Body.String(), "plain:correct")
			require.NotContains(t, response.Body.String(), string(key))
		})
	}
}

func TestWebLoginOptionsUsePublishedSelectionAndKeepNameModesSeparate(t *testing.T) {
	key := ssh.MarshalAuthorizedKey(webLoginTestSigner(t).PublicKey())
	svc, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		named := conf.Flows[0]
		named.DiscoverAsSlug = ""
		nameless := named
		nameless.Name = "nameless"
		nameless.Http.RequestUser = commonBool(false)
		nameless.Authorization.V = &configuration.AuthorizationNone{}
		fixed := named
		fixed.Name, fixed.DiscoverAsSlug = "fixed", "Private"
		fixed.Authorization.V = &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{Name: "alice", AuthorizedKeys: crypto.AuthorizedKeys(key)}}}
		conf.Flows = configuration.Flows{named, nameless, fixed}
	})
	require.Equal(t, []authorization.LoginOption{{Method: authorization.LoginMethodPublicKey, RequestUser: true}}, webTestLoginOptions(t, handler, "Private"))
	require.Equal(t, []authorization.LoginOption{
		{Method: authorization.LoginMethodPassword, RequestUser: true},
		{Method: authorization.LoginMethodKeyboardInteractive, RequestUser: true},
		{Method: authorization.LoginMethodPublicKey, RequestUser: true},
		{Method: authorization.LoginMethodNone},
	}, webTestLoginOptions(t, handler, "Unpublished"))
	require.Equal(t, http.StatusUnauthorized, webTestPassword(handler, "alice", "correct", "Private").Code, "hidden options do not replace authoritative authentication")
	require.Empty(t, svc.web.access)
}

func TestWebOidcDiscoveryDoesNotProbeRememberedSshKeysOrStartDeviceLogin(t *testing.T) {
	svc, handler, provider, recorder := webOidcLoginFixture(t)
	require.Equal(t, []authorization.LoginOption{{Method: authorization.LoginMethodKeyboardInteractive}}, webTestLoginOptions(t, handler, "Work"))
	require.Zero(t, provider.logins.Load())
	require.Empty(t, svc.web.attempts)
	require.Empty(t, svc.web.access)
	require.Empty(t, recorder.eventsSnapshot())
}
