package authorization

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestOidcClientAuthStyle(t *testing.T) {
	tests := []struct {
		name      string
		supported []string
		want      oauth2.AuthStyle
		wantError bool
	}{
		{name: "OIDC default", want: oauth2.AuthStyleInHeader},
		{name: "basic", supported: []string{"client_secret_basic"}, want: oauth2.AuthStyleInHeader},
		{name: "basic preferred", supported: []string{"client_secret_post", "client_secret_basic"}, want: oauth2.AuthStyleInHeader},
		{name: "post", supported: []string{"client_secret_post"}, want: oauth2.AuthStyleInParams},
		{name: "unsupported", supported: []string{"none"}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := oidcClientAuthStyle(test.supported)
			if test.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, actual)
		})
	}
}

func TestSameOriginNormalizesHostAndDefaultPort(t *testing.T) {
	tests := []struct {
		name     string
		left     string
		right    string
		expected bool
	}{
		{name: "identical", left: "https://idp.example/token", right: "https://idp.example/next", expected: true},
		{name: "host case and explicit default port", left: "https://idp.example/token", right: "https://IDP.EXAMPLE:443/next", expected: true},
		{name: "numeric port with leading zero", left: "https://idp.example:0443/token", right: "https://idp.example:443/next", expected: true},
		{name: "different effective port", left: "https://idp.example/token", right: "https://idp.example:8443/next"},
		{name: "different scheme", left: "https://idp.example/token", right: "http://idp.example/next"},
		{name: "different host", left: "https://idp.example/token", right: "https://other.example/next"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			left, err := url.Parse(test.left)
			require.NoError(t, err)
			right, err := url.Parse(test.right)
			require.NoError(t, err)
			require.Equal(t, test.expected, sameOrigin(left, right))
		})
	}
}

func TestRequireOidcHttpsEndpoint(t *testing.T) {
	require.NoError(t, requireOidcHttpsEndpoint("endpoint", "https://idp.example/device"))
	require.NoError(t, requireOidcHttpsEndpoint("endpoint", "HTTPS://idp.example/device"))
	for _, endpoint := range []string{"", "/device", "http://idp.example/device", "https:///device", "://invalid"} {
		t.Run(endpoint, func(t *testing.T) {
			require.Error(t, requireOidcHttpsEndpoint("endpoint", endpoint))
		})
	}
}

func TestNewOidcDeviceAuthRejectsHttpIssuerBeforeDiscovery(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer server.Close()
	conf := &configuration.AuthorizationOidcDeviceAuth{
		Issuer:       template.MustNewUrl(server.URL),
		ClientId:     template.MustNewString("client"),
		ClientSecret: template.MustNewString("secret"),
		Scopes:       template.MustNewStrings("openid"),
	}

	_, err := NewOidcDeviceAuth(context.Background(), "test", conf)
	require.ErrorContains(t, err, "issuer must be an absolute HTTPS URL")
	require.False(t, called)
}

func TestNewOidcDeviceAuthRejectsHttpDeviceEndpoint(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/.well-known/openid-configuration" {
			t.Errorf("request path: got %q, want discovery endpoint", req.URL.Path)
		}
		if err := json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                server.URL,
			"authorization_endpoint":                server.URL + "/authorize",
			"device_authorization_endpoint":         "http://idp.example/device",
			"token_endpoint":                        server.URL + "/token",
			"jwks_uri":                              server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}); err != nil {
			t.Errorf("encode discovery response: %v", err)
		}
	}))
	defer server.Close()
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	conf := &configuration.AuthorizationOidcDeviceAuth{
		Issuer:       template.MustNewUrl(server.URL),
		ClientId:     template.MustNewString("client"),
		ClientSecret: template.MustNewString("secret"),
		Scopes:       template.MustNewStrings("openid"),
	}

	_, err := NewOidcDeviceAuth(ctx, "test", conf)
	require.ErrorContains(t, err, "device authorization endpoint must be an absolute HTTPS URL")
}

func TestOidcClientSecretPostIsNotRedirectedAcrossOrigins(t *testing.T) {
	destinationCalled := make(chan struct{}, 1)
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationCalled <- struct{}{}
	}))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, source.Client())
	ctx, err := withSameOriginRedirects(ctx, source.URL)
	require.NoError(t, err)
	client := ctx.Value(oauth2.HTTPClient).(*http.Client)
	response, err := client.Post(source.URL, "application/x-www-form-urlencoded", strings.NewReader("client_secret=must-not-leak"))
	require.NoError(t, err)
	require.Equal(t, http.StatusTemporaryRedirect, response.StatusCode)
	require.NoError(t, response.Body.Close())
	select {
	case <-destinationCalled:
		t.Fatal("client secret request was redirected to another origin")
	default:
	}
}

func TestOidcBasicClientAuthenticationEscapesCredentials(t *testing.T) {
	const (
		clientId     = "client:id with space"
		clientSecret = "secret:% value"
	)
	type credentials struct {
		username string
		password string
		basic    bool
	}
	actual := make(chan credentials, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		username, password, basic := req.BasicAuth()
		actual <- credentials{username, password, basic}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	ctx, err := withBasicClientAuthentication(ctx, server.URL, clientId, clientSecret)
	require.NoError(t, err)
	client := ctx.Value(oauth2.HTTPClient).(*http.Client)
	response, err := client.Get(server.URL)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	got := <-actual
	require.True(t, got.basic)
	require.Equal(t, url.QueryEscape(clientId), got.username)
	require.Equal(t, url.QueryEscape(clientSecret), got.password)
}

func TestOidcBasicClientAuthenticationRejectsHttpEndpoint(t *testing.T) {
	_, err := withBasicClientAuthentication(context.Background(), "http://idp.example/device", "client", "secret")
	require.ErrorContains(t, err, "must be an absolute HTTPS URL")
}
