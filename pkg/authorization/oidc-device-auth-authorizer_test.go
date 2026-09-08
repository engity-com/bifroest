package authorization

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
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

func TestOidcClientSecretPostIsNotRedirectedAcrossOrigins(t *testing.T) {
	destinationCalled := make(chan struct{}, 1)
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationCalled <- struct{}{}
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	ctx, err := withSameOriginRedirects(context.Background(), source.URL)
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		username, password, basic := req.BasicAuth()
		actual <- credentials{username, password, basic}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	ctx, err := withBasicClientAuthentication(context.Background(), server.URL, clientId, clientSecret)
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
