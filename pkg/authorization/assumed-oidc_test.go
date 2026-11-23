package authorization

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	coidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

const assumedIDClaims = `{"iss":"https://issuer.example","sub":"subject","aud":"client","exp":1893456000,"iat":1577836800,"nonce":"nonce","at_hash":"hash","count":1,"list":[1,"two"],"empty":{},"null":null,"subject":"shadow"}`
const assumedUserClaims = `{"sub":"subject","profile":"profile","email":"info@example.org","email_verified":true,"emailVerified":"shadow","count":1,"list":[1,"two"],"empty":{},"null":null}`

func assumedOidcJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	return raw
}
func assumedOidcFixture(t *testing.T, code bool) (*configuration.Flow, AssumedOidcFacts) {
	t.Helper()
	conf := new(configuration.AuthorizationOidcDeviceAuth)
	require.NoError(t, conf.SetDefaults())
	conf.Issuer = template.MustNewUrl("https://issuer.example")
	conf.ClientId = template.MustNewString("client")
	conf.RetrieveIdToken, conf.RetrieveUserInfo = true, true
	flow := &configuration.Flow{Name: "work", Authorization: configuration.Authorization{V: conf}}
	if code {
		flow.Authorization.V = &configuration.AuthorizationOidcAuthorizationCode{AuthorizationOidcDeviceAuth: *conf}
	}
	facts := AssumedOidcFacts{Issuer: "https://issuer.example", Subject: "subject",
		Token:    assumedOidcJSON(t, assumedOidcToken{AccessToken: "access", TokenType: "Bearer", RefreshToken: "refresh", Expiry: "2030-01-01T00:00:00Z", Extra: json.RawMessage(`{"count":1,"accessToken":"shadow","empty":{},"list":[1,"two"],"null":null}`)}),
		IDToken:  assumedOidcJSON(t, assumedOidcIDToken{Issuer: "https://issuer.example", Subject: "subject", Audience: []string{"client"}, Expiry: "2030-01-01T00:00:00Z", IssuedAt: "2020-01-01T00:00:00Z", Nonce: "nonce", AccessTokenHash: "hash", Claims: json.RawMessage(assumedIDClaims)}),
		UserInfo: assumedOidcJSON(t, assumedOidcUserInfo{Subject: "subject", Profile: "profile", Email: "info@example.org", EmailVerified: true, Claims: json.RawMessage(assumedUserClaims)}),
	}
	return flow, facts
}

func TestAssumedOidcBindsBothGrantsWithoutBeingAProductionAuthorization(t *testing.T) {
	for _, code := range []bool{false, true} {
		t.Run(fmt.Sprintf("code=%t", code), func(t *testing.T) {
			flow, facts := assumedOidcFixture(t, code)
			bound, err := BindAssumedOidcAuthentication(flow, facts, noopContext{})
			require.NoError(t, err)
			require.Equal(t, flow.Name, bound.Flow())
			identity, err := bound.Authentication()
			require.NoError(t, err)
			require.Equal(t, oidcIdentity(facts.Issuer, facts.Subject), identity)
			_, production := any(bound).(Authorization)
			require.False(t, production, "a fixture binder must not be a usable login result")
			_, factory := any(bound).(DiscoveryAuthorizer)
			require.False(t, factory)
			for _, field := range []string{"session", "remote", "isAuthorized", "envVars", "FindSession", "Dispose"} {
				_, _, err := bound.GetField(field)
				require.ErrorIs(t, err, ErrAssumedOidcFieldUnavailable)
			}
			for i := range facts.IDToken {
				facts.IDToken[i] = ' '
			}
			value, _, err := bound.auth.idToken.GetField("count")
			require.NoError(t, err)
			require.Equal(t, float64(1), value, "the binder must own decoded facts")
		})
	}
	var nilBound *AssumedOidcAuthentication
	require.Empty(t, nilBound.Flow())
	_, err := nilBound.Authentication()
	require.ErrorIs(t, err, ErrInvalidOidcAuthenticationAssumption)
	_, _, err = nilBound.GetField("idToken")
	require.ErrorIs(t, err, ErrInvalidOidcAuthenticationAssumption)
}

func TestAssumedOidcNativeIDTokenAndOAuthGetterParity(t *testing.T) {
	flow, facts := assumedOidcFixture(t, false)
	bound, err := BindAssumedOidcAuthentication(flow, facts, noopContext{})
	require.NoError(t, err)
	encode := base64.RawURLEncoding.EncodeToString
	jwt := encode([]byte(`{"alg":"RS256"}`)) + "." + encode([]byte(assumedIDClaims)) + "." + encode([]byte("test-signature"))
	// Use the real library's decoding with an explicit test-only key set. This is
	// a type/field differential, not a cryptographic verification test.
	verifier := coidc.NewVerifier(facts.Issuer, oidcRestoreTestKeySet{payload: []byte(assumedIDClaims)}, &coidc.Config{ClientID: "client", Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }})
	verified, err := verifier.Verify(t.Context(), jwt)
	require.NoError(t, err)
	native := &OidcIdToken{IDToken: verified}
	for _, field := range []string{"issuer", "audience", "subject", "expiry", "issuedAt", "nonce", "accessTokenHash", "iss", "sub", "aud", "exp", "iat", "count", "list", "empty", "null", "missing"} {
		t.Run(field, func(t *testing.T) {
			expected, present, err := native.GetField(field)
			require.NoError(t, err)
			actual, known, err := bound.auth.idToken.GetField(field)
			require.NoError(t, err)
			require.Equal(t, present, known)
			require.IsType(t, expected, actual)
			if nativeTime, ok := expected.(time.Time); ok {
				// coidc's numeric dates attach time.Local. The fixture explicitly
				// models UTC instead of observing the host's timezone. Compare the
				// instant and native type, and verify the declared zone separately.
				modeledTime := actual.(time.Time)
				require.True(t, nativeTime.Equal(modeledTime))
				require.Same(t, time.UTC, modeledTime.Location())
			} else {
				require.Equal(t, expected, actual)
			}
		})
	}
	var record assumedOidcToken
	require.NoError(t, json.Unmarshal(facts.Token, &record))
	var extra map[string]any
	require.NoError(t, json.Unmarshal(record.Extra, &extra))
	expiry, err := time.Parse(time.RFC3339, record.Expiry)
	require.NoError(t, err)
	nativeToken := OidcToken{Token: (&oauth2.Token{AccessToken: record.AccessToken, TokenType: record.TokenType, RefreshToken: record.RefreshToken, Expiry: expiry}).WithExtra(extra)}
	for _, field := range []string{"accessToken", "access_token", "tokenType", "token_type", "refreshToken", "refresh_token", "expiry", "count", "list", "empty", "null", "missing"} {
		expected, present := nativeToken.GetField(field)
		actual, known := bound.auth.token.GetField(field)
		require.Equal(t, present, known)
		require.Equal(t, expected, actual)
		require.IsType(t, expected, actual)
	}
}

func TestAssumedOidcNativeUserInfoGetterParity(t *testing.T) {
	// A loopback provider is used ONLY by this production-library differential.
	// The offline binder and policy runner never construct it or perform this I/O.
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/userinfo" {
			_, _ = fmt.Fprint(w, assumedUserClaims)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": server.URL, "userinfo_endpoint": server.URL + "/userinfo"})
	}))
	defer server.Close()
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, server.Client())
	provider, err := coidc.NewProvider(ctx, server.URL)
	require.NoError(t, err)
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-only"}))
	require.NoError(t, err)
	native := &OidcUserInfo{UserInfo: info}
	flow, facts := assumedOidcFixture(t, false)
	bound, err := BindAssumedOidcAuthentication(flow, facts, noopContext{})
	require.NoError(t, err)
	for _, field := range []string{"subject", "profile", "email", "emailVerified", "sub", "email_verified", "count", "list", "empty", "null", "missing"} {
		expected, present, err := native.GetField(field)
		require.NoError(t, err)
		actual, known, err := bound.auth.userInfo.GetField(field)
		require.NoError(t, err)
		require.Equal(t, present, known)
		require.Equal(t, expected, actual)
		require.IsType(t, expected, actual)
	}
}

func TestAssumedOidcUnknownAndAbsentArtifactsFollowProductionVisibility(t *testing.T) {
	for _, id := range []bool{false, true} {
		for _, info := range []bool{false, true} {
			flow, facts := assumedOidcFixture(t, false)
			conf := configuration.OidcSettings(flow.Authorization.V)
			conf.RetrieveIdToken, conf.RetrieveUserInfo = id, info
			bound, err := BindAssumedOidcAuthentication(flow, facts, noopContext{})
			require.NoError(t, err)
			require.Equal(t, id, bound.auth.idToken.IDToken != nil)
			require.Equal(t, info, bound.auth.userInfo.UserInfo != nil)
			identity, err := bound.Authentication()
			require.NoError(t, err)
			require.Equal(t, "subject", identity.Subject)
			facts.Token = nil
			facts.IDToken = nil
			facts.UserInfo = nil
			bound, err = BindAssumedOidcAuthentication(flow, facts, noopContext{})
			if id || info {
				require.ErrorIs(t, err, ErrAssumedOidcFieldUnavailable)
				continue
			}
			require.NoError(t, err)
			_, _, err = bound.GetField("token")
			require.ErrorIs(t, err, ErrAssumedOidcFieldUnavailable)
			value, _, err := bound.auth.idToken.GetField("subject")
			require.NoError(t, err)
			require.Nil(t, value)
			facts.Token = json.RawMessage("null")
			bound, err = BindAssumedOidcAuthentication(flow, facts, noopContext{})
			require.NoError(t, err)
			value, present, err := bound.GetField("token")
			require.NoError(t, err)
			require.True(t, present)
			access, known := value.(*OidcToken).GetField("accessToken")
			require.True(t, known)
			require.Nil(t, access)
		}
	}
	flow, facts := assumedOidcFixture(t, false)
	facts.IDToken = json.RawMessage("null")
	_, err := BindAssumedOidcAuthentication(flow, facts, noopContext{})
	require.NoError(t, err, "refresh-enabled production policy permits an absent visible ID token")
	conf := configuration.OidcSettings(flow.Authorization.V)
	conf.ForceDisposeSessionOn = "never"
	conf.RefreshToken.Mode = "never"
	_, err = BindAssumedOidcAuthentication(flow, facts, noopContext{})
	require.ErrorContains(t, err, "token does not contain id_token")
	conf.RetrieveIdToken = false
	facts.UserInfo = json.RawMessage("null")
	_, err = BindAssumedOidcAuthentication(flow, facts, noopContext{})
	require.ErrorIs(t, err, ErrAssumedOidcFieldUnavailable)
}

func TestAssumedOidcRejectsContradictoryIncompleteAndForeignFacts(t *testing.T) {
	for _, mutate := range []func(*configuration.Flow, *AssumedOidcFacts){
		func(_ *configuration.Flow, f *AssumedOidcFacts) { f.Issuer = "https://other.example" },
		func(_ *configuration.Flow, f *AssumedOidcFacts) { f.Subject = "other" },
		func(_ *configuration.Flow, f *AssumedOidcFacts) { f.Subject = "bad\nsubject" },
		func(flow *configuration.Flow, _ *AssumedOidcFacts) {
			flow.Authorization.V = &configuration.AuthorizationLocal{}
		},
		func(flow *configuration.Flow, _ *AssumedOidcFacts) {
			flow.Authorization.V = (*configuration.AuthorizationOidcAuthorizationCode)(nil)
		},
		func(_ *configuration.Flow, f *AssumedOidcFacts) { f.Token = json.RawMessage(`{}`) },
		func(_ *configuration.Flow, f *AssumedOidcFacts) { f.Token = json.RawMessage(`[]`) },
		func(_ *configuration.Flow, f *AssumedOidcFacts) {
			f.IDToken = json.RawMessage(strings.Replace(string(f.IDToken), `"audience":["client"]`, `"audience":[1]`, 1))
		},
		func(_ *configuration.Flow, f *AssumedOidcFacts) {
			f.IDToken = json.RawMessage(strings.Replace(string(f.IDToken), `"audience":["client"]`, `"audience":[null]`, 1))
		},
		func(_ *configuration.Flow, f *AssumedOidcFacts) {
			f.IDToken = json.RawMessage(strings.Replace(string(f.IDToken), `"nonce":"nonce"`, `"nonce":null`, 1))
		},
		func(_ *configuration.Flow, f *AssumedOidcFacts) {
			f.UserInfo = json.RawMessage(strings.Replace(string(f.UserInfo), `"email_verified":true`, `"email_verified":false`, 1))
		},
		func(_ *configuration.Flow, f *AssumedOidcFacts) {
			f.IDToken = json.RawMessage(strings.Replace(string(f.IDToken), `"expiry":"2030-01-01T00:00:00Z"`, `"expiry":"2030-01-01T00:00:00.5Z"`, 1))
		},
		func(_ *configuration.Flow, f *AssumedOidcFacts) {
			f.IDToken = json.RawMessage(strings.Replace(string(f.IDToken), `"issuedAt":"2020-01-01T00:00:00Z"`, `"issuedAt":"2020-01-01T00:00:00.5Z"`, 1))
		},
		func(_ *configuration.Flow, f *AssumedOidcFacts) {
			f.IDToken = json.RawMessage(strings.Repeat(" ", 65537))
		},
	} {
		flow, facts := assumedOidcFixture(t, false)
		mutate(flow, &facts)
		_, err := BindAssumedOidcAuthentication(flow, facts, noopContext{})
		require.Error(t, err)
	}
	_, err := BindAssumedOidcAuthentication(nil, AssumedOidcFacts{}, noopContext{})
	require.ErrorIs(t, err, ErrInvalidOidcAuthenticationAssumption)
	// coidc converts JSON numeric dates to whole seconds. Preserve its conversion
	// (including float64 rounding), rather than demanding integer JSON claims.
	for _, value := range []string{"1893456000.5", "1893456000.999999999"} {
		flow, facts := assumedOidcFixture(t, false)
		facts.IDToken = json.RawMessage(strings.Replace(string(facts.IDToken), `"exp":1893456000`, `"exp":`+value, 1))
		if strings.HasSuffix(value, "999999999") {
			facts.IDToken = json.RawMessage(strings.Replace(string(facts.IDToken), `"expiry":"2030-01-01T00:00:00Z"`, `"expiry":"2030-01-01T00:00:01Z"`, 1))
		}
		_, err := BindAssumedOidcAuthentication(flow, facts, noopContext{})
		require.NoError(t, err)
	}
}
