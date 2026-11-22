package test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const oidcFactsSource = `issuer="https://issuer.example",subject="subject",
token=object{accessToken="access",tokenType="Bearer",refreshToken="refresh",expiry="2030-01-01T00:00:00Z",extra=object{count=1,accessToken="shadow",oauthOnly="oauth"}},
idToken=object{issuer="https://issuer.example",subject="subject",audience=list{"client"},expiry="2030-01-01T00:00:00Z",issuedAt="2020-01-01T00:00:00Z",nonce="nonce",accessTokenHash="hash",claims=object{preferred_username="alice",count=1,empty=object{},array=list{"a","b"},nullValue=null,subject="shadow",idOnly="id",iss="https://issuer.example",sub="subject",aud="client",exp=1893456000,iat=1577836800}},
userInfo=object{subject="subject",profile="profile",email="info@example.org",emailVerified=true,claims=object{preferred_username="user-info",count=1,userOnly="user",emailVerified="shadow",sub="subject",email="info@example.org",email_verified=true}}`

func oidcConfiguration(kind, mapping, flags string) string {
	conf := strings.Replace(testConfiguration, "type: local", "type: "+kind+"\n      issuer: https://issuer.example\n      clientId: client\n      clientSecret: example-only\n      retrieveIdToken: true\n      retrieveUserInfo: true"+flags, 1)
	conf = strings.Replace(conf, "mapped-{{ .authentication.principal }}", mapping, 1)
	if kind == "oidcAuthorizationCode" {
		conf = "http:\n  enabled: true\n  addresses: [':8443']\n  domains: [app.example.org]\n  tls: {dummy: true}\n" + conf
	}
	return conf
}
func oidcSource(verify string) string {
	return `suite{name="oidc",environment=object{accounts=list{}},tests={{name="example",input=object{request=object{requestingName="ops",method="keyboard-interactive"},authentication=object{primary=object{outcome="allow",mode="verified-oidc",oidc=object{` + oidcFactsSource + `}}}},verify=function(t,actual) ` + verify + ` end}}}`
}
func runOidc(t *testing.T, kind, mapping, source string) Report {
	t.Helper()
	return RunSources(t.Context(), []byte(source), []byte(oidcConfiguration(kind, mapping, "")))
}

func TestOidcBothGrantsUseProductionPrincipalMapping(t *testing.T) {
	for _, kind := range []string{"oidcDeviceAuth", "oidcAuthorizationCode"} {
		t.Run(kind, func(t *testing.T) {
			source := oidcSource(`
 t:IsEqual("selected",actual.decision)
 t:IsEqual("verified-oidc",actual.authentication.mode)
 t:IsEqual(true,actual.authenticationAssumed)
 t:IsEqual("ops",t.input.request.requestingName)
 t:IsEqual("subject",actual.authentication.subject)
 t:IsEqual("https://issuer.example",actual.identity.issuer)
 t:IsEqual("subject",actual.identity.subject)
 t:IsEqual("mapped-alice",actual.identity.principal)
 t:IsEqual("mapped-alice",actual.environment.user)
 t:IsEqual(false,actual.environment.portForwardingAllowed)
 t:IsEqual("work.example.:22",actual.environment.address)
 `)
			report := runOidc(t, kind, `mapped-{{ .authorization.idToken.preferred_username }}`, source)
			require.Zero(t, report.ExitCode(), "%+v", report)
			require.Equal(t, 11, report.Results[0].Assertions)
			for _, mapping := range []string{"", "{{ .authentication.principal }}", "{{ .authentication.subject }}"} {
				report := runOidc(t, kind, mapping, oidcSource(`t:IsEqual("subject",actual.identity.principal)`))
				require.Zero(t, report.ExitCode(), "%+v", report)
			}
		})
	}
}

func TestOidcVisibilityDoesNotEraseVerifiedIdentity(t *testing.T) {
	for _, kind := range []string{"oidcDeviceAuth", "oidcAuthorizationCode"} {
		for _, id := range []bool{false, true} {
			for _, info := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/id=%t/info=%t", kind, id, info), func(t *testing.T) {
					mapping := fmt.Sprintf(`{{ if and (eq (not .authorization.idToken.subject) %t) (eq (not .authorization.userInfo.subject) %t) }}mapped-{{ .authentication.subject }}{{ else }}wrong{{ end }}`, !id, !info)
					conf := strings.Replace(oidcConfiguration(kind, mapping, ""), "retrieveIdToken: true", fmt.Sprintf("retrieveIdToken: %t", id), 1)
					conf = strings.Replace(conf, "retrieveUserInfo: true", fmt.Sprintf("retrieveUserInfo: %t", info), 1)
					report := RunSources(t.Context(), []byte(oidcSource(`t:IsEqual("mapped-subject",actual.identity.principal);t:IsEqual("subject",actual.identity.subject)`)), []byte(conf))
					require.Zero(t, report.ExitCode(), "%+v", report)
				})
			}
		}
	}
}

func TestOidcNativeGetterTypesAliasesAndArtifactSeparation(t *testing.T) {
	for _, test := range []struct{ expression, expected string }{
		{`.authorization.token.accessToken`, "access"}, {`.authorization.token.access_token`, "access"},
		{`.authorization.token.tokenType`, "Bearer"}, {`.authorization.token.token_type`, "Bearer"},
		{`.authorization.token.refresh_token`, "refresh"},
		{`.authorization.idToken.subject`, "subject"}, {`.authorization.idToken.sub`, "subject"},
		{`.authorization.userInfo.emailVerified`, "true"},
		{`len .authorization.idToken.audience`, "1"}, {`len .authorization.idToken.array`, "2"},
		{`len .authorization.idToken.empty`, "0"},
		{`eq .authorization.idToken.count 1.0`, "true"},
		{`eq .authorization.token.count .authorization.userInfo.count`, "true"},
		{`eq .authorization.idToken.missing nil`, "true"}, {`eq .authorization.idToken.nullValue nil`, "true"},
		{`eq .authorization.token.idOnly nil`, "true"}, {`eq .authorization.idToken.userOnly nil`, "true"},
		{`eq .authorization.userInfo.oauthOnly nil`, "true"},
		{`.authorization.token.expiry`, "2030-01-01 00:00:00 +0000 UTC"},
		{`.authorization.idToken.issuedAt`, "2020-01-01 00:00:00 +0000 UTC"},
	} {
		t.Run(test.expression, func(t *testing.T) {
			report := runOidc(t, "oidcDeviceAuth", "{{ "+test.expression+" }}", oidcSource(`t:IsEqual("`+test.expected+`",actual.identity.principal)`))
			require.Zero(t, report.ExitCode(), "%+v", report)
		})
	}
	// A generic fixture map would retain Lua integers. Native JSON claims are
	// float64: the production template must reject an integer comparison.
	report := runOidc(t, "oidcDeviceAuth", `{{ eq .authorization.idToken.count 1 }}`, oidcSource(`t:IsEqual(true,true)`))
	require.Equal(t, 2, report.ExitCode(), "%+v", report)
}

func TestOidcUnknownAbsentAndMalformedFactsCannotLookSuccessful(t *testing.T) {
	for _, replacement := range []struct{ old, new string }{
		{`mode="verified-oidc"`, `mode="post-authentication"`}, {`mode="verified-oidc"`, `mode="verified-oidc",account="alice"`},
		{`subject="subject",` + "\n" + `token=`, `subject="other",` + "\n" + `token=`},
		{`issuer="https://issuer.example",subject="subject",` + "\n" + `token=`, `issuer="https://other.example",subject="subject",` + "\n" + `token=`},
		{`idToken=object{`, `unknownIdToken=object{`},
		{`nonce="nonce"`, `nonce=null`}, // Canonical metadata cannot be null.
		{`audience=list{"client"}`, `audience=list{1}`},
		{`claims=object{`, `claims=list{`},
		{`expiry="2030-01-01T00:00:00Z"`, `expiry="2030-01-01T00:00:00+00:00"`},
		{`email_verified=true`, `email_verified=false`},
		{`sub="subject"`, `sub="different"`},
		{`exp=1893456000`, `exp=1`},
		{`method="keyboard-interactive"`, `method="oidc"`},
		{`requestingName="ops"`, `requestingName="ops",transport="http"`},
	} {
		t.Run(replacement.new, func(t *testing.T) {
			source := strings.Replace(oidcSource(`t:IsEqual("deny",actual.decision)`), replacement.old, replacement.new, 1)
			require.NotEqual(t, oidcSource(`t:IsEqual("deny",actual.decision)`), source, "replacement must affect the fixture")
			report := runOidc(t, "oidcDeviceAuth", "constant", source)
			require.Equal(t, 2, report.ExitCode(), "%+v", report)
			require.Zero(t, report.Results[0].Assertions)
		})
	}
	for _, fragment := range []string{``, `token=null,`, `idToken=null,userInfo=null,`} {
		source := strings.Replace(oidcSource(`t:IsEqual(true,true)`), oidcFactsSource, `issuer="https://issuer.example",subject="subject",`+fragment, 1)
		report := runOidc(t, "oidcDeviceAuth", "constant", source)
		require.Equal(t, 2, report.ExitCode(), "%+v", report)
	}
}

func TestOidcPasswordDenialAndInteractiveLocalFallback(t *testing.T) {
	for _, kind := range []string{"oidcDeviceAuth", "oidcAuthorizationCode"} {
		source := strings.Replace(oidcSource(`t:IsEqual("deny",actual.decision)`), `method="keyboard-interactive"`, `method="password"`, 1)
		require.Zero(t, runOidc(t, kind, "constant", source).ExitCode())
		source = strings.Replace(source, `,method="password"`, "", 1)
		require.Zero(t, runOidc(t, kind, "constant", source).ExitCode(), "the default is still password")
	}
	source := strings.Replace(suiteSource(`t:IsEqual("mapped-alice",actual.identity.principal)`), `requestingName="ops"`, `requestingName="ops",method="keyboard-interactive"`, 1)
	require.Zero(t, RunSources(t.Context(), []byte(source), []byte(testConfiguration)).ExitCode())
}

func TestOidcMixedFlowsKeepProductionOrderFallbackAndErrorAborts(t *testing.T) {
	for _, kind := range []string{"oidcDeviceAuth", "oidcAuthorizationCode"} {
		conf := oidcConfiguration(kind, "{{ .authentication.subject }}", "") + `  - name: secondary
    authorization: {type: local}
    environment:
      type: ssh
      address: fallback.example.org
      user: '{{ .authentication.principal }}'
      acceptAllHostKeys: true
`
		for _, test := range []struct {
			name, assumptions, method, expected string
			code                                int
		}{
			{"denial falls through", `primary=object{outcome="deny"},secondary=object{outcome="allow",account="alice"}`, "keyboard-interactive", "secondary", 0},
			{"first wins", `primary=object{outcome="allow",mode="verified-oidc",oidc=object{` + oidcFactsSource + `}}`, "keyboard-interactive", "primary", 0},
			{"unknown stops", `secondary=object{outcome="allow",account="alice"}`, "keyboard-interactive", "", 2},
			{"foreign identity stops", `primary=object{outcome="allow",mode="verified-oidc",oidc=object{issuer="https://foreign.example",subject="subject"}},secondary=object{outcome="allow",account="alice"}`, "keyboard-interactive", "", 2},
			{"password skips OIDC", `secondary=object{outcome="allow",account="alice"}`, "password", "secondary", 0},
		} {
			t.Run(kind+"/"+test.name, func(t *testing.T) {
				source := oidcSource(`t:IsEqual("` + test.expected + `",actual.flow)`)
				source = strings.Replace(source, `primary=object{outcome="allow",mode="verified-oidc",oidc=object{`+oidcFactsSource+`}}`, test.assumptions, 1)
				source = strings.Replace(source, `method="keyboard-interactive"`, `method="`+test.method+`"`, 1)
				source = strings.Replace(source, `accounts=list{}`, `accounts=list{object{`+accountSource()+`}}`, 1)
				report := RunSources(t.Context(), []byte(source), []byte(conf))
				require.Equal(t, test.code, report.ExitCode(), "%+v", report)
				if test.code == 2 {
					require.Zero(t, report.Results[0].Assertions)
				}
			})
		}
	}
}

type oidcNoNetwork struct{ calls atomic.Int32 }

func (this *oidcNoNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	this.calls.Add(1)
	return nil, fmt.Errorf("unexpected offline OIDC network access")
}

func TestOidcRunnerDoesNotInitializeProvidersOrPerformLogin(t *testing.T) {
	transport := new(oidcNoNetwork)
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: transport})
	for _, kind := range []string{"oidcDeviceAuth", "oidcAuthorizationCode"} {
		source := strings.ReplaceAll(oidcSource(`t:IsEqual("subject",actual.identity.subject)`), "https://issuer.example", "https://127.0.0.1:1")
		conf := strings.ReplaceAll(oidcConfiguration(kind, "{{ .authentication.subject }}", ""), "https://issuer.example", "https://127.0.0.1:1")
		report := RunSources(ctx, []byte(source), []byte(conf))
		require.Zero(t, report.ExitCode(), "%+v", report)
	}
	require.Zero(t, transport.calls.Load())
}

func TestOidcTemplatesCannotInvokeNativeTimeOrHostCapabilities(t *testing.T) {
	for _, expression := range []string{`.authorization`, `.authorization.token`, `.authorization.idToken`, `.authorization.userInfo`, `.authorization.idToken.expiry.Local`, `.authorization.idToken.issuedAt.Location`, `.authorization.token.expiry.UTC`, `(.authorization.token.expiry).Local`, `.authorization.FindSession`, `env "BIFROEST_OIDC_SECRET"`, `.remote.host`} {
		t.Run(expression, func(t *testing.T) {
			report := runOidc(t, "oidcDeviceAuth", "{{ "+expression+" }}", oidcSource(`t:IsEqual(true,true)`))
			require.Equal(t, 2, report.ExitCode(), "%+v", report)
			require.Zero(t, report.Results[0].Assertions)
		})
	}
	badIssuer := strings.Replace(oidcConfiguration("oidcDeviceAuth", "constant", ""), "issuer: https://issuer.example", `issuer: '{{ .Context }}'`, 1)
	require.Equal(t, 2, RunSources(t.Context(), []byte(oidcSource(`t:IsEqual(true,true)`)), []byte(badIssuer)).ExitCode())
}

func TestOidcFailuresDoNotEchoTokensOrClaims(t *testing.T) {
	source := strings.Replace(oidcSource(`t:IsEqual(true,true)`), `accessToken="access"`, `accessToken="PRIVATE-ACCESS-TOKEN"`, 1)
	report := runOidc(t, "oidcDeviceAuth", `{{ .authorization.idToken.count.Local }}`, source)
	require.Equal(t, 2, report.ExitCode())
	var raw bytes.Buffer
	require.NoError(t, report.WriteJSON(&raw))
	require.NotContains(t, raw.String(), "PRIVATE-ACCESS-TOKEN")
}
