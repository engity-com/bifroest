package test

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const httpConfigurationPrefix = `http:
  enabled: true
  addresses: [':8443']
  domains: [app.example.org, second.example.org]
  tls: {dummy: true}
authorizations:
  local:
    type: local
    principal: 'mapped-{{ .authentication.principal }}'
  device:
    type: oidcDeviceAuth
    issuer: https://issuer.example
    clientId: client
    clientSecret: example-only
    retrieveIdToken: true
    retrieveUserInfo: true
    principal: 'mapped-{{ .authorization.idToken.preferred_username }}'
  code:
    type: oidcAuthorizationCode
    issuer: https://issuer.example
    clientId: client
    clientSecret: example-only
    domain: app.example.org
    retrieveIdToken: true
    retrieveUserInfo: true
    principal: 'mapped-{{ .authorization.idToken.preferred_username }}'
environments:
  target:
    type: ssh
    address: work.example.org
    user: '{{ .authentication.principal }}'
    acceptAllHostKeys: true
flows:
`

func httpFlow(name, auth string) string {
	return "  - name: " + name + "\n    authorization: " + auth + "\n    environment: target\n    requirement:\n      http: {includedSlug: '.*'}\n"
}
func httpAssumption(name string) string {
	return name + `=object{outcome="allow",mode="verified-oidc",oidc=object{` + oidcFactsSource + `}}`
}
func httpSource(request, outcomes, verify string) string {
	return `suite{name="http",environment=object{accounts=list{object{` + accountSource() + `}}},tests={{name="example",input=object{request=object{` + request + `},authentication=object{` + outcomes + `}},verify=function(t,actual) ` + verify + ` end}}}`
}
func runHttp(t *testing.T, config, request, outcomes, verify string) Report {
	t.Helper()
	return RunSources(t.Context(), []byte(httpSource(request, outcomes, verify)), []byte(config))
}

const httpRequest = `transport="http",host="APP.Example.Org.:08443",slug="Work",requestingName="ops"`

func TestHttpRequestUsesCanonicalServerScopeAndRetainsRawInput(t *testing.T) {
	conf := httpConfigurationPrefix + httpFlow("primary", "local")
	report := runHttp(t, conf, httpRequest, `primary=object{outcome="allow",account="alice"}`, `
 t:IsEqual("selected",actual.decision)
 t:IsEqual("primary",actual.flow)
 t:IsEqual("mapped-alice",actual.identity.principal)
 t:IsEqual("mapped-alice",actual.environment.user)
 t:IsEqual("APP.Example.Org.:08443",t.input.request.host)
 t:IsEqual(object{transport="http",method="password",host="app.example.org",origin="https://app.example.org:8443",slug="Work",requestingName="ops"},actual.request)
 local ok=pcall(function() actual.request.host="changed" end)
 t:IsEqual(false,ok)
 t:IsEqual("app.example.org",actual.request.host)
 `)
	require.Zero(t, report.ExitCode(), "%+v", report)
	for _, test := range []struct{ authority, host, origin string }{
		{"BÜCHER.Example.:00443", "xn--bcher-kva.example", "https://xn--bcher-kva.example"},
		{"APP.EXAMPLE.ORG:443", "app.example.org", "https://app.example.org"},
		{"[2001:0db8::1]:08443", "[2001:db8::1]", "https://[2001:db8::1]:8443"},
		{"127.0.0.1:443", "127.0.0.1", "https://127.0.0.1"},
	} {
		req := strings.Replace(httpRequest, "APP.Example.Org.:08443", test.authority, 1)
		report := runHttp(t, conf, req, `primary=object{outcome="allow",account="alice"}`, `t:IsEqual("`+test.host+`",actual.request.host);t:IsEqual("`+test.origin+`",actual.request.origin)`)
		require.Zero(t, report.ExitCode(), "%+v", report)
	}
	ssh := run(t, `t:IsEqual(object{transport="ssh",method="password",requestingName="ops"},actual.request)`)
	require.Zero(t, ssh.ExitCode(), "%+v", ssh)
}

func TestHttpMethodsRespectConfiguredGrantAndOrigin(t *testing.T) {
	for _, test := range []struct{ auth, method, authority, decision string }{
		{"device", "keyboard-interactive", "app.example.org:8443", "selected"},
		{"device", "oidc", "app.example.org:8443", "deny"},
		{"device", "password", "app.example.org:8443", "deny"},
		{"code", "oidc", "app.example.org:8443", "selected"},
		{"code", "keyboard-interactive", "app.example.org:8443", "deny"},
		{"code", "password", "app.example.org:8443", "deny"},
		{"code", "oidc", "app.example.org", "deny"},
		{"code", "oidc", "app.example.org:443", "deny"},
		{"code", "oidc", "app.example.org:8444", "deny"},
		{"code", "oidc", "second.example.org:8443", "deny"},
		{"local", "oidc", "app.example.org:8443", "deny"},
		{"local", "keyboard-interactive", "app.example.org:8443", "selected"},
	} {
		t.Run(test.auth+"/"+test.method+"/"+test.authority, func(t *testing.T) {
			conf := httpConfigurationPrefix + httpFlow("primary", test.auth)
			req := strings.Replace(httpRequest, "APP.Example.Org.:08443", test.authority, 1) + `,method="` + test.method + `"`
			outcomes := ""
			if test.decision == "selected" {
				if test.auth == "local" {
					outcomes = `primary=object{outcome="allow",account="alice"}`
				} else {
					outcomes = httpAssumption("primary")
				}
			}
			report := runHttp(t, conf, req, outcomes, `t:IsEqual("`+test.decision+`",actual.decision);t:IsEqual("`+test.method+`",actual.request.method)`)
			require.Zero(t, report.ExitCode(), "%+v", report)
		})
	}
	// Default HTTPS ports compare canonically, not as textual aliases.
	conf := strings.Replace(httpConfigurationPrefix, ":8443", ":443", 1) + httpFlow("primary", "code")
	report := runHttp(t, conf, strings.Replace(httpRequest, ":08443", ":00443", 1)+`,method="oidc"`, httpAssumption("primary"), `t:IsEqual("selected",actual.decision);t:IsEqual("https://app.example.org",actual.request.origin)`)
	require.Zero(t, report.ExitCode(), "%+v", report)
}

func TestHttpNamedAndNamelessFlowsStaySeparate(t *testing.T) {
	for _, kind := range []string{"device", "code"} {
		method := "keyboard-interactive"
		if kind == "code" {
			method = "oidc"
		}
		conf := httpConfigurationPrefix + httpFlow("named", kind) + httpFlow("nameless", kind) + "    http: {requestUser: false}\n"
		for _, test := range []struct{ name, expected string }{{"ops", "named"}, {"", "nameless"}, {"   ", ""}} {
			t.Run(kind+"/name="+test.name, func(t *testing.T) {
				req := strings.Replace(httpRequest, `requestingName="ops"`, `requestingName="`+test.name+`"`, 1) + `,method="` + method + `"`
				outcome := ""
				verify := `t:IsEqual("deny",actual.decision)`
				if test.expected != "" {
					outcome = httpAssumption(test.expected)
					verify = `t:IsEqual("` + test.expected + `",actual.flow);t:IsEqual("subject",actual.identity.subject);t:IsEqual("` + test.name + `",actual.request.requestingName)`
				}
				report := runHttp(t, conf, req, outcome, verify)
				require.Zero(t, report.ExitCode(), "%+v", report)
			})
		}
	}
	conf := httpConfigurationPrefix + httpFlow("primary", "device") + "    http: {requestUser: false}\n"
	conf = strings.Replace(conf, "http: {includedSlug: '.*'}", "includedRequestingName: '^not-empty$'\n      http: {includedSlug: '.*'}", 1)
	report := runHttp(t, conf, strings.Replace(httpRequest, `requestingName="ops"`, `requestingName=""`, 1)+`,method="keyboard-interactive"`, "", `t:IsEqual("deny",actual.decision)`)
	require.Zero(t, report.ExitCode(), "empty names still pass through real requirements: %+v", report)
	// The native HTTP adapter accepts 256 bytes, independently of the bounded
	// legacy SSH name contract. It neither trims nor authenticates that name.
	for _, name := range []string{strings.Repeat("x", 256), "  ops  ", "älice"} {
		req := strings.Replace(httpRequest, `requestingName="ops"`, `requestingName="`+name+`"`, 1) + `,method="oidc"`
		report := runHttp(t, httpConfigurationPrefix+httpFlow("primary", "code"), req, httpAssumption("primary"), `t:IsEqual("selected",actual.decision);t:IsEqual("`+name+`",actual.request.requestingName)`)
		require.Zero(t, report.ExitCode(), "%+v", report)
	}
}

func TestHttpPublishedFlowBindingNeverLeaksToGenericFallback(t *testing.T) {
	for _, test := range []struct {
		name, auth, settings, request, outcomes, decision string
		code                                              int
	}{
		{"published wins", "code", "", httpRequest + `,method="oidc"`, httpAssumption("fixed"), "selected", 0},
		{"denial stays pinned", "code", "", httpRequest + `,method="oidc"`, `fixed=object{outcome="deny"}`, "deny", 0},
		{"wrong port stays pinned", "code", "", strings.Replace(httpRequest, ":08443", ":443", 1) + `,method="oidc"`, "", "deny", 0},
		{"wrong method stays pinned", "code", "", httpRequest + `,method="keyboard-interactive"`, "", "deny", 0},
		{"named mode stays pinned", "code", "    http: {requestUser: false}\n", httpRequest + `,method="oidc"`, "", "deny", 0},
		{"name mismatch stays pinned", "code", "", strings.Replace(httpRequest, `requestingName="ops"`, `requestingName="bob"`, 1) + `,method="oidc"`, "", "deny", 0},
		{"unknown outcome is error", "code", "", httpRequest + `,method="oidc"`, "", "", 2},
		{"invalid identity is error", "code", "", httpRequest + `,method="oidc"`, `fixed=object{outcome="allow",mode="verified-oidc",oidc=object{issuer="https://foreign.example",subject="other"}}`, "", 2},
		{"local denial stays pinned", "local", "", httpRequest, `fixed=object{outcome="deny"}`, "deny", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixed := httpFlow("fixed", test.auth) + "    discoverAsSlug: Work\n" + test.settings
			fixed = strings.Replace(fixed, "requirement:\n", "requirement:\n      includedRequestingName: '^ops$'\n", 1)
			conf := httpConfigurationPrefix + httpFlow("generic-first", "code") + fixed + httpFlow("generic-last", "local")
			verify := `t:IsEqual("` + test.decision + `",actual.decision)`
			if test.decision == "selected" {
				verify += `;t:IsEqual("fixed",actual.flow)`
			}
			report := runHttp(t, conf, test.request, test.outcomes, verify)
			require.Equal(t, test.code, report.ExitCode(), "%+v", report)
			if test.code == 2 {
				require.Zero(t, report.Results[0].Assertions)
			}
		})
	}
	// A case-distinct slug is not an alias for the published flow. A valid
	// unpublished slug retains native configuration-order matching.
	conf := httpConfigurationPrefix + httpFlow("first", "code") + httpFlow("fixed", "code") + "    discoverAsSlug: Work\n"
	report := runHttp(t, conf, strings.Replace(httpRequest, `slug="Work"`, `slug="work"`, 1)+`,method="oidc"`, httpAssumption("first"), `t:IsEqual("first",actual.flow)`)
	require.Zero(t, report.ExitCode(), "%+v", report)
}

func TestHttpUnpublishedFlowsKeepOrderingDenialFallbackAndErrorAbort(t *testing.T) {
	conf := httpConfigurationPrefix + httpFlow("first", "code") + httpFlow("second", "device")
	for _, test := range []struct {
		name, request, outcomes, flow string
		code                          int
	}{
		{"first success", httpRequest + `,method="oidc"`, httpAssumption("first"), "first", 0},
		{"unknown is not denial", httpRequest + `,method="oidc"`, "", "", 2},
		{"device method skips code", httpRequest + `,method="keyboard-interactive"`, httpAssumption("second"), "second", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := runHttp(t, conf, test.request, test.outcomes, `t:IsEqual("`+test.flow+`",actual.flow)`)
			require.Equal(t, test.code, report.ExitCode(), "%+v", report)
		})
	}
	conf = httpConfigurationPrefix + httpFlow("first", "code") + httpFlow("second", "code")
	report := runHttp(t, conf, httpRequest+`,method="oidc"`, `first=object{outcome="deny"},`+httpAssumption("second"), `t:IsEqual("second",actual.flow)`)
	require.Zero(t, report.ExitCode(), "%+v", report)
	// Wrong-origin code candidates are ineligible before outcomes are consumed.
	conf = strings.Replace(conf, "    domain: app.example.org", "    domain: second.example.org", 1)
	report = runHttp(t, conf, httpRequest+`,method="oidc"`, "", `t:IsEqual("deny",actual.decision)`)
	require.Zero(t, report.ExitCode(), "%+v", report)
}

func TestHttpRequirementsUseCanonicalHostAndIndependentTransportSwitches(t *testing.T) {
	for _, test := range []struct{ name, flow, request, decision string }{
		{"HTTP disabled", "    http: {enabled: false}\n", httpRequest, "deny"},
		{"SSH disabled", "    ssh: {enabled: false}\n", httpRequest, "selected"},
		{"SSH ignores HTTP switch", "    http: {enabled: false}\n", `requestingName="ops"`, "selected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			outcome := ""
			if test.decision == "selected" {
				outcome = `primary=object{outcome="allow",account="alice"}`
			}
			report := runHttp(t, httpConfigurationPrefix+httpFlow("primary", "local")+test.flow, test.request, outcome, `t:IsEqual("`+test.decision+`",actual.decision)`)
			require.Zero(t, report.ExitCode(), "%+v", report)
		})
	}
	conf := httpConfigurationPrefix + httpFlow("primary", "local")
	conf = strings.Replace(conf, "http: {includedSlug: '.*'}", `http: {includedHost: '^app\.example\.org$', includedSlug: '^Work$', excludedRequestingName: '^other$'}`, 1)
	for _, req := range []string{httpRequest, strings.Replace(httpRequest, `slug="Work"`, `slug="Other"`, 1), strings.Replace(httpRequest, "APP.Example.Org.:08443", "second.example.org", 1), strings.Replace(httpRequest, `requestingName="ops"`, `requestingName="other"`, 1)} {
		outcome := ""
		expected := "deny"
		if req == httpRequest {
			outcome = `primary=object{outcome="allow",account="alice"}`
			expected = "selected"
		}
		report := runHttp(t, conf, req, outcome, `t:IsEqual("`+expected+`",actual.decision)`)
		require.Zero(t, report.ExitCode(), "%+v", report)
	}
}

func TestHttpMalformedAndUnmodeledRequestFactsAreErrors(t *testing.T) {
	for _, req := range []string{
		`transport="http",requestingName="ops",slug=""`,
		`transport="http",requestingName="ops",host="app.example.org"`,
		`transport="http",host="app.example.org",slug=""`,
		`transport="http",requestingName=null,host="app.example.org",slug=""`,
		`transport="http",requestingName="ops",host=null,slug=""`,
		`transport="http",requestingName="ops",host="app.example.org",slug=null`,
		httpRequest + `,origin="https://foreign.example"`,
		httpRequest + `,peer="127.0.0.1"`,
		`transport="",requestingName="ops"`, `transport="https",requestingName="ops"`,
		`transport=null,requestingName="ops"`, `requestingName="ops",method=null`,
		`requestingName="ops",host="app.example.org"`, `requestingName="ops",slug=""`,
		`requestingName="ops",method="oidc"`,
		strings.Replace(httpRequest, `requestingName="ops"`, `requestingName="`+strings.Repeat("x", 257)+`"`, 1),
		strings.Replace(httpRequest, `requestingName="ops"`, `requestingName="bad\nname"`, 1),
		strings.Replace(httpRequest, `requestingName="ops"`, `requestingName="bad\255name"`, 1),
		httpRequest + `,method="public-key"`, httpRequest + `,method="none"`,
	} {
		report := runHttp(t, httpConfigurationPrefix+httpFlow("primary", "local"), req, `primary=object{outcome="deny"}`, `t:IsEqual("deny",actual.decision)`)
		require.Equal(t, 2, report.ExitCode(), "%s: %+v", req, report)
		require.Zero(t, report.Results[0].Assertions)
	}
	for _, authority := range []string{"", "https://app.example.org", "app.example.org/path", "user@app.example.org", "app.example.org:0", "app.example.org:65536", "app.example.org?secret", "[fe80::1%eth0]", " app.example.org"} {
		report := runHttp(t, httpConfigurationPrefix+httpFlow("primary", "code"), strings.Replace(httpRequest, "APP.Example.Org.:08443", authority, 1)+`,method="oidc"`, "", `t:IsEqual("deny",actual.decision)`)
		require.Equal(t, 2, report.ExitCode(), "%+v", report)
	}
	for _, slug := range []string{"/", "/Work", "Work/", "one/two/three", "api/Work", "login", "assets/x", "a%2fb", "..", strings.Repeat("x", 65)} {
		report := runHttp(t, httpConfigurationPrefix+httpFlow("primary", "code"), strings.Replace(httpRequest, `slug="Work"`, `slug="`+slug+`"`, 1)+`,method="oidc"`, "", `t:IsEqual("deny",actual.decision)`)
		require.Equal(t, 2, report.ExitCode(), "%+v", report)
	}
	root := runHttp(t, httpConfigurationPrefix+httpFlow("primary", "code"), strings.Replace(httpRequest, `slug="Work"`, `slug=""`, 1)+`,method="oidc"`, httpAssumption("primary"), `t:IsEqual("selected",actual.decision);t:IsEqual("",actual.request.slug)`)
	require.Zero(t, root.ExitCode(), "%+v", root)
	rootOnly := strings.Replace(httpConfigurationPrefix+httpFlow("primary", "code"), "    requirement:\n      http: {includedSlug: '.*'}\n", "", 1)
	defaultRoot := runHttp(t, rootOnly, strings.Replace(httpRequest, `slug="Work"`, `slug=""`, 1)+`,method="oidc"`, httpAssumption("primary"), `t:IsEqual("selected",actual.decision)`)
	require.Zero(t, defaultRoot.ExitCode(), "%+v", defaultRoot)
	defaultOther := runHttp(t, rootOnly, httpRequest+`,method="oidc"`, "", `t:IsEqual("deny",actual.decision)`)
	require.Zero(t, defaultOther.ExitCode(), "default slug requirements are root-only: %+v", defaultOther)
}

func TestHttpUnsupportedAuthorizersAndHostMetadataCannotTurnIntoDenial(t *testing.T) {
	for _, method := range []string{"password", "keyboard-interactive", "oidc"} {
		conf := strings.Replace(httpConfigurationPrefix, "    type: local", "    type: none", 1) + httpFlow("primary", "local")
		report := runHttp(t, conf, httpRequest+`,method="`+method+`"`, "", `t:IsEqual("deny",actual.decision)`)
		require.Equal(t, 2, report.ExitCode(), "%+v", report)
		require.Zero(t, report.Results[0].Assertions)
	}
	conf := strings.Replace(httpConfigurationPrefix, `mapped-{{ .authentication.principal }}`, `{{ .remote.host }}`, 1) + httpFlow("primary", "local")
	report := runHttp(t, conf, httpRequest, `primary=object{outcome="allow",account="alice"}`, `t:IsEqual("deny",actual.decision)`)
	require.Equal(t, 2, report.ExitCode(), "HTTP server authority is not modeled peer metadata: %+v", report)
}

func TestHttpInteractiveLocalEligibilityUsesProductionCapabilities(t *testing.T) {
	conf := strings.Replace(httpConfigurationPrefix, "    type: local", "    type: local\n    password: {interactiveAllowed: false}", 1) + httpFlow("primary", "local")
	report := runHttp(t, conf, httpRequest+`,method="keyboard-interactive"`, "", `t:IsEqual("deny",actual.decision)`)
	require.Zero(t, report.ExitCode(), "a statically disabled method must not require an outcome: %+v", report)
	// Password assumptions still describe the post-authentication boundary, not
	// a native credential-policy test or a second interactive-method hint.
	report = runHttp(t, conf, httpRequest, `primary=object{outcome="allow",account="alice"}`, `t:IsEqual("selected",actual.decision)`)
	require.Zero(t, report.ExitCode(), "%+v", report)
}

func TestHttpSelectionNeverStartsAnHTTPOrOidcRuntime(t *testing.T) {
	transport := new(oidcNoNetwork)
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: transport})
	for _, kind := range []string{"device", "code"} {
		method := "keyboard-interactive"
		if kind == "code" {
			method = "oidc"
		}
		conf := strings.ReplaceAll(httpConfigurationPrefix+httpFlow("primary", kind), "https://issuer.example", "https://127.0.0.1:1")
		source := strings.ReplaceAll(httpSource(httpRequest+`,method="`+method+`"`, httpAssumption("primary"), `t:IsEqual("selected",actual.decision)`), "https://issuer.example", "https://127.0.0.1:1")
		report := RunSources(ctx, []byte(source), []byte(conf))
		require.Zero(t, report.ExitCode(), "%+v", report)
	}
	require.Zero(t, transport.calls.Load())
}

func TestHttpInvalidInputsDoNotEchoAuthoritySecrets(t *testing.T) {
	report := runHttp(t, httpConfigurationPrefix+httpFlow("primary", "code"), strings.Replace(httpRequest, "APP.Example.Org.:08443", "user:PRIVATE-SECRET@app.example.org", 1)+`,method="oidc"`, "", `t:IsEqual("deny",actual.decision)`)
	require.Equal(t, 2, report.ExitCode())
	var raw bytes.Buffer
	require.NoError(t, report.WriteJSON(&raw))
	require.NotContains(t, raw.String(), "PRIVATE-SECRET")
}
