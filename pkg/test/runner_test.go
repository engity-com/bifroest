package test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testConfiguration = `flows:
  - name: primary
    requirement:
      includedRequestingName: '^ops$'
    authorization:
      type: local
      principal: 'mapped-{{ .authentication.principal }}'
    environment:
      type: ssh
      address: WORK.EXAMPLE.
      user: '{{ .authentication.principal }}'
      acceptAllHostKeys: true
      portForwardingAllowed: false
`

func accountSource() string {
	if runtime.GOOS == "windows" {
		return `name="alice",sid="S-1-5-21-1-2-3-1001"`
	}
	return `name="alice",uid=1001`
}
func suiteSource(verify string) string {
	return `suite {
 name="offline",
 environment=object{accounts=list{object{` + accountSource() + `}}},
 tests={{ name="example", input=object{request=object{requestingName="ops"},authentication=object{primary=object{outcome="allow",account="alice"}}},
 verify=function(t, actual) ` + verify + ` end }}
}`
}
func run(t *testing.T, verify string) Report {
	t.Helper()
	return RunSources(t.Context(), []byte(suiteSource(verify)), []byte(testConfiguration))
}

func TestOfflineProductionPath(t *testing.T) {
	_, err := discover(t.Context(), []byte(suiteSource(`t:IsEqual(true,true)`)), nil)
	require.NoError(t, err)
	report := run(t, `
 t:IsEqual("selected",actual.decision)
 t:IsEqual("primary",actual.flow)
 t:IsEqual(true,actual.authenticationAssumed)
 t:IsEqual("mapped-alice",actual.identity.principal)
 t:IsEqual("local",actual.identity.issuer)
 t:IsEqual("work.example.:22",actual.environment.address)
 t:IsEqual("mapped-alice",actual.environment.user)
 t:IsEqual(false,actual.environment.portForwardingAllowed)
 t:IsEqual("ops",t.input.request.requestingName)
 t:IsEqual("alice",t.environment.accounts[1].name)
 t:IsEqual("primary",t.configuration.flows[1].name)
 `)
	require.Equal(t, 0, report.ExitCode(), "%+v", report)
	require.Equal(t, 11, report.Results[0].Assertions)
}

func TestSuiteDeclarationsDoNotUseReportAPIVersion(t *testing.T) {
	source := suiteSource(`t:IsEqual("selected",actual.decision)`)
	report := RunSources(t.Context(), []byte(source), []byte(testConfiguration))
	require.Zero(t, report.ExitCode(), "%+v", report)
	require.Equal(t, APIVersion, report.APIVersion)
	var raw bytes.Buffer
	require.NoError(t, report.WriteJSON(&raw))
	require.Contains(t, raw.String(), `"apiVersion":"`+APIVersion+`"`)
	for _, value := range []string{`"` + APIVersion + `"`, `"unsupported"`, `1`} {
		t.Run(value, func(t *testing.T) {
			obsolete := strings.Replace(source, "suite {", "suite {apiVersion="+value+",", 1)
			report := RunSources(t.Context(), []byte(obsolete), []byte(testConfiguration))
			require.Equal(t, 2, report.ExitCode(), "%+v", report)
			require.Len(t, report.Results, 1)
			require.Equal(t, "config", report.Results[0].Category)
			require.Zero(t, report.Results[0].Assertions)
		})
	}
}

func TestIgnoredAssertionsAndStructuredFailures(t *testing.T) {
	report := run(t, `t:IsEqual("wrong",actual.flow,"first reason");pcall(function() t:IsEqual(true,false,"second reason") end)`)
	require.Equal(t, 1, report.ExitCode())
	require.Equal(t, "failed", report.Results[0].Status)
	require.Len(t, report.Results[0].Failures, 2)
	require.Positive(t, report.Results[0].Failures[0].Line)
	require.Equal(t, "first reason", report.Results[0].Failures[0].Reason)
	var text, raw bytes.Buffer
	require.NoError(t, report.WriteText(&text))
	require.NoError(t, report.WriteJSON(&raw))
	require.Contains(t, text.String(), "first reason")
	require.Contains(t, raw.String(), `"status":"failed"`)
}

func TestErrorsCannotBecomeDenyOrSuccess(t *testing.T) {
	for _, body := range []string{
		``,
		`error("private-secret")`,
		`pcall(function() t:IsEqual(function() end,actual.flow) end);t:IsEqual(true,true)`,
		`pcall(function() t:IsEqual(true,true,42) end);t:IsEqual(true,true)`,
		`t:IsEqual("deny",actual.unmodeled)`,
		`t.input.request.requestingName="changed"`,
		`actual.flow="changed"`,
		`t.configuration.flows[1].name="changed"`,
		`for i=1,129 do t:IsEqual(true,true) end`,
	} {
		t.Run(body, func(t *testing.T) {
			report := run(t, body)
			require.Equal(t, 2, report.ExitCode(), "%+v", report)
			var out bytes.Buffer
			require.NoError(t, report.WriteJSON(&out))
			require.NotContains(t, out.String(), "private-secret")
		})
	}
}

func TestReadOnlyViewsAndTypedValues(t *testing.T) {
	report := run(t, `
 local ok=pcall(function() t.environment.accounts[1].name="changed" end)
 t:IsEqual(false,ok)
 t:IsEqual("alice",t.environment.accounts[1].name)
 t:IsEqual(list{},list{})
 t:IsEqual(object{},object{})
 t:IsEqual(null,null)
 t:IsEqual(nil,nil)
 t:IsEqual(1,#t.environment.accounts)
 `)
	require.Zero(t, report.ExitCode(), "%+v", report)
	for _, body := range []string{`t:IsEqual(null,nil)`, `t:IsEqual(false,0)`, `t:IsEqual("1",1)`, `t:IsEqual(list{},object{})`, `t:IsEqual(1,1.0)`} {
		report := run(t, body)
		require.Equal(t, 1, report.ExitCode(), "%+v", report)
	}
}

func TestLuaHasNoHostCapabilities(t *testing.T) {
	report := run(t, `for _,name in ipairs({"os","io","package","require","load","loadfile","dofile","debug","go","math","rawset","rawget","setmetatable","getmetatable","collectgarbage","print"}) do t:IsEqual("nil",type(_ENV[name]),name) end`)
	require.Zero(t, report.ExitCode(), "%+v", report)
}

func TestLuaStateAndUpvaluesAreIsolated(t *testing.T) {
	source := `local counter=0
 local function verify(t,actual) counter=counter+1;t:IsEqual(1,counter);t:IsEqual("primary",actual.flow) end
 suite{name="isolated",
 environment=object{accounts=list{object{` + accountSource() + `}}},tests={
 {name="first",input=object{request=object{requestingName="ops"},authentication=object{primary=object{outcome="allow",account="alice"}}},verify=verify},
 {name="second",input=object{request=object{requestingName="ops"},authentication=object{primary=object{outcome="allow",account="alice"}}},verify=verify}}}`
	report := RunSources(t.Context(), []byte(source), []byte(testConfiguration))
	require.Zero(t, report.ExitCode(), "%+v", report)
	require.Len(t, report.Results, 2)
}

func TestProtectedCallsShareTheOuterBudget(t *testing.T) {
	report := run(t, `
 local ok,value=pcall(function(a) return a+1 end,41)
 t:IsEqual(true,ok)
 t:IsEqual(42,value)
 local caught=pcall(function() error("ordinary Lua error") end)
 t:IsEqual(false,caught)
 local nested=pcall(function() local ok=pcall(function() error("nested") end);t:IsEqual(false,ok) end)
 t:IsEqual(true,nested)
 `)
	require.Zero(t, report.ExitCode(), "%+v", report)
	for _, body := range []string{
		`pcall(function() pcall(function() while true do end end) end);t:IsEqual(true,true)`,
		`pcall(function() pcall(function() local s="x";while true do s=s..s end end) end);t:IsEqual(true,true)`,
	} {
		report := run(t, body)
		require.Equal(t, 2, report.ExitCode(), "%+v", report)
		require.Equal(t, "system", report.Results[0].Category)
		require.Zero(t, report.Results[0].Assertions, "execution must not continue after quota exhaustion")
	}
}

func TestLuaResourceLimitsAndSourceBounds(t *testing.T) {
	for _, source := range []string{
		`while true do end`,
		suiteSource(`while true do end`),
		suiteSource(`pcall(function() local s="x";while true do s=s..s end end);t:IsEqual(true,true)`),
		`local d=object{};for i=1,100 do d=object{child=d} end;` + suiteSource(`t:IsEqual(true,true)`),
		strings.Repeat(" ", maxSource+1),
		`suite{tests={}}`,
		`pcall(function() suite{} end)`,
	} {
		t.Run(source[:min(len(source), 70)], func(t *testing.T) {
			started := time.Now()
			report := RunSources(t.Context(), []byte(source), []byte(testConfiguration))
			require.Equal(t, 2, report.ExitCode(), "%+v", report)
			require.Less(t, time.Since(started), 10*time.Second)
		})
	}
}

func TestTemplateAdmissionPreventsHostAccessAndUnboundedWork(t *testing.T) {
	t.Setenv("BIFROEST_POLICY_SECRET", "private-secret")
	for _, expression := range []string{
		`{{ env "BIFROEST_POLICY_SECRET" }}`, `{{ file "/etc/passwd" }}`, `{{ repeat 1000000000 "x" }}`,
		`{{ printf "%1000000000s" "x" }}`, `{{ range . }}x{{ end }}`, `{{ define "x" }}{{ template "x" . }}{{ end }}{{ template "x" . }}`,
	} {
		t.Run(expression, func(t *testing.T) {
			conf := strings.Replace(testConfiguration, `mapped-{{ .authentication.principal }}`, expression, 1)
			report := RunSources(t.Context(), []byte(suiteSource(`t:IsEqual("deny",actual.decision)`)), []byte(conf))
			require.Equal(t, 2, report.ExitCode(), "%+v", report)
			var out bytes.Buffer
			require.NoError(t, report.WriteJSON(&out))
			require.NotContains(t, out.String(), "private-secret")
		})
	}
	for _, source := range []string{`constant`, `{{ if eq .remote.user "ops" }}yes{{ else }}no{{ end }}`, `{{ .authentication.principal }}`} {
		require.NoError(t, admitTemplate(source))
	}
}

func TestMissingFactsDoNotBecomeDeny(t *testing.T) {
	for _, source := range []string{
		strings.Replace(suiteSource(`t:IsEqual("deny",actual.decision)`), `primary=object{outcome="allow",account="alice"}`, ``, 1),
		strings.Replace(suiteSource(`t:IsEqual("deny",actual.decision)`), `account="alice"`, `account="unmodeled"`, 1),
	} {
		report := RunSources(t.Context(), []byte(source), []byte(testConfiguration))
		require.Equal(t, 2, report.ExitCode())
		require.Zero(t, report.Results[0].Assertions)
	}
	source := strings.Replace(suiteSource(`t:IsEqual("deny",actual.decision)`), `requestingName="ops"`, `requestingName="excluded"`, 1)
	require.Zero(t, RunSources(t.Context(), []byte(source), []byte(testConfiguration)).ExitCode())
}

func TestProductionFlowOrderFallbackAndReferences(t *testing.T) {
	conf := `authorizations:
  local:
    type: local
environments:
  target:
    type: ssh
    address: WORK.EXAMPLE.
    user: '{{ .authentication.principal }}'
    acceptAllHostKeys: true
flows:
  - name: first
    authorization: local
    environment: target
  - name: second
    authorization: local
    environment: target
`
	for _, test := range []struct {
		name, outcomes, expected string
		code                     int
	}{
		{"deny falls through", `first=object{outcome="deny"},second=object{outcome="allow",account="alice"}`, "second", 0},
		{"first wins", `first=object{outcome="allow",account="alice"}`, "first", 0},
		{"unknown stops", `second=object{outcome="allow",account="alice"}`, "", 2},
		{"missing identity stops", `first=object{outcome="allow",account="unmodeled"},second=object{outcome="allow",account="alice"}`, "", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := strings.Replace(suiteSource(`t:IsEqual("`+test.expected+`",actual.flow)`), `primary=object{outcome="allow",account="alice"}`, test.outcomes, 1)
			report := RunSources(t.Context(), []byte(source), []byte(conf))
			require.Equal(t, test.code, report.ExitCode(), "%+v", report)
			if test.code == 2 {
				require.Zero(t, report.Results[0].Assertions)
			}
		})
	}
}

func TestUnknownMetadataAndInvalidPrincipalRetainConfigCategory(t *testing.T) {
	for _, mapping := range []string{`{{ .authorization.user.homeDir }}`, `{{ .authorization.user.managed }}`, `{{ .unmodeled }}`, `{{ "" }}`} {
		conf := strings.Replace(testConfiguration, `mapped-{{ .authentication.principal }}`, mapping, 1)
		report := RunSources(t.Context(), []byte(suiteSource(`t:IsEqual("deny",actual.decision)`)), []byte(conf))
		require.Equal(t, 2, report.ExitCode(), "%+v", report)
		require.Equal(t, "config", report.Results[0].Category)
	}
}

func TestKnownAbsenceCannotAuthenticateAndUIDZeroRemainsExplicit(t *testing.T) {
	for _, accountFacts := range []string{`accounts=list{},absentNames=list{"alice"}`, `accounts=list{object{name="alice"}}`} {
		source := strings.Replace(suiteSource(`t:IsEqual("deny",actual.decision)`), `accounts=list{object{`+accountSource()+`}}`, accountFacts, 1)
		report := RunSources(t.Context(), []byte(source), []byte(testConfiguration))
		require.Equal(t, 2, report.ExitCode(), "%+v", report)
	}
	if runtime.GOOS != "windows" {
		source := strings.Replace(suiteSource(`t:IsEqual("0",actual.identity.subject)`), `uid=1001`, `uid=0`, 1)
		require.Zero(t, RunSources(t.Context(), []byte(source), []byte(testConfiguration)).ExitCode())
		floatUID := strings.Replace(suiteSource(`t:IsEqual(true,true)`), `uid=1001`, `uid=1001.0`, 1)
		require.Equal(t, 2, RunSources(t.Context(), []byte(floatUID), []byte(testConfiguration)).ExitCode())
	}
}

func TestParallelRunsDoNotShareLuaState(t *testing.T) {
	for range 4 {
		t.Run("isolated", func(t *testing.T) {
			t.Parallel()
			report := run(t, `t:IsEqual("mapped-alice",actual.identity.principal)`)
			require.Zero(t, report.ExitCode(), "%+v", report)
		})
	}
}

func TestConfinedConfigurationAndExplicitInputs(t *testing.T) {
	dir := t.TempDir()
	suite := filepath.Join(dir, "access_bftest.lua")
	source := strings.Replace(suiteSource(`t:IsEqual("primary",actual.flow)`), `name="offline",`, `name="offline",configuration=file_content("configuration.yaml"),`, 1)
	require.NoError(t, os.WriteFile(suite, []byte(source), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "configuration.yaml"), []byte(testConfiguration), 0600))
	require.Zero(t, RunFile(t.Context(), suite, "").ExitCode())
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	require.NoError(t, os.WriteFile(outside, []byte(testConfiguration), 0600))
	source = strings.Replace(source, `configuration.yaml`, outside, 1)
	// filepath.ToSlash avoids introducing a Lua escape on Windows.
	source = strings.ReplaceAll(source, outside, filepath.ToSlash(outside))
	require.NoError(t, os.WriteFile(suite, []byte(source), 0600))
	require.Equal(t, 2, RunFile(t.Context(), suite, "").ExitCode())
	require.Equal(t, 2, RunFile(t.Context(), suite, outside).ExitCode(), "a fallback must not override a failing explicit configuration")
	require.NoError(t, os.WriteFile(suite, []byte(suiteSource(`t:IsEqual(true,true)`)), 0600))
	require.Zero(t, RunFile(t.Context(), suite, outside).ExitCode())
}

func TestCanceledRunAndMalformedYAML(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.Equal(t, 2, RunSources(ctx, []byte(suiteSource(`t:IsEqual(true,true)`)), []byte(testConfiguration)).ExitCode())
	for _, conf := range []string{testConfiguration + "---\nflows: []\n", `flows: [invalid]`, strings.Replace(testConfiguration, `type: ssh`, `type: local`, 1), strings.Repeat("x", maxSource+1)} {
		require.Equal(t, 2, RunSources(t.Context(), []byte(suiteSource(`t:IsEqual(true,true)`)), []byte(conf)).ExitCode())
	}
}
