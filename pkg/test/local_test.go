package test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func mappedSource(verify string) string {
	return strings.Replace(suiteSource(verify), `outcome="allow",account="alice"`, `outcome="allow",mode="mapped-local"`, 1)
}

func TestMappedLocalAuthenticationUsesProductionRemoteName(t *testing.T) {
	configuration := strings.Replace(testConfiguration, "type: local", `type: local
      remoteName: '{{ if eq .remote.user "ops" }}alice{{ else }}other{{ end }}'`, 1)
	source := mappedSource(`
 t:IsEqual("selected",actual.decision)
 t:IsEqual("mapped-local",actual.authentication.mode)
 t:IsEqual("alice",actual.authentication.remoteName)
 t:IsEqual("alice",actual.authentication.account)
 t:IsEqual("mapped-alice",actual.identity.principal)
 t:IsEqual("ops",t.input.request.requestingName)
 `)
	report := RunSources(t.Context(), []byte(source), []byte(configuration))
	require.Zero(t, report.ExitCode(), "%+v", report)
	for _, replacement := range []string{`mode="mapped-local",account="other"`, `mode="unknown"`} {
		invalid := strings.Replace(source, `mode="mapped-local"`, replacement, 1)
		require.Equal(t, 2, RunSources(t.Context(), []byte(invalid), []byte(configuration)).ExitCode())
	}
}

func TestMappedLocalDistinguishesDenialAbsenceAndUnmodeledAccounts(t *testing.T) {
	configuration := strings.Replace(testConfiguration, "type: local", "type: local\n      remoteName: alice", 1)
	deny := strings.Replace(mappedSource(`t:IsEqual("deny",actual.decision)`), `outcome="allow"`, `outcome="deny"`, 1)
	require.Zero(t, RunSources(t.Context(), []byte(deny), []byte(configuration)).ExitCode())
	for _, name := range []string{"unmodeled", "absent"} {
		conf := strings.Replace(configuration, "remoteName: alice", "remoteName: "+name, 1)
		source := strings.Replace(mappedSource(`t:IsEqual(true,true)`), `accounts=list{`, `absentNames=list{"absent"},accounts=list{`, 1)
		report := RunSources(t.Context(), []byte(source), []byte(conf))
		require.Equal(t, 2, report.ExitCode(), "%+v", report)
		require.Equal(t, "error", report.Results[0].Status)
		require.Zero(t, report.Results[0].Assertions)
	}
}

func TestMappedLocalNeverReadsHostFieldsOrUnboundedTemplates(t *testing.T) {
	for _, mapping := range []string{`{{ env "BIFROEST_TEST_SECRET" }}`, `{{ .remote.host }}alice`, `{{ .connection.remote.host }}alice`, `{{ .authorization.user.name }}`, `{{ range .remote.user }}x{{ end }}`, `{{ .remote.user }} invalid`} {
		configuration := strings.Replace(testConfiguration, "type: local", "type: local\n      remoteName: '"+mapping+"'", 1)
		report := RunSources(t.Context(), []byte(mappedSource(`t:IsEqual(true,true)`)), []byte(configuration))
		require.Equal(t, 2, report.ExitCode(), "%s: %+v", mapping, report)
	}
}

func TestPostAuthenticationBindingIsNotReinterpretedAsRemoteNameEvidence(t *testing.T) {
	configuration := strings.Replace(testConfiguration, "type: local", "type: local\n      remoteName: another-account", 1)
	report := RunSources(t.Context(), []byte(suiteSource(`t:IsEqual("post-authentication",actual.authentication.mode);t:IsEqual("alice",actual.authentication.account)`)), []byte(configuration))
	require.Zero(t, report.ExitCode(), "%+v", report)
}

func TestMappedLocalAccountNameComparisonUsesPlatformRules(t *testing.T) {
	configuration := strings.Replace(testConfiguration, "type: local", "type: local\n      remoteName: ALICE", 1)
	source := strings.Replace(mappedSource(`t:IsEqual("alice",actual.authentication.account)`), `mode="mapped-local"`, `mode="mapped-local",account="alice"`, 1)
	expected := 2
	if runtime.GOOS == "windows" {
		expected = 0
	}
	require.Equal(t, expected, RunSources(t.Context(), []byte(source), []byte(configuration)).ExitCode())
}

func TestNumericGroupAndAbsentIdentityFactsCannotCoerceFloats(t *testing.T) {
	for _, fragment := range []string{`absentUIDs=list{1.0}`, `accounts=list{object{name="alice",uid=1001,group=object{name="users",gid=1.0}}}`, `accounts=list{object{name="alice",uid=1001,groups=list{object{name="users",gid=1.0}}}}`} {
		source := `suite{name="floats",environment=object{` + fragment + `},tests={{name="case",input=object{request=object{requestingName="ops"},authentication=object{primary=object{outcome="deny"}}},verify=function(t,actual)t:IsEqual("deny",actual.decision)end}}}`
		report := RunSources(t.Context(), []byte(source), []byte(testConfiguration))
		require.Equal(t, 2, report.ExitCode(), "%+v", report)
	}
}

func TestNonlocalManagementIsKnownUnavailableNotFalse(t *testing.T) {
	configuration := strings.Replace(testConfiguration, "mapped-{{ .authentication.principal }}", `{{ if eq .authorization.user.managed nil }}unavailable{{ else }}incorrect{{ end }}`, 1)
	report := RunSources(t.Context(), []byte(suiteSource(`t:IsEqual("unavailable",actual.identity.principal)`)), []byte(configuration))
	require.Zero(t, report.ExitCode(), "%+v", report)
}

func TestNormalizedLocalSelectorsRetainIntegersAndEnforceBounds(t *testing.T) {
	value, err := normalizedJSON([]byte(`{"uid":4294967295,"enabled":false,"empty":[],"absent":null}`))
	require.NoError(t, err)
	require.Equal(t, int64(4294967295), value.(map[string]any)["uid"])
	require.Equal(t, false, value.(map[string]any)["enabled"])
	require.Equal(t, []any{}, value.(map[string]any)["empty"])
	require.Nil(t, value.(map[string]any)["absent"])
	for _, raw := range []string{`{"uid":1.0}`, `{} {}`, `{"uid":9223372036854775808}`, strings.Repeat("[", maxDepth+2) + "0" + strings.Repeat("]", maxDepth+2), `["` + strings.Repeat("x", maxString+1) + `"]`, "[" + strings.Repeat("0,", maxNodes) + "0]", strings.Repeat(" ", maxSource+1)} {
		_, err := normalizedJSON([]byte(raw))
		require.Error(t, err)
	}
}
