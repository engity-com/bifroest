package test

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/errors"
)

func TestFixtureDataEncodingRequiresValidUTF8(t *testing.T) {
	for _, text := range []struct {
		name, value string
		valid       bool
	}{
		{"ASCII", "alice", true},
		{"Unicode", "Grüße-属性", true},
		{"replacement character", "\ufffd", true},
		{"NUL encoding", "\x00", true}, // Identity/control eligibility is separate.
		{"invalid FF", "\xff", false},
		{"invalid FE", "\xfe", false},
		{"continuation", "\x80", false},
		{"overlong", "\xc0\xaf", false},
		{"surrogate", "\xed\xa0\x80", false},
		{"above Unicode range", "\xf4\x90\x80\x80", false},
		{"truncated", "\xe2\x82", false},
	} {
		for _, shape := range []struct {
			name string
			data any
		}{
			{"scalar", text.value},
			{"object key", map[string]any{text.value: "value"}},
			{"object value", map[string]any{"key": text.value}},
			{"list item", []any{text.value}},
			{"nested key", map[string]any{"claims": []any{map[string]any{text.value: "value"}}}},
			{"nested value", map[string]any{"extra": []any{map[string]any{"key": text.value}}}},
		} {
			t.Run(text.name+"/"+shape.name, func(t *testing.T) {
				// RawMessage skips fixed-property validation, but must not skip
				// encoding checks on arbitrary claims/extra objects and keys.
				var target json.RawMessage
				err := decodeData(shape.data, &target)
				if text.valid {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.True(t, errors.Config.IsErr(err))
				}
			})
		}
	}
}

func TestRunnerRejectsMalformedFixtureIdentifiersWithoutRepair(t *testing.T) {
	identity := strings.TrimPrefix(accountSource(), `name="alice",`)
	groupIdentity := `gid=42`
	if runtime.GOOS == "windows" {
		groupIdentity = `sid="S-1-5-21-1-2-3-3001"`
	}
	type scenario struct {
		name, facts, assumed string
		code                 int
	}
	tests := []scenario{
		{"ASCII control", `accounts=list{object{name="alice",` + identity + `}}`, `"alice"`, 0},
		{"Unicode control", `accounts=list{object{name="Grüße",` + identity + `}}`, `"Grüße"`, 0},
		{"replacement control", `accounts=list{object{name="\239\191\189",` + identity + `}}`, `"\239\191\189"`, 0},
		{"account name", `accounts=list{object{name="\255",` + identity + `}}`, `"\239\191\189"`, 2},
		{"assumed account", `accounts=list{object{name="\239\191\189",` + identity + `}}`, `"\255"`, 2},
		{"distinct malformed names", `accounts=list{object{name="\255",` + identity + `}}`, `"\254"`, 2},
		{"absent name", `accounts=list{object{name="alice",` + identity + `}},absentNames=list{"\255"}`, `"alice"`, 2},
		{"supplementary group name", `accounts=list{object{name="alice",` + identity + `,groups=list{object{name="\255",` + groupIdentity + `}}}}`, `"alice"`, 2},
	}
	if runtime.GOOS != "windows" {
		tests = append(tests, scenario{"primary group name", `accounts=list{object{name="alice",` + identity + `,group=object{name="\255",gid=42}}}`, `"alice"`, 2})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := `suite{name="encoding",environment=object{` + test.facts + `},tests={{name="identity",input=object{request=object{requestingName="ops"},authentication=object{primary=object{outcome="allow",account=` + test.assumed + `}}},verify=function(t,actual)t:IsEqual("selected",actual.decision)end}}}`
			report := RunSources(t.Context(), []byte(source), []byte(testConfiguration))
			require.Equal(t, test.code, report.ExitCode(), "%+v", report)
			require.Len(t, report.Results, 1)
			if test.code == 2 {
				require.Equal(t, "config", report.Results[0].Category)
				require.Zero(t, report.Results[0].Assertions)
			} else {
				require.Equal(t, Summary{Passed: 1}, report.Summary())
				require.Equal(t, 1, report.Results[0].Assertions)
			}
		})
	}
}

func TestOidcFixturesRejectMalformedUTF8BeforeJSON(t *testing.T) {
	for _, test := range []struct{ name, old, replacement string }{
		{"subject", `"subject"`, `"\255"`},
		{"claim key collision", `claims=object{`, `claims=object{["\255"]="one",["\254"]="two",`},
		{"claim value", `claims=object{`, `claims=object{malformed="\255",`},
		{"extra key", `extra=object{`, `extra=object{["\255"]="value",`},
		{"extra value", `extra=object{`, `extra=object{malformed="\255",`},
		{"access token", `accessToken="access"`, `accessToken="\255"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := strings.ReplaceAll(oidcSource(`t:IsEqual("selected",actual.decision)`), test.old, test.replacement)
			report := runOidc(t, "oidcDeviceAuth", "constant", source)
			require.Equal(t, 2, report.ExitCode(), "%+v", report)
			require.Len(t, report.Results, 1)
			require.Equal(t, "config", report.Results[0].Category)
			require.Zero(t, report.Results[0].Assertions)
		})
	}
}

func TestOidcFixturesPreserveValidUnicodeKeysAndValues(t *testing.T) {
	source := oidcSource(`
 t:IsEqual("selected",actual.decision)
 t:IsEqual("Grüße",actual.identity.principal)
 t:IsEqual("replacement",t.input.authentication.primary.oidc.idToken.claims["�"])
 t:IsEqual("�",t.input.authentication.primary.oidc.token.extra["属性"])
 `)
	source = strings.Replace(source, `claims=object{`, `claims=object{["属性"]="Grüße",["�"]="replacement",`, 1)
	source = strings.Replace(source, `extra=object{`, `extra=object{["属性"]="�",`, 1)
	for _, kind := range []string{"oidcDeviceAuth", "oidcAuthorizationCode"} {
		t.Run(kind, func(t *testing.T) {
			report := runOidc(t, kind, `{{ .authorization.idToken.属性 }}`, source)
			require.Zero(t, report.ExitCode(), "%+v", report)
			require.Equal(t, Summary{Passed: 1}, report.Summary())
			require.Equal(t, 4, report.Results[0].Assertions)
		})
	}
}
