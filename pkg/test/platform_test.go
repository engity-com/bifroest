package test

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func platformSuite(name, selector, verify string) string {
	return strings.Replace(inlineSuite(name, verify), `name="`+name+`",`, `name="`+name+`",platform=`+selector+`,`, 1)
}

func TestVersionSelectors(t *testing.T) {
	for _, test := range []struct {
		selector, version string
		match             bool
	}{
		{"1.2.0", "1.2.0", true},
		{"1.2.0", "1.2.1", false},
		{"1.2.0", "v1.2.0", true},
		{"v1.2.0", "1.2.0", true},
		{"1.2.0+build1", "1.2.0+build2", true},
		{"1", "1.99.99", true},
		{"1", "2.0.0", false},
		{"1", "0.99.99", false},
		{"1", "1.0.0-beta1", false},
		{"1.2", "1.2.99", true},
		{"1.2", "1.3.0", false},
		{"0", "0.1.0", true},
		{"0.0", "0.0.1", true},
		{"1.0.0-beta1", "1.0.0-beta1", true},
		{"1.0.0-beta1", "1.0.0", false},
		{"1.0.0-beta1", "1.0.0-beta2", false},
		{"[1.3.5,1.4.0)", "1.3.5", true},
		{"[1.3.5,1.4.0)", "1.3.99", true},
		{"[1.3.5,1.4.0)", "1.4.0", false},
		{"(1.3.5,1.4.0]", "1.3.5", false},
		{"(1.3.5,1.4.0]", "1.4.0", true},
		{"[1.3.5,1.4.0]", "1.4.0-beta1", false},
		{"[1.4.0-beta1,1.4.0)", "1.4.0-beta2", true},
		{"[1.4.0-beta1,1.4.0)", "1.4.0", false},
		{"(,1.4.0]", "0.1.0", true},
		{"[1.4.0,)", "2.0.0", true},
		{"[1.4.0,1.4.0]", "1.4.0", true},
		{"[ v1.3.5 , v1.4.0 )", "v1.3.6", true},
		{"development", "development", true},
		{"development", "Development", false},
		{"development", "development-dirty", false},
		{"development", "1.0.0", false},
		{"1.0.0", "development", false},
		{"1", "development", false},
		{"[1.0.0,2.0.0)", "development", false},
		{"Nightly-CUSTOM", "Nightly-CUSTOM", true},
		{"Nightly-CUSTOM", "nightly-custom", false},
		{"1.02.3", "1.02.3", true},
		{"1.02.3", "1.2.3", false},
		{"1.2.3", "1.02.3", false},
		{"V1.2.3", "v1.2.3", false},
		{"1.2.3", "V1.2.3", false},
	} {
		t.Run(test.selector+"/"+test.version, func(t *testing.T) {
			selector, err := parseVersionSelector(test.selector)
			require.NoError(t, err)
			require.Equal(t, test.match, selector.matches(test.version, parseSemver(test.version)))
		})
	}
	for _, value := range []string{"[1.0.0,2.0.0", "[1.0.0]", "[1.0.0,2.0.0,3.0.0)", "[2.0.0,1.0.0)", "(1.0.0,1.0.0]", "[development,2.0.0)", "[1,2)", "(,)", "[,2.0.0)", "[1.0.0,]", "18446744073709551616"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			_, err := parseVersionSelector(value)
			require.Error(t, err)
		})
	}
}

func TestPlatformFieldsAreOptionalAndCombineWithAnd(t *testing.T) {
	for _, test := range []struct {
		selector string
		match    bool
	}{
		{`nil`, true},
		{`{}`, true},
		{`{os={"darwin","linux"}}`, true},
		{`{os={"windows"}}`, false},
		{`{arch={"arm64","amd64"}}`, true},
		{`{arch={"arm64"}}`, false},
		{`{version={"development","1.2.0","[1.3.5,1.4.0)"}}`, true},
		{`{version={"2","1.3"}}`, true},
		{`{version={"development"}}`, false},
		{`{os={"linux"},arch={"amd64"},version={"1"}}`, true},
		{`{os={"windows"},arch={"amd64"},version={"1"}}`, false},
		{`{os={"linux"},arch={"arm64"},version={"1"}}`, false},
		{`{os={"linux"},arch={"amd64"},version={"2"}}`, false},
		{`{os={}}`, false},
		{`{arch={}}`, false},
		{`{version={}}`, false},
	} {
		t.Run(test.selector, func(t *testing.T) {
			source := platformSuite("platform", test.selector, `t:IsEqual("primary",actual.flow)`)
			report := RunSourcesWithOptions(t.Context(), []byte(source), nil, Options{Platform: Platform{OS: "linux", Arch: "amd64", Version: "1.3.7"}})
			if test.match {
				require.Zero(t, report.ExitCode(), "%+v", report)
				require.Len(t, report.Results, 1)
				require.Empty(t, report.SkippedSuites)
			} else {
				require.Equal(t, 2, report.ExitCode())
				require.Empty(t, report.Results)
				require.Len(t, report.SkippedSuites, 1)
				var text, raw bytes.Buffer
				require.NoError(t, report.WriteTextWithOptions(&text, TextOptions{Verbose: true}))
				require.Contains(t, text.String(), `--- SKIP: platform:`)
				require.NoError(t, report.WriteJSON(&raw))
				require.Contains(t, raw.String(), `"skippedSuites"`)
			}
		})
	}
}

func TestPlatformSelectorsValidateEvenWhenExcluded(t *testing.T) {
	for _, selector := range []string{
		`false`, `null`, `"linux"`, `{other={"linux"}}`, `{[1]="linux"}`,
		`{os="linux"}`, `{os={false}}`, `{os={""}}`, `{os={"Linux"}}`, `{os={null}}`,
		`{os={[2]="linux"}}`, `{arch={name="amd64"}}`, `{version={1.2}}`,
		`{os={"windows"},version={"[2.0.0,1.0.0)"}}`,
		`{version={"` + strings.Repeat("x", 257) + `"}}`,
		`{os={` + strings.Repeat(`"linux",`, 65) + `}}`,
	} {
		t.Run(selector, func(t *testing.T) {
			source := platformSuite("invalid", selector, `t:IsEqual(true,true)`)
			report := RunSourcesWithOptions(t.Context(), []byte(source), nil, Options{Platform: Platform{OS: "linux"}})
			require.Equal(t, 2, report.ExitCode(), "%+v", report)
			require.Empty(t, report.SkippedSuites)
			require.Len(t, report.Results, 1)
			require.Equal(t, "error", report.Results[0].Status)
		})
	}
}

func TestExcludedSuitesDoNotDecodeConfigurationOrRunVerification(t *testing.T) {
	dir := t.TempDir()
	source := platformSuite("excluded", `{os={"windows"}}`, `error("must not run")`)
	source = strings.Replace(source, testConfiguration, "invalid YAML", 1)
	writeInput(t, filepath.Join(dir, "excluded_bftest.lua"), source)
	writeInput(t, filepath.Join(dir, "included_bftest.lua"), platformSuite("included", `{os={"linux"}}`, `t:IsEqual(true,true)`))
	calls := 0
	report := RunPaths(t.Context(), []string{dir}, Options{Platform: Platform{OS: "linux"}, DefaultConfiguration: func(context.Context) ([]byte, error) {
		calls++
		t.Fatal("excluded suites must not load fallback configuration")
		return nil, nil
	}})
	require.Zero(t, report.ExitCode(), "%+v", report)
	require.Zero(t, calls)
	require.Len(t, report.Results, 1)
	require.Len(t, report.SkippedSuites, 1)
	physicalSource, err := filepath.EvalSymlinks(filepath.Join(dir, "excluded_bftest.lua"))
	require.NoError(t, err)
	require.Equal(t, physicalSource, report.SkippedSuites[0].Source)

	source = strings.Replace(namedSuite("excluded", `error("must not run")`), `name="excluded",`, `name="excluded",platform={os={"windows"}},`, 1)
	path := writeInput(t, filepath.Join(dir, "excluded_bftest.lua"), source)
	report = RunPaths(t.Context(), []string{path}, Options{Platform: Platform{OS: "linux"}, Configuration: filepath.Join(dir, "missing.yaml")})
	require.Empty(t, report.Results)
	require.Len(t, report.SkippedSuites, 1)
}

func TestPlatformDisjointSuitesMayShareQualifiedNames(t *testing.T) {
	dir := t.TempDir()
	writeInput(t, filepath.Join(dir, "linux_bftest.lua"), platformSuite("same", `{os={"linux"}}`, `t:IsEqual(true,true)`))
	writeInput(t, filepath.Join(dir, "windows_bftest.lua"), platformSuite("same", `{os={"windows"}}`, `t:IsEqual(true,true)`))
	for _, os := range []string{"linux", "windows"} {
		report := RunPaths(t.Context(), []string{dir}, Options{Platform: Platform{OS: os}})
		require.Zero(t, report.ExitCode(), "%+v", report)
		require.Len(t, report.Results, 1)
		require.Len(t, report.SkippedSuites, 1)
	}
}

func TestMissingVersionIsNotInventedAndOpaqueVersionsAreExact(t *testing.T) {
	for _, test := range []struct {
		version, selector string
		errors, skipped   int
	}{
		{"", `{version={"development"}}`, 1, 0},
		{"", `{os={"windows"},version={"development"}}`, 0, 1},
		{"development", `{version={"development"}}`, 0, 0},
		{"Development", `{version={"development"}}`, 0, 1},
		{"development", `{version={"1.0.0"}}`, 0, 1},
	} {
		source := platformSuite("version", test.selector, `t:IsEqual(true,true)`)
		report := RunSourcesWithOptions(t.Context(), []byte(source), nil, Options{Platform: Platform{OS: "linux", Version: test.version}})
		require.Len(t, report.SkippedSuites, test.skipped)
		if test.errors > 0 {
			require.Equal(t, "error", report.Results[0].Status)
		} else if test.skipped == 0 {
			require.Zero(t, report.ExitCode())
		}
	}
}

func TestPlatformIsPartOfTheReplayContract(t *testing.T) {
	a, err := discover(t.Context(), []byte(platformSuite("replay", `{os={"linux"}}`, `t:IsEqual(true,true)`)), nil)
	require.NoError(t, err)
	b, err := discover(t.Context(), []byte(platformSuite("replay", `{os={"windows"}}`, `t:IsEqual(true,true)`)), nil)
	require.NoError(t, err)
	require.False(t, sameSpec(a, b))
	require.True(t, sameSpec(a, a))
}

func TestUnixOSGroupIsExactlyLinuxAndDarwin(t *testing.T) {
	for _, os := range []string{"linux", "darwin", "windows", "freebsd", "unix"} {
		for _, selectors := range [][]string{{"unix"}, {"windows", "unix"}, {"darwin", "linux"}} {
			matched := matchesOS(selectors, os)
			want := os == "linux" || os == "darwin" || os == "windows" && selectors[0] == "windows"
			require.Equal(t, want, matched, "%v / %s", selectors, os)
		}
	}
	for _, selector := range []string{`{os={"unix"}}`, `{os={"unix"},arch={"amd64"},version={"1"}}`} {
		source := platformSuite("unix-group", selector, `t:IsEqual(true,true)`)
		for _, os := range []string{"linux", "darwin"} {
			report := RunSourcesWithOptions(t.Context(), []byte(source), nil, Options{Platform: Platform{OS: os, Arch: "amd64", Version: "1.2.3"}})
			require.Zero(t, report.ExitCode(), "%+v", report)
		}
	}
}

func TestPlatformMismatchReasonsAreConcise(t *testing.T) {
	for _, test := range []struct{ selector, reason string }{
		{`{os={"windows"}}`, "os does not match platform"},
		{`{arch={"arm64"}}`, "arch does not match platform"},
		{`{version={"2"}}`, "version does not match platform"},
	} {
		source := platformSuite("excluded", test.selector, `t:IsEqual(true,true)`)
		report := RunSourcesWithOptions(t.Context(), []byte(source), nil, Options{Platform: Platform{OS: "linux", Arch: "amd64", Version: "1.2.3"}})
		require.Equal(t, test.reason, report.SkippedSuites[0].Reason)
		require.Equal(t, 1, report.SkippedSuites[0].Tests)
	}
}

func TestSummaryCountsTestsInExcludedSuitesNotSuiteHeaders(t *testing.T) {
	source := []byte(`local tests={}
for i=1,3 do tests[i]={name="case-"..i,input=object{},verify=function(t,actual)t:IsEqual(true,true)end} end
suite{name="three",platform={os={"windows"}},environment=object{accounts=list{}},tests=tests}`)
	report := RunSourcesWithOptions(t.Context(), source, nil, Options{Platform: Platform{OS: "linux"}})
	require.Len(t, report.SkippedSuites, 1)
	require.Equal(t, 3, report.Summary().Skipped)
	require.Equal(t, 1, report.Summary().Errors, "no selected tests is a runner error")
}
