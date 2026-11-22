package test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDocumentationGuideIsAnExecutableContract(t *testing.T) {
	block := func(marker string) string {
		return documentationBlock(t, "guides/testing.md", marker)
	}
	yaml := block("```yaml title=\"configuration.yaml\"")
	lua := block("```lua title=\"tests/access_bftest.lua\"")
	if runtime.GOOS == "windows" {
		lua = strings.Replace(lua, `os = { "unix" }`, `os = { "windows" }`, 1)
		lua = strings.Replace(lua, `object { name = "alice", uid = 1001 }`, `object { name = "alice", sid = "S-1-5-21-1-2-3-1001" }`, 1)
	}
	directory := t.TempDir()
	configuration := filepath.Join(directory, "configuration.yaml")
	tests := filepath.Join(directory, "tests")
	require.NoError(t, os.Mkdir(tests, 0700))
	source := filepath.Join(tests, "access_bftest.lua")
	require.NoError(t, os.WriteFile(configuration, []byte(yaml), 0600))
	require.NoError(t, os.WriteFile(source, []byte(lua), 0600))
	options := Options{Configuration: configuration}
	report := RunPaths(t.Context(), []string{tests}, options)
	require.Zero(t, report.ExitCode(), "%+v", report)
	require.Equal(t, Summary{Passed: 1}, report.Summary())
	// The supplied deployment file, outside the suite directory, must drive the
	// result. There is no suite-local configuration copy to fall back to.
	changedConfiguration := strings.Replace(yaml, `mapped-{{ .authentication.principal }}`, `changed-{{ .authentication.principal }}`, 1)
	require.NotEqual(t, yaml, changedConfiguration)
	require.NoError(t, os.WriteFile(configuration, []byte(changedConfiguration), 0600))
	changed := RunPaths(t.Context(), []string{tests}, options)
	require.Equal(t, 1, changed.ExitCode(), "%+v", changed)
	require.Equal(t, Summary{Failed: 1}, changed.Summary())
	require.NoError(t, os.WriteFile(configuration, []byte(yaml), 0600))
	// Follow the guide's next step: declare the denial case before suite and
	// insert its variable at the start of the ordinary tests array.
	require.Equal(t, 1, strings.Count(lua, "  tests = {\n"))
	lua = block("```lua title=\"Denied test\"") + strings.Replace(lua, "  tests = {\n", "  tests = {\n    deniedRequest,\n", 1)
	require.NoError(t, os.WriteFile(source, []byte(lua), 0600))
	report = RunPaths(t.Context(), []string{tests}, options)
	require.Zero(t, report.ExitCode(), "%+v", report)
	require.Equal(t, Summary{Passed: 2}, report.Summary())
	filteredOptions := options
	filteredOptions.Includes = []string{"^access/ops-"}
	filtered := RunPaths(t.Context(), []string{tests}, filteredOptions)
	require.Zero(t, filtered.ExitCode(), "%+v", filtered)
	require.Equal(t, Summary{Passed: 1}, filtered.Summary())
	require.NoError(t, os.WriteFile(source, []byte(strings.Replace(lua, `"mapped-alice", actual.identity.principal`, `"wrong-user", actual.identity.principal`, 1)), 0600))
	red := RunPaths(t.Context(), []string{tests}, options)
	require.Equal(t, 1, red.ExitCode(), "%+v", red)
	require.Equal(t, Summary{Passed: 1, Failed: 1}, red.Summary())
}

func documentationPage(t *testing.T, page string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", filepath.FromSlash(page)))
	require.NoError(t, err)
	return string(raw)
}

func documentationBlock(t *testing.T, page, marker string) string {
	t.Helper()
	_, rest, found := strings.Cut(documentationPage(t, page), marker+"\n")
	require.True(t, found, "missing documented block %s in %s", marker, page)
	content, _, closed := strings.Cut(rest, "\n```")
	require.True(t, closed, "unclosed documented block %s in %s", marker, page)
	return content + "\n"
}

func runDocumentationSuite(t *testing.T, source, configuration string) Report {
	t.Helper()
	if runtime.GOOS == "windows" {
		source = strings.ReplaceAll(source, `os = { "unix" }`, `os = { "windows" }`)
		source = strings.ReplaceAll(source, `object { name = "alice", uid = 1001 }`, `object { name = "alice", sid = "S-1-5-21-1-2-3-1001" }`)
	}
	directory := t.TempDir()
	configurationPath := filepath.Join(directory, "configuration.yaml")
	require.NoError(t, os.WriteFile(configurationPath, []byte(configuration), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "example_bftest.lua"), []byte(source), 0600))
	return RunPaths(t.Context(), []string{directory}, Options{Configuration: configurationPath})
}

func TestDocumentationOverviewExample(t *testing.T) {
	yaml := documentationBlock(t, "reference/testing/index.md", "```yaml title=\"configuration.yaml\"")
	source := documentationBlock(t, "reference/testing/index.md", "```lua title=\"access_bftest.lua\"")
	directory := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(directory, "configuration.yaml"), []byte(yaml), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "access_bftest.lua"), []byte(source), 0600))
	t.Chdir(directory)
	options := Options{Configuration: "configuration.yaml"}
	report := RunPaths(t.Context(), []string{"."}, options)
	require.Zero(t, report.ExitCode(), "%+v", report)
	require.Equal(t, Summary{Passed: 1}, report.Summary())
	// Matching the guest now requires an authentication observation. This must
	// error, rather than silently retaining the original configuration's denial.
	changedConfiguration := strings.Replace(yaml, "'^ops$'", "'^guest$'", 1)
	require.NotEqual(t, yaml, changedConfiguration)
	require.NoError(t, os.WriteFile("configuration.yaml", []byte(changedConfiguration), 0600))
	changed := RunPaths(t.Context(), []string{"."}, options)
	require.Equal(t, 2, changed.ExitCode(), "%+v", changed)
	require.Equal(t, Summary{Errors: 1}, changed.Summary())
	require.Zero(t, changed.Results[0].Assertions)
}

func TestDocumentationTestReferenceExample(t *testing.T) {
	declaration := documentationBlock(t, "reference/testing/tests.md", "```lua title=\"Test definition\"")
	base := documentationBlock(t, "reference/testing/suites.md", "```lua title=\"tests/reference_bftest.lua\"")
	prefix, _, found := strings.Cut(base, "  tests = {\n")
	require.True(t, found)
	source := declaration + prefix + "  tests = { selectedUser },\n}\n"
	configuration := documentationBlock(t, "guides/testing.md", "```yaml title=\"configuration.yaml\"")
	report := runDocumentationSuite(t, source, configuration)
	require.Zero(t, report.ExitCode(), "%+v", report)
	require.Equal(t, Summary{Passed: 1}, report.Summary())
}

func TestDocumentationSuiteReferenceExample(t *testing.T) {
	source := documentationBlock(t, "reference/testing/suites.md", "```lua title=\"tests/reference_bftest.lua\"")
	configuration := documentationBlock(t, "guides/testing.md", "```yaml title=\"configuration.yaml\"")
	report := runDocumentationSuite(t, source, configuration)
	require.Zero(t, report.ExitCode(), "%+v", report)
	require.Equal(t, Summary{Passed: 1}, report.Summary())
}

func TestDocumentationLuaFunctionExamples(t *testing.T) {
	blocks := regexp.MustCompile("(?ms)^```lua[^\n]*\n(.*?)^```$").FindAllStringSubmatch(documentationPage(t, "reference/testing/lua.md"), -1)
	require.Len(t, blocks, 5)
	var declarations strings.Builder
	for _, block := range blocks {
		declarations.WriteString(block[1])
		declarations.WriteByte('\n')
	}
	source := declarations.String() + `
suite {
 name="helpers",
 configuration=configuration, environment=object{},
 tests={{name="values",input=object{request=object{requestingName="guest"}},
 verify=function(t,actual)
  t:IsEqual("deny",actual.decision)
  t:IsEqual("alice",account.name)
  t:IsEqual(2,#names)
  t:IsEqual(object{},emptyObject)
  t:IsEqual(0,#emptyList)
  t:IsEqual(1,#accounts)
  t:IsEqual(nil,accounts[2])
  t:IsEqual(null,knownAbsent.token)
  t:IsEqual(object{},unknown)
  t:IsEqual(true,t:IsEqual("same","same","equal values return true"))
 end}}
}`
	configuration := documentationBlock(t, "guides/testing.md", "```yaml title=\"configuration.yaml\"")
	report := runDocumentationSuite(t, source, configuration)
	require.Zero(t, report.ExitCode(), "%+v", report)
	require.Equal(t, Summary{Passed: 1}, report.Summary())
}

func TestDocumentationReferenceVerificationFunctions(t *testing.T) {
	configuration := documentationBlock(t, "guides/testing.md", "```yaml title=\"configuration.yaml\"")
	base := documentationBlock(t, "guides/testing.md", "```lua title=\"tests/access_bftest.lua\"")
	callback := regexp.MustCompile(`(?s)verify = function\(t, actual\).*?\n      end,`)
	require.Len(t, callback.FindAllStringIndex(base, -1), 1)
	functionName := regexp.MustCompile(`local function (\w+)\(t, actual\)`)
	for _, page := range []string{"context.md", "assertions.md", "result.md"} {
		blocks := regexp.MustCompile("(?ms)^```lua[^\n]*\n(.*?)^```$").FindAllStringSubmatch(documentationPage(t, "reference/testing/"+page), -1)
		require.NotEmpty(t, blocks)
		for index, block := range blocks {
			t.Run(page+"/"+strconv.Itoa(index+1), func(t *testing.T) {
				name := functionName.FindStringSubmatch(block[1])
				require.Len(t, name, 2)
				source := block[1] + callback.ReplaceAllString(base, "verify = "+name[1]+",")
				if strings.Contains(block[1], `"deny", actual.decision`) {
					source = strings.Replace(source, `requestingName = "ops"`, `requestingName = "guest"`, 1)
				}
				report := runDocumentationSuite(t, source, configuration)
				require.Zero(t, report.ExitCode(), "%+v", report)
				require.Equal(t, Summary{Passed: 1}, report.Summary())
			})
		}
	}
}

func TestDocumentationOidcRecordExample(t *testing.T) {
	declaration := documentationBlock(t, "reference/testing/oidc.md", "```lua")
	configuration := documentationBlock(t, "guides/testing.md", "```yaml title=\"configuration.yaml\"")
	configuration = strings.Replace(configuration, "type: local", `type: oidcDeviceAuth
      issuer: https://issuer.example.org
      clientId: example-client
      clientSecret: example-only-not-a-credential
      retrieveIdToken: true
      retrieveUserInfo: false`, 1)
	configuration = strings.Replace(configuration, ".authentication.principal", ".authorization.idToken.preferred_username", 1)
	source := declaration + `
suite {
 name="oidc-reference",
 configuration=file_content("configuration.yaml"),environment=object{},
 tests={{name="mapped",input=object{
  request=object{requestingName="ops",method="keyboard-interactive"},
  authentication=authentication},verify=function(t,actual)
   t:IsEqual("selected",actual.decision)
   t:IsEqual("mapped-alice",actual.identity.principal)
   t:IsEqual("id-123",actual.identity.subject)
 end}}
}`
	report := runDocumentationSuite(t, source, configuration)
	require.Zero(t, report.ExitCode(), "%+v", report)
	require.Equal(t, Summary{Passed: 1}, report.Summary())
}
