package main

import (
	"bytes"
	"context"
	goos "os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExecutableConfigurationDiagnostics(t *testing.T) {
	if goos.Getenv("BIFROEST_TEST_CONFIGURATION_DIAGNOSTICS_CHILD") == "1" {
		separator := slices.Index(goos.Args, "--")
		if separator < 0 {
			goos.Exit(2)
		}
		goos.Args = append([]string{"bifroest"}, goos.Args[separator+1:]...)
		main()
		goos.Exit(0)
	}
	binary, err := goos.Executable()
	require.NoError(t, err)
	for _, test := range []struct {
		name      string
		contents  string
		missing   bool
		fragments []string
		absent    []string
	}{
		{name: "missing file", missing: true, fragments: []string{"does not exist"}},
		{name: "YAML syntax", contents: "flows: [\n", fragments: []string{"yaml: line 1:", "did not find expected node content"}},
		{name: "missing required flows", contents: "flows: []\n", fragments: []string{"[flows]", "required but absent"}},
		{name: "invalid field type", contents: "flows:\n  - name: test\n    authorization:\n      type: none\n    environment:\n      type: management\n      includingCredentials: notBool\n", fragments: []string{"line 7:", "notBool", "into bool"}},
		{name: "invalid credential", contents: "flows:\n  - name: test\n    authorization:\n      type: simple\n      entries:\n        - name: test\n          password: CliCredentialMarker\n    environment:\n      type: dummy\n", fragments: []string{"[password]", "illegal password", "***redacted***", "[7:"}, absent: []string{"CliCredentialMarker"}},
		{name: "invalid credential template", contents: "flows:\n  - name: test\n    authorization:\n      type: oidcDeviceAuth\n      issuer: https://example.invalid\n      clientId: test\n      clientSecret: '{{ CliSecretTemplateMarker }}'\n    environment:\n      type: dummy\n", fragments: []string{"[clientSecret]", "invalid credential template", "***redacted***", "[7:"}, absent: []string{"CliSecretTemplateMarker"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "diagnostic-configuration.yaml")
			if !test.missing {
				require.NoError(t, goos.WriteFile(path, []byte(test.contents), 0600))
			}
			for name, args := range map[string][]string{
				"codec":          {"flow", "ls", "--configuration=" + path},
				"string options": {"key", "export", "host", "--configuration=" + path, "--address=example.invalid"},
			} {
				t.Run(name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()
					arguments := append([]string{"-test.run=^TestExecutableConfigurationDiagnostics$", "--"}, args...)
					command := exec.CommandContext(ctx, binary, arguments...)
					command.Env = append(goos.Environ(), "BIFROEST_TEST_CONFIGURATION_DIAGNOSTICS_CHILD=1")
					var stdout, stderr bytes.Buffer
					command.Stdout, command.Stderr = &stdout, &stderr
					err := command.Run()
					var exit *exec.ExitError
					require.ErrorAs(t, err, &exit, "%s", stderr.String())
					require.Equal(t, 1, exit.ExitCode(), "%s", stderr.String())
					require.NoError(t, ctx.Err())
					require.Empty(t, stdout.Bytes(), "configuration failures must not contaminate command results")
					require.Contains(t, stderr.String(), "cannot load configuration")
					require.Contains(t, stderr.String(), filepath.Base(path))
					for _, fragment := range test.fragments {
						require.Contains(t, stderr.String(), fragment)
					}
					for _, secret := range test.absent {
						require.NotContains(t, stderr.String(), secret)
					}
				})
			}
		})
	}
}
