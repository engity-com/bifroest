package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	gos "os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestPolicyOCIWorkflowUsesReadOnlyPermissionsAndKeepsOnlyReports(t *testing.T) {
	raw, err := gos.ReadFile("../../.github/workflows/build.yml")
	require.NoError(t, err)
	var workflow struct {
		Jobs map[string]yaml.Node `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &workflow))
	node, found := workflow.Jobs["test-policy-oci"]
	require.True(t, found)
	var job struct {
		RunsOn      string            `yaml:"runs-on"`
		Permissions map[string]string `yaml:"permissions"`
		Env         map[string]string `yaml:"env"`
		Steps       []struct {
			Uses, Run, If   string
			With            map[string]any
			Env             map[string]string
			ContinueOnError bool `yaml:"continue-on-error"`
		}
	}
	require.NoError(t, node.Decode(&job))
	require.Equal(t, "ubuntu-latest", job.RunsOn)
	require.Equal(t, map[string]string{"contents": "read"}, job.Permissions)
	checked, uploaded := false, false
	for _, step := range job.Steps {
		require.False(t, step.ContinueOnError)
		if step.Uses == "./.github/actions/cache-go" {
			require.Equal(t, "test-policy-oci", step.With["scope"])
			require.Equal(t, "cgo0", step.With["context"])
		} else if step.Uses != "" {
			require.Regexp(t, `@[a-f0-9]{40}$`, step.Uses)
		}
		if strings.HasPrefix(step.Uses, "actions/checkout@") {
			require.Empty(t, step.With["path"])
			require.Equal(t, "${{ inputs.commit || inputs.ref }}", step.With["ref"])
			require.Equal(t, false, step.With["persist-credentials"])
		}
		if step.Run == "mise run test:policy:oci" {
			checked = true
			for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN", "MISE_GITHUB_TOKEN"} {
				value, exists := step.Env[key]
				require.True(t, exists)
				require.Empty(t, value)
				require.Empty(t, job.Env[key])
			}
		}
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") {
			uploaded = true
			require.Equal(t, "always()", step.If)
			require.Equal(t, "var/policy-oci/reports/", step.With["path"])
		}
	}
	require.True(t, checked)
	require.True(t, uploaded)
	raw, err = gos.ReadFile("../../mise.toml")
	require.NoError(t, err)
	_, body, found := strings.Cut(string(raw), `[tasks."test:policy:oci"]`)
	require.True(t, found)
	body, _, _ = strings.Cut(body, "\n[tasks.")
	require.Contains(t, body, "go run ./test/policyci --oci --runtime docker --output var/policy-oci")
}

func TestReleaseImageUsesSharedNormalLayoutRatherThanATestEntrypoint(t *testing.T) {
	source, err := parser.ParseFile(token.NewFileSet(), "build-image.go", nil, 0)
	require.NoError(t, err)
	shared := false
	ast.Inspect(source, func(node ast.Node) bool {
		if expression, ok := node.(*ast.SelectorExpr); ok {
			if pkg, ok := expression.X.(*ast.Ident); ok && pkg.Name == "images" && expression.Sel.Name == "BifroestBuildRequest" {
				shared = true
			}
		}
		return true
	})
	require.True(t, shared, "the release image and local parity check must use the same layout/default-command constructor")
}
