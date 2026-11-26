package main

import (
	gos "os"
	goexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPackageAssemblyRunsWithoutWaitingForTestsOrPublicationRights(t *testing.T) {
	jobs := readGoJobsWorkflow(t)
	assembly := jobs["assemble"]
	var needs []string
	require.NoError(t, assembly.Needs.Decode(&needs))
	require.ElementsMatch(t, []string{"browser", "binary-host", "binary-container"}, needs)
	require.Equal(t, map[string]string{"contents": "read", "packages": "read"}, assembly.Permissions)
	require.Empty(t, assembly.If)
	require.False(t, assembly.ContinueOnError)
	prepare := assembly.Steps[goJobsStepContaining(t, assembly, "prepare-packages --")]
	require.Contains(t, prepare.Run, "mise run build:go:prepare-packages")
	require.Contains(t, prepare.Run, "mise exec -- go run ./cmd/build prepare-packages --log.colorMode=always", "retain old-source compatibility")
	require.Equal(t, "steps.mode.outputs.prepared == 'true'", prepare.If)
	for _, step := range assembly.Steps {
		require.False(t, step.ContinueOnError)
		require.NotContains(t, step.Run, "publish-packages")
		require.NotContains(t, step.Run, "build:go:package")
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") {
			require.Equal(t, "prepared-packages", step.With["name"])
			require.Equal(t, "var/dist", step.With["path"])
			require.Equal(t, "error", step.With["if-no-files-found"])
			require.Equal(t, "steps.mode.outputs.prepared == 'true' && (steps.prepare.outputs.publish == 'true' || inputs.upload_dist)", step.If)
		}
		if step.Uses == "./var/ci-workflow/.github/actions/cache-go" {
			require.Empty(t, step.With["build-cache"], "do not add persistent compiler-cache writers")
		}
	}

	gate := jobs["package"]
	finalize := "needs.assemble.outputs.prepared != 'true' || needs.assemble.outputs.publish == 'true' || inputs.upload_dist"
	require.Equal(t, "Package", gate.Name, "keep the ruleset's existing required check")
	publication := gate.Steps[goJobsStepContaining(t, gate, "publish-packages --")]
	require.Contains(t, publication.Run, "mise run build:go:publish-packages")
	require.Contains(t, publication.Run, "mise exec -- go run ./cmd/build publish-packages --log.colorMode=always", "retain old-source compatibility")
	require.Equal(t, "needs.assemble.outputs.prepared == 'true' && (needs.assemble.outputs.publish == 'true' || inputs.upload_dist)", publication.If)
	for _, step := range gate.Steps[1:] {
		switch step.Name {
		case "Checkout code", "Git configure", "Install MISE", "Checkout workflow cache action", "Cache Go", "Install dependencies", "Set reproducible build time":
			require.Equal(t, finalize, step.If, "ordinary PRs need only the final gate, no second toolchain setup")
		case "Download prepared packages":
			require.Equal(t, publication.If, step.If)
			require.Equal(t, map[string]string{"name": "prepared-packages", "path": "var/dist"}, step.With, "consume only this run's prepared artifact")
		case "Package", "Download binaries", "Cache images dependencies":
			require.Equal(t, "needs.assemble.outputs.prepared != 'true'", step.If, "old source refs alone may use the original gated packaging path")
		case "Archive package results":
			require.Equal(t, "inputs.upload_dist", step.If)
			require.Contains(t, step.With["path"], "!var/dist/prepared-packages.json")
			require.Contains(t, step.With["path"], "!var/dist/prepared-images/**")
		}
	}
}

func TestPackageAssemblyDetectsOldSourceRefsWithoutHidingBuildFailures(t *testing.T) {
	bash, err := goexec.LookPath("bash")
	if err != nil {
		t.Skip("Bash is required to exercise source-ref capability detection")
	}
	job := readGoJobsWorkflow(t)["assemble"]
	probe := job.Steps[goJobsStepContaining(t, job, "build-package-transfer.go")]
	for _, modern := range []bool{false, true} {
		directory := t.TempDir()
		if modern {
			require.NoError(t, gos.MkdirAll(filepath.Join(directory, "cmd", "build"), 0755))
			require.NoError(t, gos.WriteFile(filepath.Join(directory, "cmd", "build", "build-package-transfer.go"), nil, 0644))
		}
		outputPath := filepath.Join(directory, "github.output")
		command := goexec.Command(bash, "-e", "-o", "pipefail", "-c", probe.Run)
		command.Dir = directory
		command.Env = append(gos.Environ(), "GITHUB_OUTPUT="+outputPath)
		output, err := command.CombinedOutput()
		require.NoError(t, err, string(output))
		actual, err := gos.ReadFile(outputPath)
		require.NoError(t, err)
		if modern {
			require.Equal(t, "prepared=true\n", string(actual))
		} else {
			require.Equal(t, "prepared=false\n", string(actual))
		}
	}
	for _, jobAndCommand := range []struct{ job, command string }{{"assemble", "prepare-packages --"}, {"package", "publish-packages --"}, {"package", "build:go:package"}} {
		step := readGoJobsWorkflow(t)[jobAndCommand.job].Steps[goJobsStepContaining(t, readGoJobsWorkflow(t)[jobAndCommand.job], jobAndCommand.command)]
		command := goexec.Command(bash, "-e", "-o", "pipefail", "-c", "mise() { return 23; }\n"+step.Run)
		_, err := command.CombinedOutput()
		var exit *goexec.ExitError
		require.ErrorAs(t, err, &exit)
		require.Equal(t, 23, exit.ExitCode(), "build failures must never select the old path or turn green")
	}
}
