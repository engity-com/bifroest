package main

import (
	goexec "os/exec"
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
	prepare := assembly.Steps[goJobsStepContaining(t, assembly, "mise run build:go:prepare-packages")]
	require.Equal(t, "mise run build:go:prepare-packages", prepare.Run)
	require.Empty(t, prepare.If)
	for _, step := range assembly.Steps {
		require.False(t, step.ContinueOnError)
		require.NotContains(t, step.Run, "publish-packages")
		require.NotContains(t, step.Run, "build:go:package")
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") {
			require.Equal(t, "prepared-packages", step.With["name"])
			require.Equal(t, "var/dist", step.With["path"])
			require.Equal(t, "error", step.With["if-no-files-found"])
			require.Equal(t, "steps.prepare.outputs.publish == 'true' || inputs.upload_dist", step.If)
		} else if step.Name == "Lint licenses" {
			require.Equal(t, "inputs.lint_reuse", step.If)
		} else {
			require.Empty(t, step.If, "package preparation is mandatory for every supported source")
		}
		if step.Uses == "./.github/actions/cache-go" {
			require.Empty(t, step.With["build-cache"], "do not add persistent compiler-cache writers")
		}
	}

	gate := jobs["package"]
	finalize := "needs.assemble.outputs.publish == 'true' || inputs.upload_dist"
	require.Equal(t, "Package", gate.Name, "keep the ruleset's existing required check")
	publication := gate.Steps[goJobsStepContaining(t, gate, "mise run build:go:publish-packages")]
	require.Equal(t, "mise run build:go:publish-packages", publication.Run)
	require.Equal(t, finalize, publication.If)
	for _, step := range gate.Steps[1:] {
		switch step.Name {
		case "Checkout code", "Git configure", "Install MISE", "Cache Go", "Install dependencies", "Set reproducible build time":
			require.Equal(t, finalize, step.If, "ordinary PRs need only the final gate, no second toolchain setup")
		case "Download prepared packages":
			require.Equal(t, publication.If, step.If)
			require.Equal(t, map[string]string{"name": "prepared-packages", "path": "var/dist"}, step.With, "consume only this run's prepared artifact")
		case "Package", "Download binaries", "Cache images dependencies":
			t.Fatalf("publication must not rebuild or repackage artifacts: %s", step.Name)
		case "Archive package results":
			require.Equal(t, "inputs.upload_dist", step.If)
			require.Contains(t, step.With["path"], "!var/dist/prepared-packages.json")
			require.Contains(t, step.With["path"], "!var/dist/prepared-images/**")
		}
	}
}

func TestPackageTasksPropagateFailuresWithoutSelectingAnotherPath(t *testing.T) {
	bash, err := goexec.LookPath("bash")
	if err != nil {
		t.Skip("Bash is required to exercise task failure propagation")
	}
	for _, jobAndCommand := range []struct{ job, command string }{{"assemble", "mise run build:go:prepare-packages"}, {"package", "mise run build:go:publish-packages"}} {
		step := readGoJobsWorkflow(t)[jobAndCommand.job].Steps[goJobsStepContaining(t, readGoJobsWorkflow(t)[jobAndCommand.job], jobAndCommand.command)]
		command := goexec.Command(bash, "-e", "-o", "pipefail", "-c", "mise() { return 23; }\n"+step.Run)
		_, err := command.CombinedOutput()
		var exit *goexec.ExitError
		require.ErrorAs(t, err, &exit)
		require.Equal(t, 23, exit.ExitCode(), "build failures must never select the old path or turn green")
	}
}
