package main

import (
	gos "os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBinaryContainerWorkflowPreparesHostNodeBeforeMise(t *testing.T) {
	job := readGoJobsWorkflow(t)["binary-container"]
	require.Equal(t, "${{ matrix.image }}", job.Container.Image)
	require.Equal(t, "${{ fromJSON(inputs.binary_container_matrix) }}", job.Strategy.Matrix)
	prepare := goJobsStepContaining(t, job, "libatomic1:")
	step := job.Steps[prepare]
	require.Equal(t, "bash", step.Shell)
	require.Empty(t, step.If)
	require.False(t, step.ContinueOnError)
	require.Contains(t, step.Run, `host_arch="$(dpkg --print-architecture)"`, "the runtime must match the build host, not the cross-compilation target")
	require.Contains(t, step.Run, `apt-get install --no-install-recommends -y "libatomic1:$host_arch"`)
	mise := -1
	for i, candidate := range job.Steps {
		require.Empty(t, candidate.Env["CGO_ENABLED"], "do not disable native compilation to work around tool setup")
		if strings.HasPrefix(candidate.Uses, "jdx/mise-action@") {
			mise = i
			require.Equal(t, "jdx/mise-action@236a21c3b91f5db6d4e174b348674a0f0caac06d", candidate.Uses)
		}
	}
	require.Greater(t, mise, prepare)
	require.Equal(t, "mise run build:go:binary -- --os=${{ matrix.os }} --arch=${{ matrix.arch }}", job.Steps[goJobsStepContaining(t, job, "mise run build:go:binary")].Run)
}

func TestBinaryContainerHostRuntimeSetupSkipsInstalledPackageAndPropagatesFailure(t *testing.T) {
	bash, err := osexec.LookPath("bash")
	if err != nil {
		t.Skip("Bash is unavailable; structural workflow guards still run")
	}
	job := readGoJobsWorkflow(t)["binary-container"]
	prepare := job.Steps[goJobsStepContaining(t, job, "libatomic1:")].Run
	for _, tt := range []struct {
		name, status, installStatus, expected string
	}{
		{"already-installed", "installed", "0", ""},
		{"missing-host-package", "missing", "0", "update\ninstall --no-install-recommends -y libatomic1:amd64\n"},
		{"failed-install", "missing", "23", "update\ninstall --no-install-recommends -y libatomic1:amd64\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// The matrix targets ARM; the required Node library still belongs to the amd64 host.
			script := `dpkg() { [ "$*" = --print-architecture ] || return 42; printf amd64; }
dpkg-query() {
  [ "$*" = '-W -f=${db:Status-Status} libatomic1:amd64' ] || return 42
  [ "$PACKAGE_STATUS" = installed ] || return 1
  printf installed
}
apt-get() {
  printf '%s\n' "$*"
  if [ "$1" = install ]; then return "$INSTALL_STATUS"; fi
}
` + "PACKAGE_STATUS=" + tt.status + "\nINSTALL_STATUS=" + tt.installStatus + "\n" + prepare
			scriptPath := filepath.Join(t.TempDir(), "container-toolchain.sh")
			require.NoError(t, gos.WriteFile(scriptPath, []byte(script), 0o600))
			command := osexec.CommandContext(t.Context(), bash, "--noprofile", "--norc", "-e", "-o", "pipefail", filepath.ToSlash(scriptPath))
			output, err := command.CombinedOutput()
			if tt.installStatus == "0" {
				require.NoError(t, err, string(output))
			} else {
				require.Error(t, err)
			}
			require.Equal(t, tt.expected, string(output))
		})
	}
}
