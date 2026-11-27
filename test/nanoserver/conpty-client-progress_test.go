package nanoserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestConPTYClientProgressProbeKeepsIndependentNativeCasesAndFailures(t *testing.T) {
	raw, err := os.ReadFile("conpty-client-progress_windows_test.go")
	require.NoError(t, err)
	source := string(raw)
	require.Contains(t, source, "[]bool{false, true, true, false, false, true, true, false}")
	require.Contains(t, source, `"--isolation=process", "--user", "ContainerUser"`)
	require.Contains(t, source, `"-test.timeout=90s"`)
	require.Contains(t, source, `t.Errorf("original ConPTY smoke test failed: %v", err)`)
	require.NotContains(t, source, "allow-warnings")
	require.NotContains(t, source, "until")
	require.NotContains(t, source, "continue-on-error")
	for _, name := range []string{
		"TestLocalConPTYRelayRoundTrip",
		"TestLocalConPTYClientProgressEventsAreIndependentOfConsoleOutput",
		"TestLocalConPTYProcessSnapshotObservesWithoutWaiting",
		"TestLocalNanoServerDLLExports",
		"TestLocalConPTYOutputReadKeepsEmptyMessagesDistinctFromEOF",
		"TestLocalConPTYOutputPipeKeepsEmptyWritesAndBinaryOutput",
	} {
		require.Contains(t, source, `"`+name+`"`)
	}
	raw, err = os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "windows-conpty-client-progress.yml"))
	require.NoError(t, err)
	var workflow struct {
		Jobs map[string]struct {
			RunsOn          string `yaml:"runs-on"`
			ContinueOnError any    `yaml:"continue-on-error"`
			Strategy        struct {
				FailFast bool `yaml:"fail-fast"`
				Matrix   struct {
					Windows []string `yaml:"windows"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
			Steps []struct {
				Run             string
				If              string
				Uses            string
				ContinueOnError any               `yaml:"continue-on-error"`
				With            map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &workflow))
	require.Len(t, workflow.Jobs, 1)
	job := workflow.Jobs["probe"]
	require.Equal(t, "windows-${{ matrix.windows }}", job.RunsOn)
	require.Equal(t, []string{"2022", "2025"}, job.Strategy.Matrix.Windows)
	require.False(t, job.Strategy.FailFast)
	require.Nil(t, job.ContinueOnError)
	probes, uploads := 0, 0
	for _, step := range job.Steps {
		require.Nil(t, step.ContinueOnError)
		if step.Run == "mise run diag:windows:conpty-client" {
			probes++
			require.Empty(t, step.If)
		}
		if step.Uses == "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9" {
			uploads++
			require.Equal(t, "always()", step.If)
			require.Equal(t, "error", step.With["if-no-files-found"])
		}
	}
	require.Equal(t, 1, probes)
	require.Equal(t, 1, uploads)
}
