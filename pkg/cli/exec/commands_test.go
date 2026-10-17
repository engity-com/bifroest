package exec

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/execution"
)

func TestExecCLIForwardsPositionalCommandAndStoresExitCode(t *testing.T) {
	t.Setenv(execution.TargetEnvironmentEnvName, "")
	executable, err := os.Executable()
	require.NoError(t, err)
	app := cli.NewSimpleApplication("test").
		WithErrorHandlerEnabled(false).
		WithFallbackToStdio(false).
		WithCommand(CreateCommands()...).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	for _, test := range []struct {
		name               string
		explicitExecutable bool
	}{
		{"implicit-executable", false},
		{"explicit-executable", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			id := connection.MustNewId()
			args := []string{"exec", "--executionId=" + id.String(), "-x",
				"--exitCodeByConnectionIdPath=" + directory,
				"--env=BIFROEST_EXEC_CLI_HELPER=1", "--env=BIFROEST_EXEC_CLI_EXIT=23",
			}
			if systemRoot := os.Getenv("SystemRoot"); systemRoot != "" {
				args = append(args, "--env=SystemRoot="+systemRoot)
			}
			if testing.CoverMode() != "" {
				args = append(args, "--env=GOCOVERDIR="+t.TempDir())
			}
			if test.explicitExecutable {
				args = append(args, "-p", executable)
			}
			forwarded := []string{"argument with spaces", "--command=target-value", "-eTARGET=argument", "--"}
			args = append(args, "--", executable, "-test.run=^TestExecCLIHelperProcess$", "--")
			args = append(args, forwarded...)
			var stdout, stderr bytes.Buffer
			ctx := cli.ContextWithStdio(t.Context(), nil, &stdout, &stderr)
			require.NoError(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, args...))
			var received []string
			require.NoError(t, json.Unmarshal(stdout.Bytes(), &received))
			require.Equal(t, forwarded, received)
			require.Equal(t, "helper-stderr\n", stderr.String())
			stateDirectory := filepath.Join(directory, execution.StateDirectoryName)
			status, err := os.ReadFile(executionStatePath(stateDirectory, id, ""))
			require.NoError(t, err)
			require.Equal(t, "23", string(status))
			require.NoFileExists(t, executionStatePath(stateDirectory, id, ".pid"))
		})
	}
}

func TestExecCLIRequiresPositionalCommand(t *testing.T) {
	directory := t.TempDir()
	app := cli.NewSimpleApplication("test").
		WithErrorHandlerEnabled(false).
		WithFallbackToStdio(false).
		WithCommand(CreateCommands()...).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	for _, trailing := range [][]string{nil, {"--"}} {
		args := []string{"exec", "--executionId=" + connection.MustNewId().String(), "-x", "--exitCodeByConnectionIdPath=" + directory}
		args = append(args, trailing...)
		err := app.ParseAndExecute(t.Context(), &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, args...)
		require.ErrorContains(t, err, "command")
	}
	files, err := os.ReadDir(directory)
	require.NoError(t, err)
	require.Empty(t, files)
}

// Run the test binary as a child to verify argv, streams and exit-code storage
// through the real exec CLI on Unix and Windows, without a platform shell.
func TestExecCLIHelperProcess(t *testing.T) {
	if os.Getenv("BIFROEST_EXEC_CLI_HELPER") != "1" {
		return
	}
	for index, arg := range os.Args {
		if arg != "--" {
			continue
		}
		if err := json.NewEncoder(os.Stdout).Encode(os.Args[index+1:]); err != nil {
			os.Exit(97)
		}
		if _, err := os.Stderr.WriteString("helper-stderr\n"); err != nil {
			os.Exit(98)
		}
		code, err := strconv.Atoi(os.Getenv("BIFROEST_EXEC_CLI_EXIT"))
		if err != nil {
			os.Exit(99)
		}
		os.Exit(code)
	}
	t.Fatal("missing argument separator in exec CLI helper")
}
