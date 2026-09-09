//go:build windows

package main

import (
	"errors"
	goos "os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/execution"
	"github.com/engity-com/bifroest/pkg/sys"
)

const execSignalHelper = "BIFROEST_EXEC_SIGNAL_HELPER"

func TestDoExecStoresResultForImmediatelyExitingProcess(t *testing.T) {
	directory := t.TempDir()
	command := goos.Getenv("ComSpec")
	require.NotEmpty(t, command)

	for range 10 {
		executionId := connection.MustNewId()
		opts := execOpts{
			storeExitCodeForConnectionId: true,
			exitCodeByConnectionIdPath:   directory,
			executionId:                  executionId,
			workingDirectory:             directory,
			environment:                  map[string]string{},
			path:                         command,
			argv:                         []string{command, "/D", "/C", "exit 37"},
		}

		require.NoError(t, doExec(&opts))
		stateDirectory := filepath.Join(directory, execution.StateDirectoryName)
		content, err := goos.ReadFile(executionStatePath(stateDirectory, executionId, ""))
		require.NoError(t, err)
		require.Equal(t, "37", string(content))
		require.NoFileExists(t, executionStatePath(stateDirectory, executionId, ".pid"))
	}

	matches, err := filepath.Glob(filepath.Join(directory, execution.StateDirectoryName, ".bifroest-execution-*"))
	require.NoError(t, err)
	require.Empty(t, matches)
}

func TestSignalExecCmdTerminatesProcessWithFailure(t *testing.T) {
	if goos.Getenv(execSignalHelper) != "" {
		require.NoError(t, goos.WriteFile(goos.Getenv(execSignalHelper), nil, 0600))
		for {
			time.Sleep(time.Hour)
		}
	}

	for _, signal := range []sys.Signal{sys.SIGTERM, sys.SIGKILL} {
		t.Run(signal.String(), func(t *testing.T) {
			readyFile := filepath.Join(t.TempDir(), "ready")
			executable, err := goos.Executable()
			require.NoError(t, err)
			cmd := exec.Command(executable, "-test.run=^TestSignalExecCmdTerminatesProcessWithFailure$")
			cmd.Env = append(goos.Environ(), execSignalHelper+"="+readyFile)
			require.NoError(t, cmd.Start())
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			require.Eventually(t, func() bool {
				_, err := goos.Stat(readyFile)
				return err == nil
			}, 10*time.Second, 50*time.Millisecond)

			require.NoError(t, signalExecCmd(cmd, signal))
			err = cmd.Wait()
			var exitErr *exec.ExitError
			require.True(t, errors.As(err, &exitErr))
			require.NotZero(t, execExitCode(exitErr))
		})
	}
}

func TestResolveExecPathUsesTargetPathCaseInsensitively(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "target-path-command.EXE")
	require.NoError(t, goos.WriteFile(executable, nil, 0600))

	actual, err := resolveExecPath("target-path-command", "", map[string]string{
		"Path":    directory,
		"PathExt": ".EXE",
	})

	require.NoError(t, err)
	require.Equal(t, executable, actual)
}

func TestSetExecEnvironmentCanonicalizesCaseAliases(t *testing.T) {
	environment := map[string]string{
		"bifroest_connection_id": "attacker",
		"BiFrOeSt_CoNnEcTiOn_Id": "also-attacker",
		"UNCHANGED":              "value",
	}

	setExecEnvironment(environment, connection.EnvName, "trusted")

	require.Equal(t, map[string]string{
		connection.EnvName: "trusted",
		"UNCHANGED":        "value",
	}, environment)
}

func TestResolveExecPathCanonicalizesDuplicatePathVariables(t *testing.T) {
	directory := t.TempDir()
	shadowDirectory := t.TempDir()
	executable := filepath.Join(directory, "target-path-command.EXE")
	require.NoError(t, goos.WriteFile(executable, nil, 0600))
	environment := map[string]string{
		"PATH":    directory,
		"Path":    shadowDirectory,
		"PATHEXT": ".EXE",
		"PathExt": ".CMD",
	}

	actual, err := resolveExecPath("target-path-command", "", environment)

	require.NoError(t, err)
	require.Equal(t, executable, actual)
	require.Equal(t, directory, environment["PATH"])
	require.Equal(t, ".EXE", environment["PATHEXT"])
	require.NotContains(t, environment, "Path")
	require.NotContains(t, environment, "PathExt")
}

func TestResolveExecPathPrefersPathExtOverExtensionlessFile(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, goos.WriteFile(filepath.Join(directory, "target-path-command"), nil, 0600))
	executable := filepath.Join(directory, "target-path-command.EXE")
	require.NoError(t, goos.WriteFile(executable, nil, 0600))

	actual, err := resolveExecPath("target-path-command", "", map[string]string{"PATH": directory, "PATHEXT": ".EXE"})

	require.NoError(t, err)
	require.Equal(t, executable, actual)
}

func TestResolveExecPathAppendsNormalizedPathExtToDottedName(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "target-path-command.v1.EXE")
	require.NoError(t, goos.WriteFile(executable, nil, 0600))

	actual, err := resolveExecPath("target-path-command.v1", "", map[string]string{"PATH": directory, "PATHEXT": "EXE"})

	require.NoError(t, err)
	require.Equal(t, executable, actual)
}
