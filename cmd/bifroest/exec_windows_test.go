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

	"github.com/engity-com/bifroest/pkg/sys"
)

const execSignalHelper = "BIFROEST_EXEC_SIGNAL_HELPER"

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
