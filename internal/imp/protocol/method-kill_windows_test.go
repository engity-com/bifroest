//go:build windows

package protocol

import (
	"context"
	"errors"
	goos "os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/sys"
)

const killWindowsHelper = "BIFROEST_KILL_WINDOWS_HELPER"

func TestKillWindowsUsesSignalExitCode(t *testing.T) {
	if goos.Getenv(killWindowsHelper) != "" {
		require.NoError(t, goos.WriteFile(goos.Getenv(killWindowsHelper), nil, 0600))
		for {
			time.Sleep(time.Hour)
		}
	}

	for _, signal := range []sys.Signal{sys.SIGTERM, sys.SIGKILL} {
		t.Run(signal.String(), func(t *testing.T) {
			readyFile := filepath.Join(t.TempDir(), "ready")
			executable, err := goos.Executable()
			require.NoError(t, err)
			cmd := exec.Command(executable, "-test.run=^TestKillWindowsUsesSignalExitCode$")
			cmd.Env = append(goos.Environ(), killWindowsHelper+"="+readyFile)
			require.NoError(t, cmd.Start())
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			require.Eventually(t, func() bool {
				_, err := goos.Stat(readyFile)
				return err == nil
			}, 10*time.Second, 50*time.Millisecond)

			candidate, err := process.NewProcess(int32(cmd.Process.Pid))
			require.NoError(t, err)
			createdAt, err := candidate.CreateTime()
			require.NoError(t, err)
			require.NoError(t, (&imp{}).kill(context.Background(), processTarget{
				pid:               cmd.Process.Pid,
				expectedCreatedAt: &createdAt,
				expectedEnv:       killWindowsHelper + "=" + readyFile,
			}, signal))

			err = cmd.Wait()
			var exitErr *exec.ExitError
			require.True(t, errors.As(err, &exitErr))
			require.Equal(t, 128+int(signal), exitErr.ExitCode())
		})
	}
}
