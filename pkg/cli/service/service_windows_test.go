//go:build windows

package service

import (
	"testing"

	"github.com/stretchr/testify/require"

	cliCommon "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestWindowsServiceInstallerPinsExplicitModeAndRegisteredName(t *testing.T) {
	require.Equal(t, []string{"run", `--configuration=C:\ProgramData\Bifroest\configuration.yaml`, "--internal.windowsService", "--serviceName=owned-custom-name"}, windowsServiceArguments(`C:\ProgramData\Bifroest\configuration.yaml`, "owned-custom-name"))
}

func TestWindowsServiceInstallerPersistsExplicitConfigurationWatch(t *testing.T) {
	for _, mode := range []configuration.WatchMode{configuration.WatchModePreserve, configuration.WatchModeReconnect, configuration.WatchModeReuse} {
		args := windowsServiceArguments(`C:\config.yaml`, "bifroest", cliCommon.ServiceRunOptions{Watch: mode})
		require.Contains(t, args, "--watch="+mode.String())
	}
	require.Equal(t, windowsServiceArguments(`C:\config.yaml`, "bifroest"), windowsServiceArguments(`C:\config.yaml`, "bifroest", cliCommon.ServiceRunOptions{Watch: configuration.WatchModeOff}))
}
