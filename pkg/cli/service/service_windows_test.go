//go:build windows

package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWindowsServiceInstallerPinsExplicitModeAndRegisteredName(t *testing.T) {
	require.Equal(t, []string{"run", `--configuration=C:\ProgramData\Bifroest\configuration.yaml`, "--windowsService", "--serviceName=owned-custom-name"}, windowsServiceArguments(`C:\ProgramData\Bifroest\configuration.yaml`, "owned-custom-name"))
}
