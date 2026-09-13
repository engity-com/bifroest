//go:build windows

package sys

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWindowsExtendedPathPreservesDeviceAndUNCPaths(t *testing.T) {
	for _, test := range []struct {
		name     string
		path     string
		expected string
	}{
		{"extended drive", `\\?\C:\archive`, `\\?\C:\archive`},
		{"extended UNC", `\\?\UNC\server\share\archive`, `\\?\UNC\server\share\archive`},
		{"device", `\\.\PhysicalDrive0`, `\\.\PhysicalDrive0`},
		{"UNC", `\\server\share\archive`, `\\?\UNC\server\share\archive`},
		{"drive root", `C:\`, `\\?\C:\`},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual, err := WindowsExtendedPath(test.path)
			require.NoError(t, err)
			require.Equal(t, test.expected, actual)
		})
	}
}

func TestWindowsExtendedPathMakesRelativePathAbsolute(t *testing.T) {
	absolute, err := filepath.Abs(`archive\journal`)
	require.NoError(t, err)

	actual, err := WindowsExtendedPath(`archive\journal`)
	require.NoError(t, err)
	require.Equal(t, `\\?\`+absolute, actual)
}
