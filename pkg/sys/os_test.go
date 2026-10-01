package sys

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOsDarwin(t *testing.T) {
	var actual Os
	require.NoError(t, actual.Set("darwin"))
	require.Equal(t, OsDarwin, actual)
	require.Equal(t, "darwin", actual.String())
	require.True(t, actual.IsUnix())
	require.Equal(t, "bifroest", actual.AppendExtToFilename("bifroest"))
	require.Contains(t, AllOsVariants(), OsDarwin)
}

func TestDarwinBinaryCompatibility(t *testing.T) {
	require.True(t, IsBinaryCompatibleWithHost(OsDarwin, ArchArm64, OsDarwin, ArchArm64))
	require.True(t, IsBinaryCompatibleWithHost(OsDarwin, ArchAmd64, OsDarwin, ArchAmd64))
	require.False(t, IsBinaryCompatibleWithHost(OsDarwin, ArchAmd64, OsDarwin, ArchArm64))
	require.False(t, IsBinaryCompatibleWithHost(OsDarwin, ArchArm64, OsDarwin, ArchAmd64))
	require.False(t, IsBinaryCompatibleWithHost(OsLinux, ArchArm64, OsDarwin, ArchArm64))
}

func TestBifroestBinaryLocations(t *testing.T) {
	tests := []struct {
		os   Os
		dir  string
		file string
	}{
		{OsLinux, `/usr/bin`, `/usr/bin/bifroest`},
		{OsWindows, `C:\Program Files\Engity\Bifroest`, `C:\Program Files\Engity\Bifroest\bifroest.exe`},
		{OsDarwin, `/usr/local/bin`, `/usr/local/bin/bifroest`},
	}
	for _, test := range tests {
		t.Run(test.os.String(), func(t *testing.T) {
			require.Equal(t, test.dir, BifroestBinaryDirLocation(test.os))
			require.Equal(t, test.file, BifroestBinaryFileLocation(test.os))
		})
	}
}

func TestBifroestOciBinaryLocationsExcludeDarwin(t *testing.T) {
	require.Equal(t, BifroestBinaryDirLocationUnix, BifroestOciBinaryDirLocation(OsLinux))
	require.Equal(t, BifroestBinaryFileLocationUnix, BifroestOciBinaryFileLocation(OsLinux))
	require.Equal(t, BifroestBinaryDirLocationWindows, BifroestOciBinaryDirLocation(OsWindows))
	require.Equal(t, BifroestBinaryFileLocationWindows, BifroestOciBinaryFileLocation(OsWindows))
	require.Empty(t, BifroestOciBinaryDirLocation(OsDarwin))
	require.Empty(t, BifroestOciBinaryFileLocation(OsDarwin))
}
