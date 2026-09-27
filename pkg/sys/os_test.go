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
	require.False(t, IsBinaryCompatibleWithHost(OsDarwin, ArchAmd64, OsDarwin, ArchArm64))
	require.False(t, IsBinaryCompatibleWithHost(OsLinux, ArchArm64, OsDarwin, ArchArm64))
}

func TestDarwinBinaryLocations(t *testing.T) {
	require.Equal(t, `/usr/local/bin`, BifroestBinaryDirLocation(OsDarwin))
	require.Equal(t, `/usr/local/bin/bifroest`, BifroestBinaryFileLocation(OsDarwin))
}
