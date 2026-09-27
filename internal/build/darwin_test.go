package build

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/sys"
)

func TestDarwinBuildMatrix(t *testing.T) {
	require.True(t, IsOsAndArchSupported(sys.OsDarwin, sys.ArchArm64))
	require.False(t, IsOsAndArchSupported(sys.OsDarwin, sys.ArchAmd64))
	require.True(t, DoesEditionSupportBinaryFor(sys.EditionExtended, sys.OsDarwin, sys.ArchArm64, sys.OsDarwin, sys.ArchArm64))
	require.False(t, DoesEditionSupportBinaryFor(sys.EditionGeneric, sys.OsDarwin, sys.ArchArm64, sys.OsDarwin, sys.ArchArm64))
	require.False(t, DoesEditionSupportBinaryFor(sys.EditionExtended, sys.OsDarwin, sys.ArchArm64, sys.OsLinux, sys.ArchAmd64))
	require.False(t, (Platform{Os: sys.OsDarwin, Arch: sys.ArchArm64, Edition: sys.EditionExtended}).IsImageSupported())
}

func TestDarwinBuildEnvironment(t *testing.T) {
	env := sys.EnvVars{}
	(Platform{Os: sys.OsDarwin, Arch: sys.ArchArm64, Edition: sys.EditionExtended}).SetToEnv(sys.OsDarwin, sys.ArchArm64, env)

	require.Equal(t, "darwin", env["GOOS"])
	require.Equal(t, "arm64", env["GOARCH"])
	require.Equal(t, "1", env["CGO_ENABLED"])
	require.Equal(t, DefaultMacosDeploymentTarget, env["MACOSX_DEPLOYMENT_TARGET"])
}
