package build

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/sys"
)

func TestDarwinBuildMatrix(t *testing.T) {
	require.True(t, IsOsAndArchSupported(sys.OsDarwin, sys.ArchArm64))
	require.True(t, IsOsAndArchSupported(sys.OsDarwin, sys.ArchAmd64))
	require.True(t, DoesEditionSupportBinaryFor(sys.EditionGeneric, sys.OsDarwin, sys.ArchArm64, sys.OsDarwin, sys.ArchArm64))
	require.True(t, DoesEditionSupportBinaryFor(sys.EditionGeneric, sys.OsDarwin, sys.ArchAmd64, sys.OsDarwin, sys.ArchAmd64))
	require.False(t, DoesEditionSupportBinaryFor(sys.EditionGeneric, sys.OsDarwin, sys.ArchArm64, sys.OsLinux, sys.ArchAmd64))
	require.False(t, DoesEditionSupportBinaryFor(sys.EditionExtended, sys.OsDarwin, sys.ArchArm64, sys.OsDarwin, sys.ArchArm64))
	require.False(t, DoesEditionSupportBinaryFor(sys.EditionExtended, sys.OsDarwin, sys.ArchAmd64, sys.OsDarwin, sys.ArchAmd64))
	require.False(t, DoesEditionSupportBinaryFor(sys.EditionExtended, sys.OsDarwin, sys.ArchAmd64, sys.OsDarwin, sys.ArchArm64))
	require.False(t, DoesEditionSupportBinaryFor(sys.EditionExtended, sys.OsDarwin, sys.ArchArm64, sys.OsDarwin, sys.ArchAmd64))
	require.False(t, DoesEditionSupportBinaryFor(sys.EditionExtended, sys.OsDarwin, sys.ArchArm64, sys.OsLinux, sys.ArchAmd64))
	require.False(t, (Platform{Os: sys.OsDarwin, Arch: sys.ArchArm64, Edition: sys.EditionExtended}).IsImageSupported())
	require.False(t, (Platform{Os: sys.OsDarwin, Arch: sys.ArchAmd64, Edition: sys.EditionExtended}).IsImageSupported())
}

func TestGenericDarwinBuildEnvironmentDisablesCgo(t *testing.T) {
	for _, arch := range []sys.Arch{sys.ArchAmd64, sys.ArchArm64} {
		t.Run(arch.String(), func(t *testing.T) {
			env := sys.EnvVars{}
			(Platform{Os: sys.OsDarwin, Arch: arch, Edition: sys.EditionGeneric}).SetToEnv(sys.OsDarwin, arch, env)

			require.Equal(t, "darwin", env["GOOS"])
			require.Equal(t, arch.String(), env["GOARCH"])
			require.Equal(t, "0", env["CGO_ENABLED"])
			require.Equal(t, DefaultMacosDeploymentTarget, env["MACOSX_DEPLOYMENT_TARGET"])
			if arch == sys.ArchAmd64 {
				require.Equal(t, "v1", env["GOAMD64"])
			}
		})
	}
}
