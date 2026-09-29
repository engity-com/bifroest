package main

import (
	"encoding/binary"
	"os"
	goexec "os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tc-hib/winres"
	winversion "github.com/tc-hib/winres/version"
)

func TestWindowsBinaryResources(t *testing.T) {
	require.GreaterOrEqual(t, len(windowsIcon), 6)
	require.Positive(t, binary.LittleEndian.Uint16(windowsIcon[4:6]))
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			root := t.TempDir()
			mainFile := filepath.Join(root, "main.go")
			require.NoError(t, os.WriteFile(mainFile, []byte("package main\nfunc main() {}\n"), 0600))
			binaryFile := filepath.Join(root, "bifroest.exe")
			cmd := goexec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", binaryFile, mainFile)
			cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+arch, "CGO_ENABLED=0", "GOWORK=off")
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "%s", output)

			var v version
			require.NoError(t, v.Set("v1.2.3"))
			artifact := &buildArtifact{filepath: binaryFile, buildContext: &buildContext{
				version: v, time: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
				vendor: "Engity GmbH", revision: "abc123",
			}}
			require.NoError(t, (&buildBinary{}).addWindowsResources(artifact))
			if runtime.GOOS == "windows" && arch == runtime.GOARCH {
				output, err := goexec.Command(binaryFile).CombinedOutput()
				require.NoError(t, err, "%s", output)
			}
			f, err := os.Open(binaryFile)
			require.NoError(t, err)
			defer f.Close()
			resources, err := winres.LoadFromEXE(f)
			require.NoError(t, err)
			icon, err := resources.GetIcon(winres.ID(1))
			require.NoError(t, err)
			require.NotNil(t, icon)
			versions := 0
			resources.WalkType(winres.RT_VERSION, func(_ winres.Identifier, _ uint16, data []byte) bool {
				versions++
				info, err := winversion.FromBytes(data)
				require.NoError(t, err)
				require.Equal(t, [4]uint16{1, 2, 3, 0}, info.FileVersion)
				require.Equal(t, [4]uint16{1, 2, 3, 0}, info.ProductVersion)
				strings := info.Table().GetMainTranslation()
				require.Equal(t, "v1.2.3", strings[winversion.FileVersion])
				require.Equal(t, "Engity GmbH", strings[winversion.CompanyName])
				require.Equal(t, "Bifr\u00f6st", strings[winversion.ProductName])
				return true
			})
			require.Equal(t, 1, versions)
		})
	}
}
