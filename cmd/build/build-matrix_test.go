package main

import (
	"encoding/json"
	gos "os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/sys"
)

func TestBuildMatricesAssignEveryBinaryPlatformToExactlyOneJob(t *testing.T) {
	build := newBuild(&base{})
	matrices, err := build.buildMatrices()
	require.NoError(t, err)
	require.Equal(t, []buildTestMatrixEntry{{Os: "linux", Runner: "ubuntu-latest"}, {Os: "windows", Runner: "windows-latest"}}, matrices.Tests.Include)
	require.Len(t, matrices.Host.Include, 8)
	require.Len(t, matrices.Container.Include, 5)

	assigned := make(map[string]bool)
	for _, entry := range matrices.Host.Include {
		require.Empty(t, entry.Image)
		require.Equal(t, "generic", entry.Edition)
		require.False(t, assigned[entry.Os+"/"+entry.Arch+"/"+entry.Edition])
		assigned[entry.Os+"/"+entry.Arch+"/"+entry.Edition] = true
	}
	for _, entry := range matrices.Container.Include {
		require.Equal(t, "linux", entry.Os)
		require.Equal(t, "extended", entry.Edition)
		require.Equal(t, "ubuntu-latest", entry.Runner)
		require.Equal(t, binaryLinuxExtendedImage, entry.Image)
		require.False(t, assigned[entry.Os+"/"+entry.Arch+"/"+entry.Edition])
		assigned[entry.Os+"/"+entry.Arch+"/"+entry.Edition] = true
	}
	for platform := range build.platforms(false, sys.OsLinux, sys.ArchAmd64) {
		require.True(t, assigned[platform.String()], platform.String())
	}
	require.True(t, assigned["linux/armv6/generic"])
	require.True(t, assigned["linux/riscv64/generic"])
	require.True(t, assigned["linux/armv6/extended"])
	require.False(t, assigned["linux/riscv64/extended"])
}

func TestEvaluateEnvironmentEmitsMatrices(t *testing.T) {
	b := newBase()
	b.rawCommit = "revision"
	b.rawRef = "main"
	b.build.rawStages = buildStages{buildStageBinary}
	b.optionsOutputFilename = filepath.Join(t.TempDir(), "outputs")
	require.NoError(t, b.build.evaluateEnvironment(t.Context()))
	raw, err := gos.ReadFile(b.optionsOutputFilename)
	require.NoError(t, err)
	for _, name := range []string{"test-matrix", "binary-host-matrix", "binary-container-matrix"} {
		var matrix map[string][]map[string]string
		found := false
		for _, line := range strings.Split(string(raw), "\n") {
			if value, ok := strings.CutPrefix(line, name+"="); ok {
				require.NoError(t, json.Unmarshal([]byte(value), &matrix))
				require.NotEmpty(t, matrix["include"])
				found = true
			}
		}
		require.True(t, found, name)
	}
}
