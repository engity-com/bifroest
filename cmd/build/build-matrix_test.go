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
	require.Equal(t, []buildTestMatrixEntry{
		{Os: "windows", Arch: "amd64", Runner: "windows-latest"},
		{Os: "darwin", Arch: "amd64", Runner: "macos-15-intel"},
		{Os: "darwin", Arch: "arm64", Runner: "macos-15"},
	}, matrices.TestHost.Include)
	require.Equal(t, []buildTestMatrixEntry{{Os: "linux", Arch: "amd64", Runner: "ubuntu-latest", Image: binaryLinuxAmd64Image}}, matrices.TestContainer.Include)
	require.Len(t, matrices.Host.Include, 10)
	require.Len(t, matrices.Container.Include, 4)

	assigned := make(map[string]bool)
	for _, entry := range matrices.Host.Include {
		require.Empty(t, entry.Image)
		if entry.Os == "darwin" {
			require.Equal(t, "extended", entry.Edition)
		} else {
			require.Equal(t, "generic", entry.Edition)
		}
		require.False(t, assigned[entry.Os+"/"+entry.Arch+"/"+entry.Edition])
		assigned[entry.Os+"/"+entry.Arch+"/"+entry.Edition] = true
	}
	for _, entry := range matrices.Container.Include {
		require.Equal(t, "linux", entry.Os)
		require.Equal(t, "extended", entry.Edition)
		require.Equal(t, "ubuntu-latest", entry.Runner)
		var arch sys.Arch
		require.NoError(t, arch.Set(entry.Arch))
		require.Equal(t, binaryLinuxExtendedImages[arch], entry.Image)
		require.Contains(t, entry.Image, ":debian12-"+entry.Arch+"@sha256:")
		require.False(t, assigned[entry.Os+"/"+entry.Arch+"/"+entry.Edition])
		assigned[entry.Os+"/"+entry.Arch+"/"+entry.Edition] = true
	}
	for platform := range build.distributablePlatforms(false) {
		require.True(t, assigned[platform.String()], platform.String())
	}
	require.True(t, assigned["darwin/amd64/extended"])
	require.True(t, assigned["darwin/arm64/extended"])
	require.True(t, assigned["linux/armv6/generic"])
	require.True(t, assigned["linux/riscv64/generic"])
	require.False(t, assigned["linux/armv6/extended"])
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
	for _, name := range []string{"test-host-matrix", "test-container-matrix", "binary-host-matrix", "binary-container-matrix"} {
		var matrix map[string][]map[string]any
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
