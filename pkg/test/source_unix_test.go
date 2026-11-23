//go:build unix

package test

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSourceSymlinkCannotEscapeConfigurationRoot(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	require.NoError(t, os.WriteFile(outside, []byte(testConfiguration), 0600))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "configuration.yaml")))
	path := filepath.Join(dir, "suite_bftest.lua")
	source := strings.Replace(suiteSource(`t:IsEqual(true,true)`), `name="offline",`, `name="offline",configuration=file_content("configuration.yaml"),`, 1)
	require.NoError(t, os.WriteFile(path, []byte(source), 0600))
	require.Equal(t, 2, RunFile(t.Context(), path, "").ExitCode())
}

func TestSourceFIFOIsRejectedWithoutWaitingForWriter(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "suite_bftest.lua")
	require.NoError(t, syscall.Mkfifo(fifo, 0600))
	require.Equal(t, 2, RunFile(t.Context(), fifo, "").ExitCode())
	require.NoError(t, os.Remove(fifo))
	source := strings.Replace(suiteSource(`t:IsEqual(true,true)`), `name="offline",`, `name="offline",configuration=file_content("configuration.yaml"),`, 1)
	require.NoError(t, os.WriteFile(fifo, []byte(source), 0600))
	require.NoError(t, syscall.Mkfifo(filepath.Join(dir, "configuration.yaml"), 0600))
	require.Equal(t, 2, RunFile(t.Context(), fifo, "").ExitCode())
}

func TestDiscoveryFollowsSymlinksAndTerminatesCycles(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	a := writeInput(t, filepath.Join(root, "a_bftest.lua"), inlineSuite("alpha", `t:IsEqual(true,true)`))
	b := writeInput(t, filepath.Join(outside, "b_bftest.lua"), strings.Replace(namedSuite("beta", `t:IsEqual("physical directory",file_content("message.txt"))`), `name="beta",`, `name="beta",configuration=file_content("configuration.yaml"),`, 1))
	writeInput(t, filepath.Join(outside, "configuration.yaml"), testConfiguration)
	writeInput(t, filepath.Join(outside, "message.txt"), "physical directory")
	writeInput(t, filepath.Join(root, "message.txt"), "wrong logical directory")
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "external")))
	require.NoError(t, os.Symlink(root, filepath.Join(outside, "cycle")))
	require.NoError(t, os.Symlink(b, filepath.Join(root, "alias_bftest.lua")))
	require.NoError(t, os.Link(a, filepath.Join(root, "hardlink_bftest.lua")))
	report := RunPaths(t.Context(), []string{root, b}, Options{})
	require.Zero(t, report.ExitCode(), "%+v", report)
	require.Len(t, report.Results, 2)
	require.Empty(t, report.Warnings)
}

func TestFileContentAllowsInternalLinksButNotExternalLinks(t *testing.T) {
	dir := t.TempDir()
	writeInput(t, filepath.Join(dir, "nested", "message.txt"), "inside")
	outside := writeInput(t, filepath.Join(t.TempDir(), "message.txt"), "outside")
	require.NoError(t, os.Symlink(filepath.Join("nested", "message.txt"), filepath.Join(dir, "inside.txt")))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "outside.txt")))
	contents, err := newFileContents(dir)
	require.NoError(t, err)
	defer contents.Close()
	value, err := contents.read("inside.txt")
	require.NoError(t, err)
	require.Equal(t, "inside", value)
	_, err = contents.read("outside.txt")
	require.Error(t, err)
	require.NoError(t, os.Symlink(filepath.Dir(outside), filepath.Join(dir, "outside-directory")))
	_, err = contents.read("outside-directory/message.txt")
	require.Error(t, err)
	require.NoError(t, os.Symlink(filepath.Join(dir, "nested", "message.txt"), filepath.Join(dir, "absolute-inside.txt")))
	_, err = contents.read("absolute-inside.txt")
	require.Error(t, err)
}

func TestDiscoveryDirectoryDepthBoundIsAnError(t *testing.T) {
	dir := t.TempDir()
	deep := dir
	for range 257 {
		deep = filepath.Join(deep, "d")
	}
	require.NoError(t, os.MkdirAll(deep, 0700))
	report := RunPaths(t.Context(), []string{dir}, Options{})
	require.Equal(t, 2, report.ExitCode())
	require.Len(t, report.Results, 1)
	require.Equal(t, "suite directory depth limit exceeded", report.Results[0].Message)
}
