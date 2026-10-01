//go:build darwin

package net

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDarwinNamedPipeModesOwnershipAndCleanup(t *testing.T) {
	pipe, err := NewNamedPipeForUser("ssh-agent", strconv.Itoa(os.Geteuid()), strconv.Itoa(os.Getegid()))
	require.NoError(t, err)

	path := pipe.Path()
	dir := filepath.Dir(path)
	require.Equal(t, "/tmp", filepath.Dir(dir))

	dirInfo, err := os.Lstat(dir)
	require.NoError(t, err)
	require.True(t, dirInfo.IsDir())
	require.Equal(t, os.FileMode(0700), dirInfo.Mode().Perm())
	socketInfo, err := os.Lstat(path)
	require.NoError(t, err)
	require.Equal(t, os.ModeSocket, socketInfo.Mode().Type())
	require.Equal(t, os.FileMode(0600), socketInfo.Mode().Perm())

	for _, info := range []os.FileInfo{dirInfo, socketInfo} {
		stat := info.Sys().(*syscall.Stat_t)
		require.Equal(t, uint32(os.Geteuid()), stat.Uid)
		require.Equal(t, uint32(os.Getegid()), stat.Gid)
	}

	client, err := ConnectToNamedPipe(t.Context(), path)
	require.NoError(t, err)
	server, err := pipe.Accept()
	require.NoError(t, err)
	require.NoError(t, client.Close())
	require.NoError(t, server.Close())
	require.NoError(t, pipe.Close())
	require.NoFileExists(t, path)
	require.NoDirExists(t, dir)
}

func TestDarwinNamedPipeUsesShortSafeFallback(t *testing.T) {
	for _, id := range []string{strings.Repeat("x", 200), "../outside", "bad\x00id"} {
		pipe, err := NewNamedPipeWithId("ssh-agent", id)
		require.NoError(t, err)
		require.Equal(t, "s", filepath.Base(pipe.Path()))
		require.LessOrEqual(t, len(pipe.Path()), maxDarwinUnixSocketPathBytes)
		require.NoError(t, pipe.Close())
	}
}

func TestDarwinNamedPipePathLimits(t *testing.T) {
	dir := "/" + strings.Repeat("d", 84)
	path, err := darwinNamedPipePath(dir, "p", strings.Repeat("i", 10))
	require.NoError(t, err)
	require.Len(t, path, maxDarwinUnixSocketPathBytes)

	path, err = darwinNamedPipePath(dir, "p", strings.Repeat("i", 11))
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, "s"), path)

	_, err = darwinNamedPipePath("/"+strings.Repeat("d", 101), "p", "i")
	require.ErrorContains(t, err, "too long")
}

func TestDarwinConnectRejectsInvalidPath(t *testing.T) {
	_, err := ConnectToNamedPipe(t.Context(), "/"+strings.Repeat("x", maxDarwinUnixSocketPathBytes))
	require.ErrorContains(t, err, "too long")
	_, err = ConnectToNamedPipe(t.Context(), "bad\x00path")
	require.ErrorContains(t, err, "NUL")
}

func TestDarwinNamedPipeCleansUpAfterOwnerFailure(t *testing.T) {
	before, err := filepath.Glob("/tmp/bifroest-*")
	require.NoError(t, err)

	pipe, err := NewNamedPipeForUser("ssh-agent", "bifroest-user-that-does-not-exist", "")
	require.Nil(t, pipe)
	require.Error(t, err)

	after, err := filepath.Glob("/tmp/bifroest-*")
	require.NoError(t, err)
	require.ElementsMatch(t, before, after)
}
