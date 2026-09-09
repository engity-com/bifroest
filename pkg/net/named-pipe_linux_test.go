//go:build linux

package net

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNamedPipeForUserSetsOwnership(t *testing.T) {
	pipe, err := NewNamedPipeForUser(
		"test",
		strconv.Itoa(os.Geteuid()),
		strconv.Itoa(os.Getegid()),
	)
	require.NoError(t, err)
	defer func() { require.NoError(t, pipe.Close()) }()

	for _, path := range []string{filepath.Dir(pipe.Path()), pipe.Path()} {
		info, err := os.Stat(path)
		require.NoError(t, err)
		stat := info.Sys().(*syscall.Stat_t)
		assert.Equal(t, uint32(os.Geteuid()), stat.Uid)
		assert.Equal(t, uint32(os.Getegid()), stat.Gid)
	}
}

func TestNewNamedPipeCanBeUsedByEnvironmentUsers(t *testing.T) {
	actual, err := NewNamedPipe("agent-test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = actual.Close() })

	path := actual.Path()
	dir := filepath.Dir(path)
	assert.Equal(t, filepath.Clean(os.TempDir()), filepath.Dir(dir))

	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, dirInfo.IsDir())
	assert.Equal(t, os.FileMode(0700), dirInfo.Mode().Perm())

	socketInfo, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.ModeSocket, socketInfo.Mode().Type())
	assert.Equal(t, os.FileMode(0600), socketInfo.Mode().Perm())

	client, err := ConnectToNamedPipe(context.Background(), path)
	require.NoError(t, err)
	server, err := actual.Accept()
	require.NoError(t, err)
	require.NoError(t, client.Close())
	require.NoError(t, server.Close())

	require.NoError(t, actual.Close())
	assert.NoFileExists(t, path)
	assert.NoDirExists(t, dir)
}
