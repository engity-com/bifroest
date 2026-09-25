//go:build linux

package net

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	actual, err := NewNamedPipe("ssh-agent")
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

func TestNewNamedPipeWithLongTempDir(t *testing.T) {
	root := t.TempDir()
	if len(root) >= 80 {
		t.Skip("test temporary directory is already too long for a Linux socket")
	}
	long := filepath.Join(root, strings.Repeat("x", 80-len(root)-1))
	require.NoError(t, os.Mkdir(long, 0700))
	t.Setenv("TMPDIR", long)

	pipe, err := NewNamedPipeForUser("ssh-agent", strconv.Itoa(os.Geteuid()), strconv.Itoa(os.Getegid()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = pipe.Close() })
	dir := filepath.Dir(pipe.Path())
	require.Equal(t, long, filepath.Dir(dir))
	require.LessOrEqual(t, len(pipe.Path()), 107)
	require.Equal(t, "s", filepath.Base(pipe.Path()))
	for _, path := range []string{dir, pipe.Path()} {
		info, err := os.Stat(path)
		require.NoError(t, err)
		stat := info.Sys().(*syscall.Stat_t)
		require.Equal(t, uint32(os.Geteuid()), stat.Uid)
		require.Equal(t, uint32(os.Getegid()), stat.Gid)
	}
	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0700), dirInfo.Mode().Perm())
	socketInfo, err := os.Stat(pipe.Path())
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), socketInfo.Mode().Perm())
	client, err := ConnectToNamedPipe(t.Context(), pipe.Path())
	require.NoError(t, err)
	server, err := pipe.Accept()
	require.NoError(t, err)
	require.NoError(t, client.Close())
	require.NoError(t, server.Close())
	require.NoError(t, pipe.Close())
	require.NoDirExists(t, dir)
}

func TestNewNamedPipeRejectsUnusableTempDir(t *testing.T) {
	root := t.TempDir()
	long := filepath.Join(root, strings.Repeat("x", 110))
	require.NoError(t, os.Mkdir(long, 0700))
	t.Setenv("TMPDIR", long)

	pipe, err := NewNamedPipe("ssh-agent")
	require.Nil(t, pipe)
	require.ErrorContains(t, err, "too long")
	entries, err := os.ReadDir(long)
	require.NoError(t, err)
	require.Empty(t, entries)
}
