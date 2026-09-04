//go:build linux

package net

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNamedPipeCanBeUsedByEnvironmentUsers(t *testing.T) {
	actual, err := NewNamedPipe("agent-test")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, actual.Close()) })

	info, err := os.Stat(actual.Path())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0666), info.Mode().Perm())
}
