package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteBuildEpoch(t *testing.T) {
	output := filepath.Join(t.TempDir(), "github.env")
	t.Setenv("GITHUB_ENV", output)
	require.NoError(t, newBase().writeBuildEpoch(t.Context()))
	data, err := os.ReadFile(output)
	require.NoError(t, err)
	timestamp := strings.TrimSuffix(strings.TrimPrefix(string(data), "SOURCE_DATE_EPOCH="), "\n")
	_, err = strconv.ParseUint(timestamp, 10, 64)
	require.NoError(t, err)
	first := append([]byte(nil), data...)
	require.NoError(t, newBase().writeBuildEpoch(t.Context()))
	data, err = os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, append(first, first...), data)
}

func TestWriteBuildEpochRequiresOutputFile(t *testing.T) {
	t.Setenv("GITHUB_ENV", "")
	require.ErrorContains(t, newBase().writeBuildEpoch(t.Context()), "GITHUB_ENV is required")
}
