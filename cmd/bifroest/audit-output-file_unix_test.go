//go:build unix

package main

import (
	goos "os"
	"testing"

	"github.com/stretchr/testify/require"
)

func requireAuditOutputPrivate(t *testing.T, _ string, info goos.FileInfo) {
	t.Helper()
	require.Equal(t, goos.FileMode(0600), info.Mode().Perm())
}
