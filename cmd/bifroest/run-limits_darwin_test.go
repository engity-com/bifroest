//go:build darwin

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDesiredDarwinOpenFileLimit(t *testing.T) {
	require.Equal(t, uint64(darwinOpenFileLimit), desiredDarwinOpenFileLimit(256, 1<<20))
	require.Equal(t, uint64(4096), desiredDarwinOpenFileLimit(256, 4096))
	require.Equal(t, uint64(1<<20), desiredDarwinOpenFileLimit(1<<20, 1<<20))
}
