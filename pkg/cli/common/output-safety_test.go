package common

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOutputAliasCheckFindsProtectedFilesAcrossDirectoryBatches(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, "protected")
	require.NoError(t, os.Mkdir(protected, 0700))
	for index := range 1025 {
		require.NoError(t, os.WriteFile(filepath.Join(protected, fmt.Sprintf("%04d", index)), []byte("evidence"), 0600))
	}
	alias := filepath.Join(root, "output")
	if err := os.Link(filepath.Join(protected, "1024"), alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	info, err := os.Stat(alias)
	require.NoError(t, err)
	require.ErrorContains(t, EnsureFileDoesNotAliasDirectoryFile(t.Context(), alias, info, protected, "evidence"), "must not replace")
	safe := filepath.Join(root, "safe-output")
	require.NoError(t, os.WriteFile(safe, nil, 0600))
	info, err = os.Stat(safe)
	require.NoError(t, err)
	require.NoError(t, EnsureFileDoesNotAliasDirectoryFile(t.Context(), safe, info, protected, "evidence"))
}

func TestOutputSafetyChecksRespectCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, EnsureStandardOutputSafe(ctx, io.Discard, "", nil, nil), context.Canceled)
	require.ErrorIs(t, EnsureFileDoesNotAliasDirectoryFile(ctx, "unused", nil, "unused", "evidence"), context.Canceled)
}
