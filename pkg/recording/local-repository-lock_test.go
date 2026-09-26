package recording

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalProcessLockIsExclusiveAndRemovedOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), localLockFileName)
	lock, err := acquireLocalProcessLock(path)
	require.NoError(t, err)
	require.FileExists(t, path)

	_, err = acquireLocalProcessLock(path)
	require.Error(t, err)
	require.NoError(t, lock.Close())
	require.NoError(t, lock.Close())
	require.NoFileExists(t, path)

	reopened, err := acquireLocalProcessLock(path)
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
	require.NoFileExists(t, path)
}
