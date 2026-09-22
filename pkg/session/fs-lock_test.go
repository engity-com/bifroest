package session

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFsRepositoryProcessLockIsExclusiveAndRemovedOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repository.lock")
	lock, err := acquireFsRepositoryProcessLock(path, 0600)
	require.NoError(t, err)
	require.FileExists(t, path)

	_, err = acquireFsRepositoryProcessLock(path, 0600)
	require.Error(t, err)
	require.NoError(t, lock.Close())
	require.NoError(t, lock.Close())
	require.NoFileExists(t, path)

	reopened, err := acquireFsRepositoryProcessLock(path, 0600)
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
	require.NoFileExists(t, path)
}
