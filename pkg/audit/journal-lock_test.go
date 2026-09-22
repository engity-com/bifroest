package audit

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJournalProcessLockIsExclusiveAndRemovedOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), journalLockFileName)
	lock, err := acquireJournalProcessLock(path, journalFileMode)
	require.NoError(t, err)
	require.FileExists(t, path)

	_, err = acquireJournalProcessLock(path, journalFileMode)
	require.Error(t, err)
	require.NoError(t, lock.Close())
	require.NoError(t, lock.Close())
	require.NoFileExists(t, path)

	reopened, err := acquireJournalProcessLock(path, journalFileMode)
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
	require.NoFileExists(t, path)
}
