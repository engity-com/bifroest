package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadAuditPrivateKeyRejectsNonRegularAndOversizedFiles(t *testing.T) {
	root := t.TempDir()
	_, err := LoadAuditPrivateKey(root)
	require.ErrorContains(t, err, "not a regular file")
	path := filepath.Join(root, "oversized-key")
	file, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, file.Truncate(maxAuditPrivateKeySize+1))
	require.NoError(t, file.Close())
	_, err = LoadAuditPrivateKey(path)
	require.ErrorContains(t, err, "exceeds")
}
