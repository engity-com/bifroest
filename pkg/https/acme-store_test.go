package https

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStoredACMEAccountPemRejectsIgnoredOrNestedMaterial(t *testing.T) {
	store, err := openACMEStore(filepath.Join(t.TempDir(), "acme"), "https://ca.example.org/directory")
	require.NoError(t, err)
	defer store.close()
	_, err = store.accountKey(context.Background())
	require.NoError(t, err)
	raw, err := store.read("account.pem")
	require.NoError(t, err)
	for _, corrupted := range [][]byte{
		append([]byte("ignored prefix\n"), raw...),
		append(bytes.Clone(raw), []byte("ignored suffix")...),
		append([]byte("-----BEGIN PRIVATE KEY-----\ninvalid base64\n"), raw...),
		append(bytes.Clone(raw), raw...),
	} {
		_, err := parseACMEAccountKey(corrupted)
		require.Error(t, err)
	}
}
