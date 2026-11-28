package crypto

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
)

func TestKeyPreparationCannotBootstrapAndReusesProvisionedFile(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "not-created")
	path := filepath.Join(directory, "key")
	ctx := common.WithProviderBootstrapDisabled(t.Context())
	requirement := &KeyRequirement{Type: KeyTypeEd25519}
	key, err := EnsureKeyFileContext(ctx, path, requirement, nil)
	require.ErrorIs(t, err, common.ErrProviderBootstrapDisabled)
	require.Nil(t, key)
	require.NoDirExists(t, directory)

	provisioned, err := EnsureKeyFile(path, requirement, nil)
	require.NoError(t, err)
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	key, err = EnsureKeyFileContext(ctx, path, requirement, nil)
	require.NoError(t, err)
	require.True(t, provisioned.PublicKey().IsEqualTo(key.PublicKey()))
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
}
