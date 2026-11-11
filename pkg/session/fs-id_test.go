package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/engity-com/bifroest/pkg/uuidtext"
	"github.com/stretchr/testify/require"
)

func TestFsSessionMetadataBindsBinaryUUIDWithoutRelyingOnFilesystemCase(t *testing.T) {
	conf := newFsRepositoryTestConfiguration(t)
	repo, err := NewFsRepository(t.Context(), conf)
	require.NoError(t, err)
	defer repo.Close()
	created, err := repo.Create(t.Context(), "test", fsRepositoryTestRemote{}, nil)
	require.NoError(t, err)
	id := created.Id()
	path := filepath.Join(conf.Storage, "test", id.String())
	metadataPath := filepath.Join(path, FsFileSession)
	original, err := os.ReadFile(metadataPath)
	require.NoError(t, err)
	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(original, &body))
	require.Equal(t, `"`+id.String()+`"`, string(body["id"]))
	// Simulate an alias resolving to another UUID's metadata even on a host
	// whose filesystem is case-sensitive. Never weaken a lookup into that data.
	other := MustNewId()
	otherPath := filepath.Join(conf.Storage, "test", other.String())
	require.NoError(t, os.Rename(path, otherPath))
	cleanup := true
	found, err := repo.FindBy(t.Context(), "test", other, &FindOpts{AutoCleanUpAllowed: &cleanup})
	require.ErrorContains(t, err, "binary UUID")
	require.Nil(t, found)
	require.NotErrorIs(t, err, ErrCorruptSession)
	require.DirExists(t, otherPath)
	after, err := os.ReadFile(filepath.Join(otherPath, FsFileSession))
	require.NoError(t, err)
	require.Equal(t, original, after)
	require.NoError(t, os.Rename(otherPath, path))
	// Historical canonical UUID directories and their original metadata remain
	// readable without an automatic file/schema rewrite.
	delete(body, "id")
	legacy, err := json.Marshal(body)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(metadataPath, legacy, 0600))
	legacyPath := filepath.Join(conf.Storage, "test", uuidtext.Classic(id))
	require.NoError(t, os.Rename(path, legacyPath))
	found, err = repo.FindBy(t.Context(), "test", id, nil)
	require.NoError(t, err)
	require.Equal(t, id, found.Id())
	after, err = os.ReadFile(filepath.Join(legacyPath, FsFileSession))
	require.NoError(t, err)
	require.Equal(t, legacy, after)
}

func TestLegacyBase58SessionBindingRequiresActualExactDirectoryEntry(t *testing.T) {
	root := t.TempDir()
	var id, other Id
	require.NoError(t, id.UnmarshalText([]byte("7Xng23oeg4L1zHaZfeX6wB")))
	require.NoError(t, other.UnmarshalText([]byte("7xng23oeg4L1zHaZfeX6wB")))
	require.NotEqual(t, id, other)
	require.NoError(t, os.Mkdir(filepath.Join(root, id.String()), 0700))
	require.NoError(t, validateFsStoredIdentity(t.Context(), id, filepath.Join(root, id.String(), FsFileSession), nil))
	require.Error(t, validateFsStoredIdentity(t.Context(), other, filepath.Join(root, other.String(), FsFileSession), nil))
}
