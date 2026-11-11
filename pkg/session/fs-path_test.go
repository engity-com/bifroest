package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/stretchr/testify/require"
)

func TestFsRepositoryPathsRejectInvalidFlowsWithoutNormalizingAliases(t *testing.T) {
	root := t.TempDir()
	conf := newFsRepositoryTestConfiguration(t)
	conf.Storage = filepath.Join(root, "sessions")
	repository, err := NewFsRepository(t.Context(), conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	sentinel := filepath.Join(root, "outside")
	require.NoError(t, os.WriteFile(sentinel, []byte("protected outside state"), 0600))
	id := MustNewId()
	for _, flow := range []configuration.FlowName{"", ".", "..", "../outside", "safe/../../outside", `..\outside`, "/outside", `C:\outside`, "safe\x00flow"} {
		path, err := repository.dir(flow, id)
		require.Error(t, err, string(flow))
		require.Empty(t, path)
		_, err = repository.Create(t.Context(), flow, associationRemote("client"), nil)
		require.Error(t, err)
		_, err = repository.FindBy(t.Context(), flow, id, nil)
		require.Error(t, err)
		require.Error(t, repository.DeleteBy(t.Context(), flow, id))
		content, err := os.ReadFile(sentinel)
		require.NoError(t, err)
		require.Equal(t, "protected outside state", string(content))
	}
	require.NoDirExists(t, conf.Storage)
	current, err := repository.Create(t.Context(), "safe.flow-1", associationRemote("client"), nil)
	require.NoError(t, err)
	path, err := repository.file(current.Flow(), current.Id(), FsFileSession)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(repository.storage, "safe.flow-1", current.Id().String(), FsFileSession), path)
	require.FileExists(t, path)
}

func TestFsRepositoryFileKindsRemainSingleLocalComponents(t *testing.T) {
	repository, _ := newAssociationRepository(t)
	id := MustNewId()
	for _, kind := range []string{"", ".", "..", "../s", "part/s", `..\s`, `C:s`, "s\x00suffix"} {
		path, err := repository.file("work", id, kind)
		require.Error(t, err, kind)
		require.Empty(t, path)
	}
	for _, kind := range []string{FsFileSession, FsFileAssociation, FsFileBrowserBindings, FsFileEnvironmentToken, FsFilePublicKeysPrefix + "abc"} {
		path, err := repository.file("work", id, kind)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(repository.storage, "work", id.String(), kind), path)
	}
}
