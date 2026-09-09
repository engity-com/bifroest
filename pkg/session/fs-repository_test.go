package session

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

func TestFsRepositoryExclusiveProcessLock(t *testing.T) {
	conf := newFsRepositoryTestConfiguration(t)
	first, err := NewFsRepository(context.Background(), conf)
	require.NoError(t, err)

	_, err = NewFsRepository(context.Background(), conf)
	require.ErrorContains(t, err, "already locked")
	require.NoError(t, first.Close())
	require.NoError(t, first.Close())

	second, err := NewFsRepository(context.Background(), conf)
	require.NoError(t, err)
	require.NoError(t, second.Close())
}

func TestFsRepositoryLockCoversStorageSymlinkAliases(t *testing.T) {
	root := t.TempDir()
	realStorage := filepath.Join(root, "real", "sessions")
	require.NoError(t, os.MkdirAll(realStorage, 0700))
	aliasStorage := filepath.Join(root, "alias")
	if err := os.Symlink(realStorage, aliasStorage); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	realConfiguration := newFsRepositoryTestConfiguration(t)
	realConfiguration.Storage = realStorage
	aliasConfiguration := newFsRepositoryTestConfiguration(t)
	aliasConfiguration.Storage = aliasStorage

	repository, err := NewFsRepository(context.Background(), realConfiguration)
	require.NoError(t, err)
	defer func() { require.NoError(t, repository.Close()) }()
	_, err = NewFsRepository(context.Background(), aliasConfiguration)
	require.ErrorContains(t, err, "already locked")
}

func TestFsRepositoryRejectsDanglingStorageSymlink(t *testing.T) {
	root := t.TempDir()
	storage := filepath.Join(root, "alias")
	if err := os.Symlink(filepath.Join(root, "missing", "sessions"), storage); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	conf := newFsRepositoryTestConfiguration(t)
	conf.Storage = storage
	_, err := NewFsRepository(context.Background(), conf)
	require.ErrorContains(t, err, "dangling")
}

func TestFsRepositoryPersistsEnvironmentTokenAndCreatedAt(t *testing.T) {
	conf := newFsRepositoryTestConfiguration(t)
	conf.IdleTimeout.SetNative(0)
	conf.MaxTimeout.SetNative(24 * time.Hour)
	repository, err := NewFsRepository(context.Background(), conf)
	require.NoError(t, err)

	ctx := context.Background()
	created, err := repository.Create(ctx, "test", fsRepositoryTestRemote{}, []byte("authorization"))
	require.NoError(t, err)
	require.NoError(t, created.SetEnvironmentToken(ctx, []byte("credential")))
	createdInfo, err := created.Info(ctx)
	require.NoError(t, err)
	createdDetails, err := createdInfo.Created(ctx)
	require.NoError(t, err)
	validUntil, err := createdInfo.ValidUntil(ctx)
	require.NoError(t, err)

	time.Sleep(5 * time.Millisecond)
	_, err = created.NotifyLastAccess(ctx, fsRepositoryTestRemote{}, StateAuthorized)
	require.NoError(t, err)
	updatedValidUntil, err := createdInfo.ValidUntil(ctx)
	require.NoError(t, err)
	require.Equal(t, validUntil, updatedValidUntil)
	require.NoError(t, repository.Close())

	restoredRepository, err := NewFsRepository(ctx, conf)
	require.NoError(t, err)
	defer func() { require.NoError(t, restoredRepository.Close()) }()
	restored, err := restoredRepository.FindBy(ctx, "test", created.Id(), nil)
	require.NoError(t, err)
	token, err := restored.EnvironmentToken(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("credential"), token)
	restoredInfo, err := restored.Info(ctx)
	require.NoError(t, err)
	restoredDetails, err := restoredInfo.Created(ctx)
	require.NoError(t, err)
	require.Equal(t, createdDetails.At(), restoredDetails.At())
}

func TestFsRepositoryRejectsWritesThroughStaleDisposedSession(t *testing.T) {
	conf := newFsRepositoryTestConfiguration(t)
	repository, err := NewFsRepository(context.Background(), conf)
	require.NoError(t, err)
	defer func() { require.NoError(t, repository.Close()) }()
	ctx := context.Background()
	created, err := repository.Create(ctx, "test", fsRepositoryTestRemote{}, nil)
	require.NoError(t, err)
	stale, err := repository.FindBy(ctx, "test", created.Id(), nil)
	require.NoError(t, err)
	_, err = created.Dispose(ctx)
	require.NoError(t, err)

	require.ErrorContains(t, stale.SetEnvironmentToken(ctx, []byte("credential")), "disposed")
	_, err = stale.NotifyLastAccess(ctx, fsRepositoryTestRemote{}, StateAuthorized)
	require.ErrorContains(t, err, "disposed")
	restored, err := repository.FindBy(ctx, "test", created.Id(), nil)
	require.NoError(t, err)
	info, err := restored.Info(ctx)
	require.NoError(t, err)
	require.Equal(t, StateDisposed, info.State())
}

func newFsRepositoryTestConfiguration(t *testing.T) *configuration.SessionFs {
	t.Helper()
	result := &configuration.SessionFs{}
	require.NoError(t, result.SetDefaults())
	result.Storage = t.TempDir() + "/sessions"
	return result
}

type fsRepositoryTestRemote struct{}

func (fsRepositoryTestRemote) User() string    { return "alice" }
func (fsRepositoryTestRemote) Host() bnet.Host { return bnet.MustNewHost("127.0.0.1") }
func (fsRepositoryTestRemote) String() string  { return "alice@127.0.0.1" }
