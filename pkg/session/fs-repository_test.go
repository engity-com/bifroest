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

func TestCanonicalizeFsRepositoryStorageRejectsMissingParent(t *testing.T) {
	storage := filepath.Join(t.TempDir(), "missing", "sessions")

	canonical, err := canonicalizeFsRepositoryStorage(storage)
	require.ErrorContains(t, err, "cannot canonicalize parent directory")
	require.Empty(t, canonical)
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

func TestFsRepositoryDeleteRemovesEmptyFlowDirectory(t *testing.T) {
	conf := newFsRepositoryTestConfiguration(t)
	repository, err := NewFsRepository(context.Background(), conf)
	require.NoError(t, err)
	defer func() { require.NoError(t, repository.Close()) }()
	ctx := context.Background()
	first, err := repository.Create(ctx, "test", fsRepositoryTestRemote{}, nil)
	require.NoError(t, err)
	second, err := repository.Create(ctx, "test", fsRepositoryTestRemote{}, nil)
	require.NoError(t, err)
	firstDirectory, err := repository.dir("test", first.Id())
	require.NoError(t, err)
	flowDirectory := filepath.Dir(firstDirectory)

	require.NoError(t, repository.Delete(ctx, first))
	require.DirExists(t, flowDirectory)
	require.NoError(t, repository.Delete(ctx, second))
	require.NoDirExists(t, flowDirectory)
}

func TestFsRepositoryFindAllReportsCorruptEntryAndContinues(t *testing.T) {
	conf := newFsRepositoryTestConfiguration(t)
	repository, err := NewFsRepository(context.Background(), conf)
	require.NoError(t, err)
	defer func() { require.NoError(t, repository.Close()) }()
	ctx := context.Background()
	corruptId := MustNewId()
	corruptDirectory, err := repository.dir("test", corruptId)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(corruptDirectory, 0700))
	corruptSessionFile := filepath.Join(corruptDirectory, FsFileSession)
	require.NoError(t, os.WriteFile(corruptSessionFile, []byte("not-json"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(corruptDirectory, FsFileEnvironmentToken), []byte(`{"containerId":"recover-me"}`), 0600))
	valid, err := repository.Create(ctx, "test", fsRepositoryTestRemote{}, nil)
	require.NoError(t, err)

	var diagnostics []FindDiagnostic
	var visited []Id
	autoCleanup := false
	err = repository.FindAll(ctx, func(_ context.Context, candidate Session) (bool, error) {
		visited = append(visited, candidate.Id())
		return true, nil
	}, &FindOpts{
		AutoCleanUpAllowed: &autoCleanup,
		DiagnosticConsumer: func(_ context.Context, diagnostic FindDiagnostic) error {
			diagnostics = append(diagnostics, diagnostic)
			return nil
		},
	})

	require.NoError(t, err)
	require.Equal(t, []Id{valid.Id()}, visited)
	require.Len(t, diagnostics, 1)
	require.Equal(t, configuration.FlowName("test"), diagnostics[0].Flow)
	require.Equal(t, corruptId, diagnostics[0].Id)
	require.Equal(t, corruptDirectory, diagnostics[0].Path)
	require.ErrorContains(t, diagnostics[0], "cannot decode session")
	require.FileExists(t, corruptSessionFile)
	require.FileExists(t, filepath.Join(corruptDirectory, FsFileEnvironmentToken))
}

func TestFsRepositoryFindAllReportsSessionDirectoryWithoutMetadata(t *testing.T) {
	conf := newFsRepositoryTestConfiguration(t)
	repository, err := NewFsRepository(context.Background(), conf)
	require.NoError(t, err)
	defer func() { require.NoError(t, repository.Close()) }()
	missingId := MustNewId()
	missingDirectory, err := repository.dir("test", missingId)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(missingDirectory, 0700))
	environmentToken := filepath.Join(missingDirectory, FsFileEnvironmentToken)
	require.NoError(t, os.WriteFile(environmentToken, []byte(`{"containerId":"recover-me"}`), 0600))
	valid, err := repository.Create(context.Background(), "test", fsRepositoryTestRemote{}, nil)
	require.NoError(t, err)

	var diagnostic FindDiagnostic
	var visited []Id
	autoCleanup := false
	err = repository.FindAll(context.Background(), func(_ context.Context, candidate Session) (bool, error) {
		visited = append(visited, candidate.Id())
		return true, nil
	}, &FindOpts{
		AutoCleanUpAllowed: &autoCleanup,
		DiagnosticConsumer: func(_ context.Context, candidate FindDiagnostic) error {
			diagnostic = candidate
			return nil
		},
	})

	require.NoError(t, err)
	require.Equal(t, []Id{valid.Id()}, visited)
	require.Equal(t, missingId, diagnostic.Id)
	require.ErrorIs(t, diagnostic, ErrCorruptSession)
	require.FileExists(t, environmentToken)
}

func TestFsRepositoryFindAllRestrictsAutoCleanupPerFlow(t *testing.T) {
	conf := newFsRepositoryTestConfiguration(t)
	repository, err := NewFsRepository(context.Background(), conf)
	require.NoError(t, err)
	defer func() { require.NoError(t, repository.Close()) }()
	corruptFiles := make(map[configuration.FlowName]string)
	for _, flow := range []configuration.FlowName{"current", "removed"} {
		id := MustNewId()
		directory, err := repository.dir(flow, id)
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(directory, 0700))
		corruptFiles[flow] = filepath.Join(directory, FsFileSession)
		require.NoError(t, os.WriteFile(corruptFiles[flow], []byte("not-json"), 0600))
	}
	autoCleanup := true
	var diagnostics []FindDiagnostic

	err = repository.FindAll(context.Background(), func(context.Context, Session) (bool, error) {
		return true, nil
	}, &FindOpts{
		AutoCleanUpAllowed: &autoCleanup,
		AutoCleanUpAllowedFor: func(_ context.Context, flow configuration.FlowName, _ Id) bool {
			return flow == "current"
		},
		DiagnosticConsumer: func(_ context.Context, diagnostic FindDiagnostic) error {
			diagnostics = append(diagnostics, diagnostic)
			return nil
		},
	})

	require.NoError(t, err)
	require.NoFileExists(t, corruptFiles["current"])
	require.FileExists(t, corruptFiles["removed"])
	require.Len(t, diagnostics, 1)
	require.Equal(t, configuration.FlowName("removed"), diagnostics[0].Flow)
}

func TestFsRepositoryAutoCleanupPreservesSessionAfterMetadataReadError(t *testing.T) {
	for _, autoCleanup := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[autoCleanup], func(t *testing.T) {
			repository, err := NewFsRepository(t.Context(), newFsRepositoryTestConfiguration(t))
			require.NoError(t, err)
			defer func() { require.NoError(t, repository.Close()) }()
			created, err := repository.Create(t.Context(), "test", fsRepositoryTestRemote{}, []byte("retain authorization"))
			require.NoError(t, err)
			interceptor, err := created.ConnectionInterceptor(t.Context())
			require.NoError(t, err)
			defer func() { require.NoError(t, interceptor.Close()) }()
			metadata, err := repository.file("test", created.Id(), FsFileSession)
			require.NoError(t, err)
			original, err := os.ReadFile(metadata)
			require.NoError(t, err)
			require.NoError(t, os.Rename(metadata, metadata+".saved"))
			require.NoError(t, os.Mkdir(metadata, 0700))

			_, err = repository.FindBy(t.Context(), "test", created.Id(), &FindOpts{AutoCleanUpAllowed: &autoCleanup})
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrCorruptSession)
			require.NotErrorIs(t, err, ErrNoSuchSession)
			require.False(t, interceptor.(*fsConnectionInterceptor).disposed.Load())
			require.DirExists(t, metadata)
			saved, readErr := os.ReadFile(metadata + ".saved")
			require.NoError(t, readErr)
			require.Equal(t, original, saved)

			var diagnostics []FindDiagnostic
			require.NoError(t, repository.FindAll(t.Context(), func(context.Context, Session) (bool, error) {
				t.Fatal("unreadable session must not be returned")
				return false, nil
			}, &FindOpts{AutoCleanUpAllowed: &autoCleanup, DiagnosticConsumer: func(_ context.Context, diagnostic FindDiagnostic) error {
				diagnostics = append(diagnostics, diagnostic)
				return nil
			}}))
			require.Len(t, diagnostics, 1)
			require.NotErrorIs(t, diagnostics[0].Err, ErrCorruptSession)
			require.DirExists(t, metadata)

			require.NoError(t, os.Remove(metadata))
			require.NoError(t, os.Rename(metadata+".saved", metadata))
			restored, err := repository.FindBy(t.Context(), "test", created.Id(), nil)
			require.NoError(t, err)
			token, err := restored.AuthorizationToken(t.Context())
			require.NoError(t, err)
			require.Equal(t, []byte("retain authorization"), token)
		})
	}
}

func TestFsRepositoryAutoCleanupOnlyRemovesCorruptOrMissingMetadata(t *testing.T) {
	for _, kind := range []string{"malformed", "wrong type", "invalid state", "missing"} {
		t.Run(kind, func(t *testing.T) {
			repository, err := NewFsRepository(t.Context(), newFsRepositoryTestConfiguration(t))
			require.NoError(t, err)
			defer func() { require.NoError(t, repository.Close()) }()
			created, err := repository.Create(t.Context(), "test", fsRepositoryTestRemote{}, []byte("retain until confirmed corrupt"))
			require.NoError(t, err)
			interceptor, err := created.ConnectionInterceptor(t.Context())
			require.NoError(t, err)
			defer func() { require.NoError(t, interceptor.Close()) }()
			metadata, err := repository.file("test", created.Id(), FsFileSession)
			require.NoError(t, err)
			switch kind {
			case "malformed":
				require.NoError(t, os.WriteFile(metadata, []byte("not-json"), 0600))
			case "wrong type":
				require.NoError(t, os.WriteFile(metadata, []byte(`{"state":42}`), 0600))
			case "invalid state":
				require.NoError(t, os.WriteFile(metadata, []byte(`{"state":"bogus"}`), 0600))
			case "missing":
				require.NoError(t, os.Remove(metadata))
			}
			var diagnostic FindDiagnostic
			autoCleanup := false
			require.NoError(t, repository.FindAll(t.Context(), func(context.Context, Session) (bool, error) {
				t.Fatal("corrupt session must not be returned")
				return false, nil
			}, &FindOpts{AutoCleanUpAllowed: &autoCleanup, DiagnosticConsumer: func(_ context.Context, value FindDiagnostic) error {
				diagnostic = value
				return nil
			}}))
			require.ErrorIs(t, diagnostic.Err, ErrCorruptSession)
			dir, err := repository.dir("test", created.Id())
			require.NoError(t, err)
			require.DirExists(t, dir)
			require.False(t, interceptor.(*fsConnectionInterceptor).disposed.Load())

			autoCleanup = true
			require.NoError(t, repository.FindAll(t.Context(), func(context.Context, Session) (bool, error) {
				t.Fatal("corrupt session must not be returned")
				return false, nil
			}, &FindOpts{AutoCleanUpAllowed: &autoCleanup}))
			require.NoDirExists(t, dir)
			require.True(t, interceptor.(*fsConnectionInterceptor).disposed.Load())
		})
	}
}

func TestFsRepositoryCanceledAutoCleanupPreservesCorruptSession(t *testing.T) {
	repository, err := NewFsRepository(t.Context(), newFsRepositoryTestConfiguration(t))
	require.NoError(t, err)
	defer func() { require.NoError(t, repository.Close()) }()
	created, err := repository.Create(t.Context(), "test", fsRepositoryTestRemote{}, nil)
	require.NoError(t, err)
	metadata, err := repository.file("test", created.Id(), FsFileSession)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(metadata, []byte("not-json"), 0600))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	autoCleanup := true
	_, err = repository.FindBy(ctx, "test", created.Id(), &FindOpts{AutoCleanUpAllowed: &autoCleanup})
	require.ErrorIs(t, err, context.Canceled)
	require.FileExists(t, metadata)
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
