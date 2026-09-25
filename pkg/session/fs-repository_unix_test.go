//go:build unix

package session

import (
	"context"
	iofs "io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFsRepositoryAutoCleanupPreservesSessionOnPermissionError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read a file with no read permission")
	}
	repository, err := NewFsRepository(t.Context(), newFsRepositoryTestConfiguration(t))
	require.NoError(t, err)
	defer func() { require.NoError(t, repository.Close()) }()
	created, err := repository.Create(t.Context(), "test", fsRepositoryTestRemote{}, []byte("keep authorization"))
	require.NoError(t, err)
	metadata, err := repository.file("test", created.Id(), FsFileSession)
	require.NoError(t, err)
	before, err := os.ReadFile(metadata)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(metadata, 0000))
	defer func() { require.NoError(t, os.Chmod(metadata, 0600)) }()
	autoCleanup := true
	_, err = repository.FindBy(t.Context(), "test", created.Id(), &FindOpts{AutoCleanUpAllowed: &autoCleanup})
	require.ErrorIs(t, err, iofs.ErrPermission)
	var diagnostic FindDiagnostic
	require.NoError(t, repository.FindAll(t.Context(), func(context.Context, Session) (bool, error) {
		t.Fatal("unreadable session must not be returned")
		return false, nil
	}, &FindOpts{AutoCleanUpAllowed: &autoCleanup, DiagnosticConsumer: func(_ context.Context, value FindDiagnostic) error {
		diagnostic = value
		return nil
	}}))
	require.ErrorIs(t, diagnostic.Err, iofs.ErrPermission)
	content, err := os.ReadFile(metadata)
	require.ErrorIs(t, err, iofs.ErrPermission)
	require.Empty(t, content)
	require.NoError(t, os.Chmod(metadata, 0600))
	after, err := os.ReadFile(metadata)
	require.NoError(t, err)
	require.Equal(t, before, after)
	restored, err := repository.FindBy(t.Context(), "test", created.Id(), nil)
	require.NoError(t, err)
	token, err := restored.AuthorizationToken(t.Context())
	require.NoError(t, err)
	require.Equal(t, []byte("keep authorization"), token)
}
