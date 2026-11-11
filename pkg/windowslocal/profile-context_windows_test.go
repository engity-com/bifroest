//go:build windows

package windowslocal

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSAMProfileContextRejectsCancellationBeforeNativeCalls(t *testing.T) {
	home, err := profileDirectoryContext(nil, Account{})
	require.Empty(t, home)
	require.Error(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	home, err = profileDirectoryContext(ctx, Account{})
	require.Empty(t, home)
	require.ErrorIs(t, err, context.Canceled)
}

func TestLocalSAMContextBoundProfileDirectory(t *testing.T) {
	requireSAMPolicyContainer(t)
	account, _ := newSAMPolicyAccount(t)
	var contextual string
	err := withS4USystemContext(t.Context(), func() error {
		var err error
		contextual, err = profileDirectoryContext(t.Context(), account)
		return err
	})
	require.NoError(t, err)
	require.NotEmpty(t, contextual)
	require.True(t, filepath.IsAbs(contextual))
	legacy, err := profileDirectory(account)
	require.NoError(t, err)
	require.Equal(t, legacy, contextual, "context-bound and legacy flags0 profile lookups must select the same owned account's home")
	_, err = currentAccount(account)
	require.NoError(t, err)
	t.Log("CONTEXT_SAM_PROFILE isolated context/legacy flags0 home match after unload and token cleanup; own account, no password replay or resume permission")
}
