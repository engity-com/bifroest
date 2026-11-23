//go:build windows

package windowslocal

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	berrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestPolicyRegressionNativeSAMNameRulesAndNotFoundSignal(t *testing.T) {
	for _, name := range []string{"alice", "ALICE", "some user", "Müller", "名字", "a$"} {
		require.True(t, validName(name), "%q", name)
	}
	for _, name := range []string{"", ".", "..", `host\alice`, "alice@host", " alice", "alice ", "alice.", "bad\nname", "\xff"} {
		require.False(t, validName(name), "%q", name)
	}
	for _, char := range `\/@"[]:;|=,+*?<>` {
		require.False(t, validName("a"+string(char)+"b"))
	}
	require.EqualError(t, ErrNotFound, "local SAM account not found")
	require.ErrorIs(t, fmt.Errorf("wrapped: %w", ErrNotFound), ErrNotFound)
	_, categorized := berrors.IsError(ErrNotFound)
	require.False(t, categorized)
}
