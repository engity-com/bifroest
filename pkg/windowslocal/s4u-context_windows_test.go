//go:build windows

package windowslocal

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestS4UContextRejectsMissingOrCanceledContextBeforeRegistration(t *testing.T) {
	token, err := s4uImpersonationTokenWithFlagsContext(nil, "owned", s4uLogonFlagCheckLogonHours)
	require.Zero(t, token)
	require.ErrorContains(t, err, "context")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	token, err = s4uImpersonationTokenWithFlagsContext(ctx, "owned", s4uLogonFlagCheckLogonHours)
	require.Zero(t, token)
	require.ErrorIs(t, err, context.Canceled)
}

func TestS4UContextRejectsUnsupportedFlagsBeforeRegistration(t *testing.T) {
	for _, flags := range []uint32{1, 3, 4, 0xffffffff} {
		token, err := s4uImpersonationTokenWithFlagsContext(t.Context(), "owned", flags)
		require.Zero(t, token)
		require.ErrorContains(t, err, "unsupported local S4U flags")
	}
}
