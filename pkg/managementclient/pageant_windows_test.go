package managementclient

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"
)

func TestPageantRequestChecksBoundsBeforeContact(t *testing.T) {
	_, err := pageantQuery(nil)
	require.ErrorContains(t, err, "invalid")
	_, err = pageantQuery([]byte{0, 0, 0, 8, 1})
	require.ErrorContains(t, err, "invalid")
	oversized := make([]byte, pageantMaxMessage+1)
	binary.BigEndian.PutUint32(oversized[:4], uint32(len(oversized)-4))
	_, err = pageantQuery(oversized)
	require.ErrorContains(t, err, "oversized")
}

func TestPageantListsKeysWhenAvailable(t *testing.T) {
	if !pageantAvailable() {
		t.Skip("Pageant is not running on this Windows host")
	}
	_, err := agent.NewClient(&pageantConnection{}).List()
	require.NoError(t, err)
}

func TestWindowsAgentDialHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err := connectAgent(ctx, `\\.\pipe\bifroest-management-cancellation-test`)
	require.ErrorIs(t, err, context.Canceled)
}
