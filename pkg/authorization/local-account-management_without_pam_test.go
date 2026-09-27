//go:build unix && (!cgo || without_pam || (!linux && !darwin))

package authorization

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccountCheckWithoutPam(t *testing.T) {
	allowed, err := checkLocalAccount("", "alice", "client.example")
	require.NoError(t, err)
	require.True(t, allowed)

	allowed, err = checkLocalAccount("sshd", "alice", "client.example")
	require.Error(t, err)
	require.False(t, allowed)
}
