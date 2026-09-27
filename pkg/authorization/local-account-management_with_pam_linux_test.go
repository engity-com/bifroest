//go:build cgo && linux && !without_pam

package authorization

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLinuxEmptyPamServiceSkipsAccountCheck(t *testing.T) {
	allowed, err := checkLocalAccount("", "alice", "client.example")
	require.NoError(t, err)
	require.True(t, allowed)
}
