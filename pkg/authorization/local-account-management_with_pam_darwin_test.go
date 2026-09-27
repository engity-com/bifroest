//go:build cgo && darwin && !without_pam

package authorization

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDarwinEmptyPamServiceFailsClosed(t *testing.T) {
	allowed, err := checkLocalAccount("", "alice", "client.example")
	require.Error(t, err)
	require.False(t, allowed)
}
