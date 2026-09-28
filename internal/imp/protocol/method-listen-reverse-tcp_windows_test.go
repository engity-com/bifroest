//go:build windows

package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReverseTCPWindowsDoesNotRestrictLowPorts(t *testing.T) {
	require.NoError(t, authorizeReverseTCPPort(80, "", false))
}
