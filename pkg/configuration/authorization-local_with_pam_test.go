//go:build cgo && (linux || darwin) && !without_pam

package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultAuthorizationLocalPamService(t *testing.T) {
	require.Equal(t, "sshd", DefaultAuthorizationLocalPamService)
}
