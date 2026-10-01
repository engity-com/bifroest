//go:build !without_pam && (darwin || (linux && cgo))

package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultAuthorizationLocalPamService(t *testing.T) {
	require.Equal(t, "sshd", DefaultAuthorizationLocalPamService)
}
