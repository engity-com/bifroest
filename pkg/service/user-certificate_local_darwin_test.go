//go:build darwin

package service

import (
	osuser "os/user"
	"testing"

	"github.com/stretchr/testify/require"
)

func prepareLocalUserCertificateTest(t *testing.T) string {
	t.Helper()
	current, err := osuser.Current()
	require.NoError(t, err)
	return current.Username
}
