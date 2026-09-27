//go:build darwin

package service

import (
	osuser "os/user"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func prepareLocalUserCertificateTest(t *testing.T) string {
	t.Helper()
	current, err := osuser.Current()
	require.NoError(t, err)
	return current.Username
}

func configureLocalUserCertificateAuthorization(*configuration.AuthorizationLocal) {}
