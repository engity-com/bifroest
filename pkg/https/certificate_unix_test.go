//go:build unix

package https

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTlsPrivateKeyPermissionsAreCheckedWithoutRepairingTheFile(t *testing.T) {
	fixture := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	require.NoError(t, os.Chmod(fixture.configured.PrivateKeyFile, 0644))
	_, err := loadCertificate(fixture.configured, time.Now())
	require.ErrorContains(t, err, "protected TLS private key")
	info, err := os.Stat(fixture.configured.PrivateKeyFile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0644), info.Mode().Perm())
}
