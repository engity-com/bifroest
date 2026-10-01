package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestDoWithEachAuthorizedKeyProvidesOptions(t *testing.T) {
	file := filepath.Join(t.TempDir(), "authorized_keys")
	entry := `restrict,command="forced-command",environment="FROM_KEY=value" ` + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ed255191Pub)))
	require.NoError(t, os.WriteFile(file, []byte(entry), 0600))

	called := false
	_, err := DoWithEachAuthorizedKey[bool](true, func(candidate ssh.PublicKey, options []AuthorizedKeyOption) (bool, bool, error) {
		called = true
		require.Equal(t, ed255191Pub.Marshal(), candidate.Marshal())
		require.Equal(t, []AuthorizedKeyOption{
			{Type: AuthorizedKeyRestrict},
			{Type: AuthorizedKeyCommand, Value: "forced-command"},
			{Type: AuthorizedKeyEnvironment, Value: "FROM_KEY=value"},
		}, options)
		return true, false, nil
	}, file)
	require.NoError(t, err)
	require.True(t, called)
}
