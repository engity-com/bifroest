package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestPublicKeysFile(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "valid")
	empty := filepath.Join(directory, "empty")
	invalid := filepath.Join(directory, "invalid")
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ed255191Pub)))
	require.NoError(t, os.WriteFile(valid, []byte(key+"\n"), 0600))
	require.NoError(t, os.WriteFile(empty, []byte("# empty\n"), 0600))
	require.NoError(t, os.WriteFile(invalid, []byte("restrict "+key+"\n"), 0600))

	actual, err := PublicKeysFile(valid).Get()
	require.NoError(t, err)
	require.Len(t, actual, 1)
	require.Equal(t, ed255191Pub.Marshal(), actual[0].Marshal())
	require.Error(t, PublicKeysFile(empty).Validate())
	require.Error(t, PublicKeysFile(invalid).Validate())
	require.Error(t, PublicKeysFile(filepath.Join(directory, "missing")).Validate())
	require.NoError(t, PublicKeysFile("").Validate())
}
