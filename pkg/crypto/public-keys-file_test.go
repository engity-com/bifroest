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
	require.ErrorContains(t, PublicKeysFile(directory).Validate(), "not a regular file")
	require.NoError(t, PublicKeysFile("").Validate())
}

func TestPublicKeysFileGetIsBoundedWhileForEachStreams(t *testing.T) {
	directory := t.TempDir()
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ed255191Pub)))
	below := filepath.Join(directory, "below")
	above := filepath.Join(directory, "above")
	belowCount := writePublicKeysTestFile(t, below, maxMaterializedPublicKeysFileSize-1, key)
	aboveCount := writePublicKeysTestFile(t, above, maxMaterializedPublicKeysFileSize+1, key)

	keys, err := PublicKeysFile(below).Get()
	require.NoError(t, err)
	require.Len(t, keys, belowCount)
	_, err = PublicKeysFile(above).Get()
	require.ErrorContains(t, err, "exceeds 4194304 bytes")

	streamed := 0
	require.NoError(t, PublicKeysFile(above).ForEach(func(_ int, _ ssh.PublicKey, _ string) (bool, error) {
		streamed++
		return true, nil
	}))
	require.Equal(t, aboveCount, streamed)
}

func writePublicKeysTestFile(t *testing.T, path string, size int64, key string) int {
	t.Helper()
	var content strings.Builder
	content.Grow(int(size))
	keyLine := key + "\n"
	keyCount := 0
	for int64(content.Len()+len(keyLine)) <= size {
		content.WriteString(keyLine)
		keyCount++
	}
	for int64(content.Len()) < size {
		lineSize := min(int64(1024), size-int64(content.Len()))
		if lineSize == 1 {
			content.WriteByte('\n')
			continue
		}
		content.WriteByte('#')
		content.WriteString(strings.Repeat("x", int(lineSize)-2))
		content.WriteByte('\n')
	}
	require.NoError(t, os.WriteFile(path, []byte(content.String()), 0600))
	return keyCount
}
