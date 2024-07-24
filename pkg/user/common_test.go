package user

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"strings"
	"testing"
)

var (
	keepPkgUserFiles = os.Getenv("KEEP_PKG_USER_TEST_FILES") == "yes"
)

func b(in string) []byte {
	return []byte(in)
}

func bs(ins ...string) [][]byte {
	result := make([][]byte, len(ins))
	for i, in := range ins {
		result[i] = b(in)
	}
	return result
}

type testFile string

func (this testFile) dispose(t *testing.T) {
	if keepPkgUserFiles {
		t.Logf("File %q preserved", this)
		return
	}

	err := os.Remove(string(this))
	if os.IsNotExist(err) {
		return
	}
	assert.NoError(t, err, "test file %q should be deleted after the test", this)
}

func (this testFile) update(t *testing.T, with string) {
	f, err := os.OpenFile(string(this), os.O_TRUNC|os.O_WRONLY, 0600)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, f.Close())
	}()

	_, err = io.Copy(f, strings.NewReader(with))
	require.NoError(t, err)
}
