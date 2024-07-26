package user

import (
	"bytes"
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

func (this testFile) content(t *testing.T) string {
	f, err := os.OpenFile(string(this), os.O_RDONLY, 0)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, f.Close())
	}()

	all, err := io.ReadAll(f)
	require.NoError(t, err)

	return string(all)
}

type namedReader struct {
	io.Reader
	name string
}

func (this namedReader) Name() string {
	return this.name
}

type namedBytesBuffer struct {
	bytes.Buffer
}

func (this namedBytesBuffer) Name() string {
	return "test"
}

func (this namedBytesBuffer) Truncate(n int64) error {
	this.Buffer.Truncate(int(n))
	return nil
}
