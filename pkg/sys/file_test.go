package sys

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
)

func TestCloneFile(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "just-a-file"))
	require.NoError(t, err)
	defer common.IgnoreCloseError(f)

	for lineN := 0; lineN < 10; lineN++ {
		_, err = fmt.Fprintf(f, "%d:abcdefg", lineN)
		require.NoError(t, err)
	}
	_, err = f.Seek(0, 0)
	require.NoError(t, err)

	read := func(expectedLineN int, from io.Reader) {
		expected := fmt.Sprintf("%d:abcdefg", expectedLineN)
		buf := make([]byte, len(expected))
		n, err := from.Read(buf)
		require.NoError(t, err)
		require.Equal(t, len(expected), n)
		assert.Equal(t, expected, string(buf[:n]))
	}

	read(0, f)
	read(1, f)

	f1, err := CloneFile(f)
	require.NoError(t, err)
	read(2, f1)
	read(3, f1)
	require.NoError(t, f1.Close())

	read(4, f)

	f2, err := CloneFile(f)
	require.NoError(t, err)
	read(5, f2)
	read(6, f2)
	require.NoError(t, f2.Close())

	read(7, f)
	read(8, f)
	read(9, f)
}
