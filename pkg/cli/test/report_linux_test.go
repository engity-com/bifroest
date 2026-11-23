package test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReportsRejectSymlinksAndInputHardlinks(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.yaml")
	require.NoError(t, os.WriteFile(input, []byte("original input"), 0600))
	for _, link := range []struct {
		name   string
		create func(string, string) error
	}{{"symlink", os.Symlink}, {"hardlink", os.Link}} {
		path := filepath.Join(dir, link.name+".xml")
		require.NoError(t, link.create(input, path))
		err := writeReport(path, func(io.Writer) error {
			t.Fatal("protected destinations must be rejected before serialization")
			return nil
		}, input)
		require.Error(t, err)
		require.ErrorContains(t, err, path)
		data, err := os.ReadFile(input)
		require.NoError(t, err)
		require.Equal(t, "original input", string(data))
	}
}
