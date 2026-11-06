package metadatacache

import (
	"context"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCacheReusesOnlySameFingerprintAndChecksItsOwnDigest(t *testing.T) {
	cache := New(1024, 2)
	defer func() { require.NoError(t, cache.Close()) }()
	var stamp [32]byte
	stamp[0] = 1
	builds := 0
	build := func(w io.Writer) error { builds++; _, err := io.WriteString(w, "metadata"); return err }
	consume := func(r io.Reader) error {
		data, err := io.ReadAll(r)
		require.Equal(t, "metadata", string(data))
		return err
	}
	require.NoError(t, cache.Use(t.Context(), "source", stamp, 64, build, consume))
	require.NoError(t, cache.Use(t.Context(), "source", stamp, 64, build, consume))
	require.Equal(t, 1, builds)
	value := cache.entries["source"]
	require.NoError(t, os.WriteFile(value.path, []byte("tampered"), 0600))
	err := cache.Use(t.Context(), "source", stamp, 64, build, func(r io.Reader) error { _, err := io.Copy(io.Discard, r); return err })
	require.ErrorContains(t, err, "integrity")
	require.Empty(t, cache.entries)
	require.NoError(t, cache.Use(t.Context(), "source", stamp, 64, build, consume))
	stamp[0] = 2
	require.NoError(t, cache.Use(t.Context(), "source", stamp, 64, build, consume))
	require.Equal(t, 3, builds)
}
func TestCacheBoundsDiskAndHonorsCancellationWhileWaiting(t *testing.T) {
	cache := New(16, 1)
	defer func() { require.NoError(t, cache.Close()) }()
	var stamp [32]byte
	build := func(w io.Writer) error { _, err := io.WriteString(w, "12345678"); return err }
	consume := func(r io.Reader) error { _, err := io.Copy(io.Discard, r); return err }
	require.NoError(t, cache.Use(t.Context(), "first", stamp, 8, build, consume))
	old := cache.entries["first"].path
	require.NoError(t, cache.Use(t.Context(), "second", stamp, 8, build, consume))
	require.NoFileExists(t, old)
	require.Len(t, cache.entries, 1)
	require.EqualValues(t, 8, cache.bytes)
	cache.lock <- struct{}{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, cache.Use(ctx, "third", stamp, 8, build, consume), context.Canceled)
	<-cache.lock
	err := cache.Use(t.Context(), "overflow", stamp, 8, func(w io.Writer) error { _, err := io.WriteString(w, "too many bytes"); return err }, consume)
	require.ErrorContains(t, err, "bound")
	files, err := os.ReadDir(cache.directory)
	require.NoError(t, err)
	require.Len(t, files, 1, "failed builds must not accumulate untracked spool files")
}
func TestCacheNeverCreatesItsWorkspaceInsideEvidence(t *testing.T) {
	root := t.TempDir()
	temporary := filepath.Join(root, "temporary")
	require.NoError(t, os.Mkdir(temporary, 0700))
	for _, name := range []string{"TMPDIR", "TEMP", "TMP"} {
		t.Setenv(name, temporary)
	}
	cache := New(1024, 2, root)
	defer func() { require.NoError(t, cache.Close()) }()
	var stamp [32]byte
	err := cache.Use(t.Context(), "source", stamp, 32, func(io.Writer) error { t.Fatal("builder must not run inside evidence"); return nil }, func(io.Reader) error { return nil })
	require.ErrorContains(t, err, "inside an evidence")
	entries, err := os.ReadDir(temporary)
	require.NoError(t, err)
	require.Empty(t, entries)
}
func TestFingerprintIgnoresReadsButRejectsSameLengthRestoredMtimeCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0600))
	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()
	before, err := Fingerprint(file)
	require.NoError(t, err)
	info, err := file.Stat()
	require.NoError(t, err)
	_, err = io.ReadAll(file)
	require.NoError(t, err)
	read, err := Fingerprint(file)
	require.NoError(t, err)
	require.Equal(t, before, read)
	require.NoError(t, os.WriteFile(path, []byte("modified"), 0600))
	require.NoError(t, os.Chtimes(path, info.ModTime(), info.ModTime()))
	after, err := Fingerprint(file)
	require.NoError(t, err)
	require.NotEqual(t, before, after)
}
