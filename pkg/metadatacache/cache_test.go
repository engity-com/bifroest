package metadatacache

import (
	"bytes"
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
func TestFileCacheIgnoresReadsButRejectsSameLengthRestoredMtimeCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0600))
	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()
	before, err := Fingerprint(file)
	require.NoError(t, err)
	cache := New(1024, 2)
	defer func() { require.NoError(t, cache.Close()) }()
	readImage := func(stamp [32]byte) []byte {
		var result []byte
		require.NoError(t, cache.UseFile(t.Context(), path, stamp, 64, func(output io.Writer) error { _, err := io.Copy(output, io.NewSectionReader(file, 0, 8)); return err }, func(input io.Reader) error { var err error; result, err = io.ReadAll(input); return err }))
		return result
	}
	first := readImage(before)
	require.Equal(t, []byte("original"), first)
	info, err := file.Stat()
	require.NoError(t, err)
	_, err = io.ReadAll(file)
	require.NoError(t, err)
	read, err := Fingerprint(file)
	require.NoError(t, err)
	require.Equal(t, before, read)
	require.Equal(t, first, readImage(read), "reads alone do not change the consumed metadata")
	require.NoError(t, os.WriteFile(path, []byte("modified"), 0600))
	require.NoError(t, os.Chtimes(path, info.ModTime(), info.ModTime()))
	after, err := Fingerprint(file)
	require.NoError(t, err)
	changed := readImage(after)
	require.Equal(t, []byte("modified"), changed, "the cache consumer must see the changed bytes, even if native time observations coincide")
	require.NotEqual(t, first, changed)
}

func TestUnreusableFileObservationsNeverRetainOrReuseAnImage(t *testing.T) {
	cache := New(1024, 2)
	defer func() { require.NoError(t, cache.Close()) }()
	var observation [32]byte
	source := []byte("original")
	builds := 0
	read := func() []byte {
		var result bytes.Buffer
		require.NoError(t, cache.use(t.Context(), "source", observation, 64, func(output io.Writer) error { builds++; _, err := output.Write(source); return err }, func(input io.Reader) error { _, err := io.Copy(&result, input); return err }, false))
		require.Empty(t, cache.entries)
		require.Zero(t, cache.bytes)
		files, err := os.ReadDir(cache.directory)
		require.NoError(t, err)
		require.Empty(t, files, "uncacheable images are removed after their lease, including on Windows")
		return result.Bytes()
	}
	require.Equal(t, []byte("original"), read())
	source = []byte("modified")
	require.Equal(t, []byte("modified"), read())
	require.Equal(t, 2, builds)
	err := cache.use(t.Context(), "source", observation, 64, func(output io.Writer) error { _, err := output.Write(source); return err }, func(io.Reader) error { return io.ErrUnexpectedEOF }, false)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Empty(t, cache.entries)
	files, err := os.ReadDir(cache.directory)
	require.NoError(t, err)
	require.Empty(t, files)
}
