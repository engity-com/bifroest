package recording

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func sealedPageTestID(number uint64) Id {
	var result Id
	binary.BigEndian.PutUint64(result[8:], number)
	result[6], result[8] = 0x40, result[8]|0x80
	return result
}

type sealedPageTestEntry struct {
	name string
	mode os.FileMode
}

func (this sealedPageTestEntry) Name() string      { return this.name }
func (this sealedPageTestEntry) IsDir() bool       { return this.mode.IsDir() }
func (this sealedPageTestEntry) Type() os.FileMode { return this.mode.Type() }
func (this sealedPageTestEntry) Info() (os.FileInfo, error) {
	panic("page selection must not inspect artifact contents")
}

type sealedPageTestReader struct {
	entries []os.DirEntry
	read    int
	lastErr error
}

func (this *sealedPageTestReader) ReadDir(count int) ([]os.DirEntry, error) {
	if count < 1 || count > 256 {
		panic("sealed inventory must use bounded directory reads")
	}
	end := min(this.read+count, len(this.entries))
	entries := this.entries[this.read:end]
	this.read = end
	if end == len(this.entries) {
		if this.lastErr != nil {
			return entries, this.lastErr
		}
		return entries, io.EOF
	}
	return entries, nil
}

func TestSealedRecordingPageSelectsIDsAcrossUnsortedBatches(t *testing.T) {
	var entries []os.DirEntry
	for number := uint64(4097); number > 0; number-- {
		suffix := ".bcast"
		if number%2 == 0 {
			suffix = ".becast"
		}
		entries = append(entries, sealedPageTestEntry{name: sealedPageTestID(number).String() + suffix})
	}
	entries = append(entries, sealedPageTestEntry{name: sealedPageTestID(2).String() + ".bcast" + localRetentionTombstone})
	for _, test := range []struct {
		after uint64
		limit uint
		want  []Id
	}{
		{0, 3, []Id{sealedPageTestID(1), sealedPageTestID(2), sealedPageTestID(3)}},
		{3, 2, []Id{sealedPageTestID(4), sealedPageTestID(5)}},
		{4096, 3, []Id{sealedPageTestID(4097)}},
		{4097, 3, []Id{}},
	} {
		reader := &sealedPageTestReader{entries: entries}
		var after Id
		if test.after > 0 {
			after = sealedPageTestID(test.after)
		}
		page, err := readSealedRecordingPage(t.Context(), reader, []string{".bcast", ".becast"}, SealedPageOptions{After: after, Limit: test.limit})
		require.NoError(t, err)
		require.Equal(t, len(entries), reader.read)
		ids := make([]Id, 0, len(page))
		for _, entry := range page {
			ids = append(ids, entry.ID)
		}
		require.Equal(t, test.want, ids)
	}
	page, err := readSealedRecordingPage(t.Context(), &sealedPageTestReader{entries: entries}, []string{".bcast", ".becast"}, SealedPageOptions{Limit: MaximumSealedPageSize})
	require.NoError(t, err)
	require.Len(t, page, int(MaximumSealedPageSize))
	require.Equal(t, sealedPageTestID(1), page[0].ID)
	require.Equal(t, sealedPageTestID(uint64(MaximumSealedPageSize)), page[len(page)-1].ID)
}

func TestSealedRecordingPageRejectsInvalidOptionsBeforeDirectoryAccess(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	for _, limit := range []uint{0, MaximumSealedPageSize + 1, ^uint(0)} {
		page, err := ReadSealedRecordingPage(t.Context(), missing, SealedPageOptions{Limit: limit})
		require.ErrorContains(t, err, "limit must be between")
		require.Nil(t, page)
	}
	_, err := ReadSealedRecordingPage(t.Context(), missing, SealedPageOptions{After: Id{1}, Limit: 1})
	require.ErrorContains(t, err, "illegal recording ID")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = ReadSealedRecordingPage(ctx, missing, SealedPageOptions{Limit: 1})
	require.ErrorIs(t, err, context.Canceled)
}

func TestSealedRecordingPageRejectsAmbiguityAndUnsafeInventory(t *testing.T) {
	name := sealedPageTestID(1).String()
	for _, entries := range [][]os.DirEntry{
		{sealedPageTestEntry{name: name + ".bcast"}, sealedPageTestEntry{name: name + ".becast"}},
		{sealedPageTestEntry{name: name + ".bcast", mode: os.ModeSymlink}},
		{sealedPageTestEntry{name: name + ".bcast", mode: os.ModeDir}},
		{sealedPageTestEntry{name: "../outside.bcast"}},
		{sealedPageTestEntry{name: "not-an-id.bcast" + localRetentionTombstone}},
	} {
		page, err := readSealedRecordingPage(t.Context(), &sealedPageTestReader{entries: entries}, []string{".bcast", ".becast"}, SealedPageOptions{Limit: 1})
		require.Error(t, err)
		require.Nil(t, page)
	}
	failure := errors.New("directory read failed")
	page, err := readSealedRecordingPage(t.Context(), &sealedPageTestReader{
		entries: []os.DirEntry{sealedPageTestEntry{name: name + ".bcast"}}, lastErr: failure,
	}, []string{".bcast"}, SealedPageOptions{Limit: 1})
	require.ErrorIs(t, err, failure)
	require.Nil(t, page)
}

func TestReadSealedRecordingPageDoesNotVerifyUnselectedArtifacts(t *testing.T) {
	root := t.TempDir()
	for _, number := range []uint64{3, 1, 2} {
		require.NoError(t, os.WriteFile(filepath.Join(root, sealedPageTestID(number).String()+".bcast"), []byte("not inspected by filename selection"), 0600))
	}
	page, err := ReadSealedRecordingPage(t.Context(), root, SealedPageOptions{After: sealedPageTestID(1), Limit: 1})
	require.NoError(t, err)
	require.Equal(t, []SealedRecordingFile{{ID: sealedPageTestID(2), Name: sealedPageTestID(2).String() + ".bcast"}}, page)
}

func TestSealedPageScanReleasesRepositoryMutexAndDrainsBeforeClose(t *testing.T) {
	identity, _, _ := castTestValues(t, true)
	repository, err := NewLocalNativeRecordingRepository(t.Context(), filepath.Join(t.TempDir(), "recordings"), identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	scanning, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseScan := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() {
		releaseScan()
		_ = repository.Close()
	})
	done := make(chan error, 1)
	go func() {
		done <- repository.repository.withSealedDirectory(t.Context(), func(*os.File) error {
			close(scanning)
			<-release
			return nil
		})
	}()
	select {
	case <-scanning:
	case <-time.After(time.Second):
		t.Fatal("page scan did not start")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.NoError(t, repository.repository.mutex.LockContext(ctx), "directory scanning must not block recording writers")
	repository.repository.mutex.Unlock()
	closed := make(chan error, 1)
	go func() { closed <- repository.Close() }()
	require.Eventually(t, func() bool {
		repository.repository.mutex.Lock()
		defer repository.repository.mutex.Unlock()
		return repository.repository.closed
	}, time.Second, time.Millisecond)
	select {
	case err := <-closed:
		t.Fatalf("repository closed before page scan finished: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	releaseScan()
	require.NoError(t, <-done)
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("repository did not close after page scan finished")
	}
}
