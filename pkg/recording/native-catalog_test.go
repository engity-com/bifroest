package recording

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestNativeCatalogCachesOnlyVerifiedContextAndRevalidatesChangeStamp(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted], func(t *testing.T) {
			identity, header, metadata := castTestValues(t, true)
			var recipient *bfcrypto.AgeSshRecipient
			if encrypted {
				recipient, _ = newBECastTestEncryption(t)
			}
			root := t.TempDir()
			repo, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, repo.Close()) })
			active, err := repo.CreateActive(t.Context(), header, metadata, 0)
			require.NoError(t, err)
			_, err = active.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, sealedArtifactUint32(0))
			require.NoError(t, err)
			rows, err := repo.CatalogMetadata(t.Context())
			require.NoError(t, err)
			require.Len(t, rows, 1)
			require.Equal(t, metadata.StartedAt, rows[0].StartedAt)
			if encrypted {
				require.Empty(t, rows[0].Flow)
				require.Empty(t, rows[0].SessionID)
			} else {
				require.Equal(t, metadata.Flow.String(), rows[0].Flow)
				require.Equal(t, metadata.SessionId.String(), rows[0].SessionID)
			}
			// Keep this entry warm but observably older than the next real
			// verification, even on a coarse Windows clock. Do not wait/sleep.
			entry := repo.catalog.entries[metadata.RecordingId]
			entry.verified = entry.verified.Add(-time.Second)
			repo.catalog.entries[metadata.RecordingId] = entry
			verified := entry.verified
			_, err = repo.CatalogMetadata(t.Context())
			require.NoError(t, err)
			require.Equal(t, verified, repo.catalog.entries[metadata.RecordingId].verified, "unchanged warm entries must not reread artifacts")
			entry = repo.catalog.entries[metadata.RecordingId]
			entry.verified = time.Now().Add(-nativeCatalogTTL - time.Second)
			repo.catalog.entries[metadata.RecordingId] = entry
			_, err = repo.CatalogMetadata(t.Context())
			require.NoError(t, err)
			require.True(t, repo.catalog.entries[metadata.RecordingId].verified.After(verified))
			path := filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+repo.repository.format.sealedSuffix())
			info, err := os.Stat(path)
			require.NoError(t, err)
			content, err := os.ReadFile(path)
			require.NoError(t, err)
			content[len(content)/2] ^= 1
			require.NoError(t, os.WriteFile(path, content, 0600))
			require.NoError(t, os.Chtimes(path, info.ModTime(), info.ModTime()))
			rows, err = repo.CatalogMetadata(t.Context())
			require.Error(t, err, "same-length corruption with restored mtime must invalidate the cache")
			require.Nil(t, rows)
			require.Empty(t, repo.catalog.entries)
			require.FileExists(t, path, "read failure must not repair or delete evidence")
		})
	}
}

func TestNativeCatalogBoundsColdReadsAndHonorsClosedOrCanceledRepository(t *testing.T) {
	identity, _, metadata := castTestValues(t, true)
	root := t.TempDir()
	repo, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	path := filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+".bcast")
	file, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, file.Truncate(MaximumNativeCatalogBytes+1))
	require.NoError(t, file.Close())
	rows, err := repo.CatalogMetadata(t.Context())
	require.ErrorContains(t, err, "bounded verification budget")
	require.Nil(t, rows)
	require.Empty(t, repo.catalog.entries)
	require.NoError(t, os.Remove(path)) // Only the sparse file this test injected.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = repo.CatalogMetadata(ctx)
	require.ErrorIs(t, err, context.Canceled)
	first, err := repo.CatalogCursorMAC([]byte("first"))
	require.NoError(t, err)
	second, err := repo.CatalogCursorMAC([]byte("second"))
	require.NoError(t, err)
	require.False(t, bytes.Equal(first, second))
	require.NoError(t, repo.Close())
	_, err = repo.CatalogMetadata(t.Context())
	require.ErrorContains(t, err, "closed")
}

func TestNativeCatalogRejectsOversizedInventoryBeforeReadingArtifacts(t *testing.T) {
	var entries []os.DirEntry
	for number := uint64(1); number <= MaximumNativeCatalogEntries+1; number++ {
		entries = append(entries, sealedPageTestEntry{name: sealedPageTestID(number).String() + ".bcast"})
	}
	files, err := readNativeCatalogInventory(t.Context(), &sealedPageTestReader{entries: entries[:MaximumNativeCatalogEntries]}, ".bcast")
	require.NoError(t, err)
	require.Len(t, files, MaximumNativeCatalogEntries)
	files, err = readNativeCatalogInventory(t.Context(), &sealedPageTestReader{entries: entries}, ".bcast")
	require.ErrorContains(t, err, "bounded metadata inventory")
	require.Nil(t, files)
}

func TestNativeCatalogLockWaitHonorsCancellationBeforeLockRelease(t *testing.T) {
	for _, mode := range []string{"canceled", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			identity, _, _ := castTestValues(t, true)
			repo, err := NewLocalNativeRecordingRepository(t.Context(), t.TempDir(), identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, repo.Close()) })
			repo.catalog.mutex.Lock()
			defer repo.catalog.mutex.Unlock() // Intentionally held through every assertion below.
			ctx, cancel := context.WithCancel(t.Context())
			want := context.Canceled
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 25*time.Millisecond)
				want = context.DeadlineExceeded
			}
			defer cancel()
			entered := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				close(entered)
				_, err := repo.CatalogMetadata(ctx)
				done <- err
			}()
			<-entered
			if mode == "canceled" {
				cancel()
			}
			select {
			case err := <-done:
				require.ErrorIs(t, err, want)
			case <-time.After(time.Second):
				t.Fatal("catalog waited for lock release despite canceled/deadline context")
			}
			require.Empty(t, repo.catalog.entries)
		})
	}
}
