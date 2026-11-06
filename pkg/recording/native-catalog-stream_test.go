package recording

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func catalogScanTemp(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"TMPDIR", "TEMP", "TMP"} {
		t.Setenv(name, root)
	}
	t.Cleanup(func() {
		files, err := filepath.Glob(filepath.Join(root, "bifroest-recording-inventory-*"))
		require.NoError(t, err)
		require.Empty(t, files, "success, failure and cancellation must remove their private snapshot")
	})
	return root
}

func TestNativeCatalogStreamInventoriesBeyondCacheCapacityInBoundedBatches(t *testing.T) {
	var entries []os.DirEntry
	for index := uint64(1); index <= MaximumNativeCatalogEntries+1; index++ {
		entries = append(entries, sealedPageTestEntry{name: sealedPageTestID(index).String() + ".bcast"})
	}
	var output bytes.Buffer
	var last int64
	count, err := writeNativeCatalogInventory(t.Context(), &sealedPageTestReader{entries: entries}, &output, ".bcast", func(count int64) error { require.LessOrEqual(t, count-last, int64(128)); last = count; return nil })
	require.NoError(t, err)
	require.EqualValues(t, MaximumNativeCatalogEntries+1, count)
	require.EqualValues(t, count*16, output.Len())
	for index := uint64(1); index <= uint64(count); index++ {
		var id Id
		_, err := io.ReadFull(&output, id[:])
		require.NoError(t, err)
		require.Equal(t, sealedPageTestID(index), id)
	}
}

func TestNativeCatalogStreamVerifiesMoreThan1024RealSignedRecordings(t *testing.T) {
	catalogScanTemp(t)
	repo, _ := newCatalogWarmupFixture(t, false)
	_, header, metadata := castTestValues(t, true)
	for number := uint64(3); number <= MaximumNativeCatalogEntries+1; number++ {
		current := metadata
		current.RecordingId = sealedPageTestID(number)
		active, err := repo.CreateActive(t.Context(), header, current, 0)
		require.NoError(t, err)
		_, err = active.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, sealedArtifactUint32(0))
		require.NoError(t, err)
	}
	var count int64
	var final NativeCatalogProgress
	deadline, hasDeadline := t.Context().Deadline()
	err := repo.walkCatalog(t.Context(), func(ctx context.Context, path string, id Id, container, cast int64) (nativeCatalogEntry, error) {
		actual, actualDeadline := ctx.Deadline()
		require.Equal(t, hasDeadline, actualDeadline)
		require.Equal(t, deadline, actual, "the scanner must not install an aggregate deadline")
		require.EqualValues(t, MaximumNativeCatalogBytes, container)
		require.EqualValues(t, MaximumNativeCatalogBytes, cast)
		return repo.catalogMetadataEntry(ctx, path, id, container, cast)
	}, func(row NativeRecordingSummary) error {
		require.False(t, row.RecordingId.IsZero())
		count++
		return nil
	}, func(progress NativeCatalogProgress) error { final = progress; return nil })
	require.NoError(t, err)
	require.EqualValues(t, MaximumNativeCatalogEntries+1, count)
	require.Len(t, repo.catalog.entries, MaximumNativeCatalogEntries)
	require.Equal(t, NativeCatalogProgress{"verifying", count, count}, final)
}

func TestNativeCatalogStreamUsesPerRecordingRatherThanAggregateByteBudget(t *testing.T) {
	catalogScanTemp(t)
	repo, _ := newCatalogWarmupFixture(t, false)
	_, header, metadata := castTestValues(t, true)
	output := bytes.Repeat([]byte("x"), 256<<10)
	for number := uint64(3); number <= 5; number++ {
		current := metadata
		current.RecordingId = sealedPageTestID(number)
		active, err := repo.CreateActive(t.Context(), header, current, 0)
		require.NoError(t, err)
		for index := 1; index <= 180; index++ {
			require.NoError(t, active.WriteOutput(time.Duration(index)*time.Millisecond, OutputStreamTerminal, output))
		}
		_, err = active.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, sealedArtifactUint32(0))
		require.NoError(t, err)
	}
	var castBytes uint64
	count := 0
	err := repo.WalkCatalog(t.Context(), func(row NativeRecordingSummary) error { count++; castBytes += row.CastBytes; return nil }, nil)
	require.NoError(t, err)
	require.Equal(t, 5, count)
	require.Greater(t, castBytes, uint64(MaximumNativeCatalogBytes))
}

func TestNativeCatalogStreamFixesInventoryBeforeVerificationAndRetainsNoPrivateContext(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted], func(t *testing.T) {
			catalogScanTemp(t)
			repo, _ := newCatalogWarmupFixture(t, encrypted)
			_, header, metadata := castTestValues(t, true)
			added := false
			count := 0
			err := repo.WalkCatalog(t.Context(), func(row NativeRecordingSummary) error {
				count++
				if encrypted {
					require.Empty(t, row.Flow)
					require.Empty(t, row.SessionID)
					require.Empty(t, row.User)
				}
				return nil
			}, func(progress NativeCatalogProgress) error {
				if progress.Phase == "verifying" && progress.Completed == 0 {
					require.False(t, added)
					require.EqualValues(t, 2, progress.Total)
					current := metadata
					current.RecordingId = sealedPageTestID(3)
					active, err := repo.CreateActive(t.Context(), header, current, 0)
					require.NoError(t, err)
					_, err = active.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, sealedArtifactUint32(0))
					require.NoError(t, err)
					added = true
				}
				return nil
			})
			require.NoError(t, err)
			require.True(t, added)
			require.Equal(t, 2, count)
			count = 0
			require.NoError(t, repo.WalkCatalog(t.Context(), func(NativeRecordingSummary) error { count++; return nil }, nil))
			require.Equal(t, 3, count)
		})
	}
}

func TestNativeCatalogStreamFailureAndCancellationDiscardProvisionalCache(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "observer", "corruption"} {
		t.Run(mode, func(t *testing.T) {
			catalogScanTemp(t)
			repo, root := newCatalogWarmupFixture(t, false)
			if mode == "corruption" {
				path := filepath.Join(root, localSealedDirectory, sealedPageTestID(2).String()+".bcast")
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				data[len(data)/2] ^= 1
				require.NoError(t, os.WriteFile(path, data, 0600))
			}
			cause := context.Canceled
			if mode == "deadline" {
				cause = context.DeadlineExceeded
			}
			ctx := &catalogControlledContext{Context: t.Context(), cause: cause, done: make(chan struct{})}
			observerErr := errors.New("observer stopped")
			err := repo.WalkCatalog(ctx, func(NativeRecordingSummary) error { return nil }, func(progress NativeCatalogProgress) error {
				if progress.Phase == "verifying" && progress.Completed == 1 {
					if mode == "observer" {
						return observerErr
					}
					if mode == "cancel" || mode == "deadline" {
						ctx.expire()
					}
				}
				return nil
			})
			require.Error(t, err)
			require.Empty(t, repo.catalog.entries)
			require.Nil(t, repo.catalog.warmup)
			if mode == "observer" {
				require.ErrorIs(t, err, observerErr)
			} else if mode != "corruption" {
				require.ErrorIs(t, err, cause)
			}
		})
	}
}

func TestNativeCatalogStreamRejectsChangedTemporaryInventoryBeforeCompletion(t *testing.T) {
	temporary := catalogScanTemp(t)
	repo, _ := newCatalogWarmupFixture(t, false)
	err := repo.WalkCatalog(t.Context(), func(NativeRecordingSummary) error { return nil }, func(progress NativeCatalogProgress) error {
		if progress.Phase == "verifying" && progress.Completed == 0 {
			files, err := filepath.Glob(filepath.Join(temporary, "bifroest-recording-inventory-*"))
			require.NoError(t, err)
			require.Len(t, files, 1)
			id := sealedPageTestID(1)
			require.NoError(t, os.WriteFile(files[0], bytes.Repeat(id[:], 2), 0600))
		}
		return nil
	})
	require.ErrorContains(t, err, "inventory changed during scan")
	require.Empty(t, repo.catalog.entries)
}
