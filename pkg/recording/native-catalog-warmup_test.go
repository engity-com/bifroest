package recording

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

type catalogControlledContext struct {
	context.Context
	cause error
	done  chan struct{}
	once  sync.Once
}

func (ctx *catalogControlledContext) Done() <-chan struct{} { return ctx.done }
func (ctx *catalogControlledContext) Err() error {
	select {
	case <-ctx.done:
		return ctx.cause
	default:
		return ctx.Context.Err()
	}
}
func (ctx *catalogControlledContext) expire() { ctx.once.Do(func() { close(ctx.done) }) }

func newCatalogWarmupFixture(t *testing.T, encrypted bool) (*LocalNativeRecordingRepository, string) {
	t.Helper()
	identity, header, metadata := castTestValues(t, true)
	var recipient *bfcrypto.AgeSshRecipient
	if encrypted {
		recipient, _ = newBECastTestEncryption(t)
	}
	root := t.TempDir()
	repo, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repo.Close()) })
	for number := uint64(1); number <= 2; number++ {
		current := metadata
		current.RecordingId = sealedPageTestID(number)
		active, err := repo.CreateActive(t.Context(), header, current, 0)
		require.NoError(t, err)
		_, err = active.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, sealedArtifactUint32(0))
		require.NoError(t, err)
	}
	return repo, root
}

// Trigger cancellation only after real cryptographic verification and descriptor
// checks. No sleeps, smaller production timeout, fake successful entry or retry.
func interruptCatalogWarmup(t *testing.T, repo *LocalNativeRecordingRepository, after int, cause, extra error) error {
	t.Helper()
	parent := &catalogControlledContext{Context: t.Context(), cause: cause, done: make(chan struct{})}
	loaded := 0
	rows, err := repo.catalogMetadata(parent, func(ctx context.Context, path string, id Id, container, cast int64) (nativeCatalogEntry, error) {
		entry, err := repo.catalogMetadataEntry(ctx, path, id, container, cast)
		if err != nil {
			return entry, err
		}
		loaded++
		if loaded == after {
			parent.expire()
			<-ctx.Done() // Observe the derived context's actual cancellation.
			if extra != nil {
				return nativeCatalogEntry{}, errors.Join(ctx.Err(), extra)
			}
		}
		return entry, nil
	})
	require.Nil(t, rows, "an incomplete scan must never publish partial metadata")
	require.ErrorIs(t, err, cause)
	require.Equal(t, after, loaded)
	return err
}

func TestNativeCatalogRetainsOnlyVerifiedDeadlineProgressAndResumesExplicitly(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprint(encrypted), func(t *testing.T) {
			repo, _ := newCatalogWarmupFixture(t, encrypted)
			err := interruptCatalogWarmup(t, repo, 1, context.DeadlineExceeded, nil)
			require.True(t, IsNativeCatalogWarmup(err))
			var pending *NativeCatalogWarmupError
			require.ErrorAs(t, err, &pending)
			require.Equal(t, 1, pending.Cached)
			require.Equal(t, 2, pending.Total)
			require.Len(t, repo.catalog.entries, 1)
			require.NotNil(t, repo.catalog.warmup)
			var id Id
			var cached nativeCatalogEntry
			for id, cached = range repo.catalog.entries {
			}
			if encrypted {
				require.Empty(t, cached.summary.Flow)
				require.Empty(t, cached.summary.SessionID)
				require.Empty(t, cached.summary.User)
			}
			require.EqualValues(t, MaximumNativeCatalogBytes-int64(cached.summary.Bytes), repo.catalog.warmup.remainingContainer)
			require.EqualValues(t, MaximumNativeCatalogBytes-int64(cached.castVerificationBytes), repo.catalog.warmup.remainingCast)
			containerBudget, castBudget := repo.catalog.warmup.remainingContainer, repo.catalog.warmup.remainingCast
			observed := false
			rows, err := repo.catalogMetadata(t.Context(), func(ctx context.Context, path string, current Id, container, cast int64) (nativeCatalogEntry, error) {
				if !observed {
					require.Equal(t, containerBudget, container)
					require.Equal(t, castBudget, cast)
					observed = true
				}
				return repo.catalogMetadataEntry(ctx, path, current, container, cast)
			})
			require.NoError(t, err)
			require.Len(t, rows, 2)
			require.Nil(t, repo.catalog.warmup)
			require.Equal(t, cached.verified, repo.catalog.entries[id].verified, "reuse a fresh, unchanged, fully verified entry without re-decoding it")
		})
	}
}

func TestNativeCatalogWarmupDoesNotResetItsByteAllowanceAcrossReads(t *testing.T) {
	repo, _ := newCatalogWarmupFixture(t, false)
	require.True(t, IsNativeCatalogWarmup(interruptCatalogWarmup(t, repo, 1, context.DeadlineExceeded, nil)))
	repo.catalog.warmup.remainingCast = 1
	rows, err := repo.CatalogMetadata(t.Context())
	require.Error(t, err, "the next unverified recording must use the carried allowance, not a fresh 128 MiB")
	require.False(t, IsNativeCatalogWarmup(err))
	require.Nil(t, rows)
	require.Empty(t, repo.catalog.entries)
	require.Nil(t, repo.catalog.warmup)
}

func TestNativeCatalogWarmupStillRejectsChangedEvidenceAndKeepsOriginalCacheTTL(t *testing.T) {
	for _, mode := range []string{"corruption", "expired"} {
		t.Run(mode, func(t *testing.T) {
			repo, root := newCatalogWarmupFixture(t, false)
			require.True(t, IsNativeCatalogWarmup(interruptCatalogWarmup(t, repo, 1, context.DeadlineExceeded, nil)))
			if mode == "expired" {
				repo.catalog.warmup.started = time.Now().Add(-nativeCatalogTTL - time.Second)
				repo.catalog.warmup.remainingCast = 1
				rows, err := repo.CatalogMetadata(t.Context())
				require.NoError(t, err, "an expired warmup is discarded as a whole before a new scan")
				require.Len(t, rows, 2)
				require.Nil(t, repo.catalog.warmup)
				return
			}
			var id Id
			for id = range repo.catalog.entries {
			}
			path := filepath.Join(root, localSealedDirectory, id.String()+".bcast")
			info, err := os.Stat(path)
			require.NoError(t, err)
			content, err := os.ReadFile(path)
			require.NoError(t, err)
			content[len(content)/2] ^= 1
			require.NoError(t, os.WriteFile(path, content, 0600))
			require.NoError(t, os.Chtimes(path, info.ModTime(), info.ModTime()))
			rows, err := repo.CatalogMetadata(t.Context())
			require.Error(t, err)
			require.False(t, IsNativeCatalogWarmup(err))
			require.Nil(t, rows)
			require.Empty(t, repo.catalog.entries)
			require.Nil(t, repo.catalog.warmup)
			require.FileExists(t, path)
		})
	}
}

func TestNativeCatalogWarmupDiscardsCancellationAndMixedDeadlineIOFailure(t *testing.T) {
	for _, test := range []struct {
		name         string
		after        int
		cause, extra error
	}{
		{"cancel", 1, context.Canceled, nil},
		{"mixed", 2, context.DeadlineExceeded, io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo, _ := newCatalogWarmupFixture(t, false)
			err := interruptCatalogWarmup(t, repo, test.after, test.cause, test.extra)
			require.False(t, IsNativeCatalogWarmup(err))
			require.Empty(t, repo.catalog.entries)
			require.Nil(t, repo.catalog.warmup)
		})
	}
}

func TestNativeCatalogWarmupClassificationNeverHidesAnotherFailure(t *testing.T) {
	pending := &NativeCatalogWarmupError{Cached: 1, Total: 2, cause: context.DeadlineExceeded}
	require.True(t, IsNativeCatalogWarmup(fmt.Errorf("wrapped: %w", pending)))
	require.True(t, IsNativeCatalogWarmup(errors.Join(pending, nil)))
	require.False(t, IsNativeCatalogWarmup(errors.Join(pending, io.ErrUnexpectedEOF)))
	require.False(t, IsNativeCatalogWarmup(context.DeadlineExceeded))
	require.False(t, IsNativeCatalogWarmup(errors.New("recording catalog verification incomplete")))
}
