package recording

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/engity-com/bifroest/pkg/uuidpath"
	"io"
	"os"
)

// NativeCatalogProgress contains counts only, never identities or private data.
// Total is unknown (-1) until the fixed inventory has been captured.
type NativeCatalogProgress struct {
	Phase            string
	Completed, Total int64
}

// WalkCatalog verifies a fixed inventory with bounded resident memory. It has no
// wall-clock deadline or aggregate archive-size limit: caller cancellation and
// authorization own its lifetime. Each individual verification remains bounded.
// consume is provisional; callers must not publish results until this method AND
// their shared execution/capture/final-audit driver have completed successfully.
func (r *LocalNativeRecordingRepository) WalkCatalog(ctx context.Context, consume func(NativeRecordingSummary) error, progress func(NativeCatalogProgress) error) error {
	return r.walkCatalog(ctx, r.catalogMetadataEntry, consume, progress)
}

// VerifyCatalog is an explicit full read, never a cache/stamp-only success.
func (r *LocalNativeRecordingRepository) VerifyCatalog(ctx context.Context, consume func(NativeRecordingSummary) error, progress func(NativeCatalogProgress) error) error {
	return r.walkCatalog(ctx, func(ctx context.Context, path string, id Id, container, cast int64) (nativeCatalogEntry, error) {
		return r.readCatalogEntry(ctx, path, id, container, cast, false)
	}, consume, progress)
}

func (r *LocalNativeRecordingRepository) walkCatalog(ctx context.Context, load func(context.Context, string, Id, int64, int64) (nativeCatalogEntry, error), consume func(NativeRecordingSummary) error, progress func(NativeCatalogProgress) error) (resultErr error) {
	if r == nil || r.repository == nil || consume == nil {
		return fmt.Errorf("invalid recording catalog scan")
	}
	if err := r.catalog.mutex.LockContext(ctx); err != nil {
		return err
	}
	defer r.catalog.mutex.Unlock()
	// A streaming scan never carries a deadline's partial warmup budget forward.
	r.catalog.warmup = nil
	defer func() {
		if resultErr != nil {
			r.catalog.entries = nil
		}
	}()
	entries := make(map[Id]nativeCatalogEntry)
	err := r.walkInventory(ctx, "verifying", func(path string, id Id) error {
		item, err := load(ctx, path, id, MaximumNativeCatalogBytes, MaximumNativeCatalogBytes)
		if err != nil {
			return fmt.Errorf("recording catalog verification failed for %s: %w", id.String(), err)
		}
		if len(entries) < MaximumNativeCatalogEntries {
			entries[id] = item
		}
		return consume(item.summary)
	}, progress)
	if err == nil {
		r.catalog.entries = entries
	}
	return err
}

// WalkMetadata reads reusable selection metadata, not recording contents. Unlike
// WalkCatalog it neither acquires the full-verification lock nor populates its
// verified cache. Only the chosen page is subsequently fully checked.
func (r *LocalNativeRecordingRepository) WalkMetadata(ctx context.Context, consume func(NativeRecordingSummary) error, progress func(NativeCatalogProgress) error) error {
	if r == nil || r.repository == nil || r.metadata == nil || consume == nil {
		return fmt.Errorf("invalid recording metadata catalog")
	}
	return r.walkInventory(ctx, "metadata", func(path string, id Id) error {
		summary, err := r.indexedMetadata(ctx, path, id)
		if err != nil {
			return fmt.Errorf("recording metadata unavailable for %s: %w", id.String(), err)
		}
		return consume(summary)
	}, progress)
}

func (r *LocalNativeRecordingRepository) walkInventory(ctx context.Context, phase string, consume func(string, Id) error, progress func(NativeCatalogProgress) error) (resultErr error) {
	report := func(phase string, completed, total int64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if progress != nil {
			return progress(NativeCatalogProgress{phase, completed, total})
		}
		return nil
	}
	// Disk holds only canonical binary IDs, not metadata, keys or plaintext.
	// No archive file is opened for repair/recovery or modified by this scan.
	snapshot, err := os.CreateTemp("", "bifroest-recording-inventory-*")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, snapshot.Close(), os.Remove(snapshot.Name())) }()
	if err := report("inventory", 0, -1); err != nil {
		return err
	}
	return r.repository.withSealedDirectory(ctx, func(directory *os.File) error {
		captured := sha256.New()
		buffer := bufio.NewWriterSize(io.MultiWriter(snapshot, captured), 128*16)
		total, err := writeNativeCatalogInventory(ctx, directory, buffer, r.repository.format.sealedSuffix(), func(count int64) error { return report("inventory", count, -1) })
		if err != nil {
			return err
		}
		if err := buffer.Flush(); err != nil {
			return err
		}
		if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if err := report(phase, 0, total); err != nil {
			return err
		}
		replayed := sha256.New()
		inventory := io.TeeReader(snapshot, replayed)
		for index := int64(0); index < total; index++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			var id Id
			if _, err := io.ReadFull(inventory, id[:]); err != nil {
				return err
			}
			path, err := uuidpath.Resolve(r.repository.sealedPath, id, r.repository.format.sealedSuffix())
			if err != nil {
				return err
			}
			if err := consume(path, id); err != nil {
				return err
			}
			if err := report(phase, index+1, total); err != nil {
				return err
			}
		}
		var trailing [1]byte
		if n, err := inventory.Read(trailing[:]); n != 0 || err != io.EOF {
			return errors.Join(fmt.Errorf("recording inventory length changed during scan"), err)
		}
		if !bytes.Equal(captured.Sum(nil), replayed.Sum(nil)) {
			return fmt.Errorf("recording inventory changed during scan")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return nil
	})
}

func writeNativeCatalogInventory(ctx context.Context, directory sealedDirectoryReader, output io.Writer, suffix string, progress func(int64) error) (int64, error) {
	var count int64
	for {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		batch, readErr := directory.ReadDir(128)
		for _, entry := range batch {
			if err := ctx.Err(); err != nil {
				return count, err
			}
			file, skip, err := sealedPageFile(entry, []string{suffix})
			if err != nil {
				return count, err
			}
			if skip {
				continue
			}
			if count == (1<<53)-1 {
				return count, fmt.Errorf("recording inventory count overflow")
			}
			if n, err := output.Write(file.ID[:]); err != nil || n != len(file.ID) {
				return count, errors.Join(err, io.ErrShortWrite)
			}
			count++
		}
		if progress != nil {
			if err := progress(count); err != nil {
				return count, err
			}
		}
		if readErr == io.EOF {
			return count, ctx.Err()
		}
		if readErr != nil {
			return count, readErr
		}
	}
}
