package recording

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"
)

const (
	// This is deliberately not an unbounded archive index. Larger/cold archives
	// fail closed instead of returning misleading partial pages or totals.
	MaximumNativeCatalogEntries = 1024
	MaximumNativeCatalogBytes   = 128 << 20
	nativeCatalogTTL            = 30 * time.Second
	nativeCatalogDeadline       = 4 * time.Second
)

type nativeCatalogEntry struct {
	info                  os.FileInfo
	change                any
	summary               NativeRecordingSummary
	verified              time.Time
	castVerificationBytes uint64
}

type nativeRecordingCatalog struct {
	mutex   localRepositoryMutex
	entries map[Id]nativeCatalogEntry
	warmup  *nativeCatalogWarmup
	keyOnce sync.Once
	key     [32]byte
	keyErr  error
}

type nativeCatalogWarmup struct {
	started                           time.Time
	remainingContainer, remainingCast int64
}

// NativeCatalogWarmupError reports an incomplete, non-published metadata scan.
// Only fully verified entries survive a pure deadline, for an explicit next read.
type NativeCatalogWarmupError struct {
	Cached, Total int
	cause         error
}

func (err *NativeCatalogWarmupError) Error() string {
	return fmt.Sprintf("recording catalog verification incomplete; cached %d/%d entries; refresh to continue: %v", err.Cached, err.Total, err.cause)
}

func (err *NativeCatalogWarmupError) Unwrap() error { return err.cause }

// IsNativeCatalogWarmup rejects mixed failures: a simultaneous close/audit error
// must not be presented to the client as ordinary metadata warmup.
func IsNativeCatalogWarmup(err error) bool {
	return nativeCatalogErrorOnly(err, func(value error) bool {
		_, ok := value.(*NativeCatalogWarmupError)
		return ok
	})
}

func nativeCatalogErrorOnly(err error, accept func(error) bool) bool {
	if err == nil {
		return false
	}
	if accept(err) {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !nativeCatalogErrorOnly(cause, accept) {
				return false
			}
		}
		return true
	}
	return nativeCatalogErrorOnly(errors.Unwrap(err), accept)
}

// CatalogCursorMAC authenticates cursors for this repository instance only.
// Restart/rotation invalidates cursors. This is not an artifact trust pin.
func (r *LocalNativeRecordingRepository) CatalogCursorMAC(payload []byte) ([]byte, error) {
	if r == nil || r.repository == nil {
		return nil, fmt.Errorf("nil recording catalog")
	}
	r.catalog.keyOnce.Do(func() { _, r.catalog.keyErr = rand.Read(r.catalog.key[:]) })
	if r.catalog.keyErr != nil {
		return nil, r.catalog.keyErr
	}
	mac := hmac.New(sha256.New, r.catalog.key[:])
	_, _ = mac.Write([]byte("bifroest.management.recording-cursor/v1\x00"))
	_, _ = mac.Write(payload)
	return mac.Sum(nil), nil
}

// CatalogMetadata is the legacy bounded materializing convenience API. Streaming
// management pages use WalkCatalog instead, without this helper's aggregate
// count/byte/deadline limits. The shared cache remains only an acceleration hint.
// This helper is called only after the shared management authorization and
// forced-command gates. It stores no actors, credentials, plaintext or rights.
// Each query inventories names/stamps, verifies changed/expired entries within
// hard count, compressed/decoded byte and deadline budgets, and removes stale
// entries. Selected output is independently reverified by the application.
// No private decryption identities are accepted, even for encrypted recordings.
func (r *LocalNativeRecordingRepository) CatalogMetadata(ctx context.Context) ([]NativeRecordingSummary, error) {
	return r.catalogMetadata(ctx, r.catalogMetadataEntry)
}

func (r *LocalNativeRecordingRepository) catalogMetadata(ctx context.Context, load func(context.Context, string, Id, int64, int64) (nativeCatalogEntry, error)) ([]NativeRecordingSummary, error) {
	if r == nil || r.repository == nil {
		return nil, fmt.Errorf("nil recording catalog")
	}
	ctx, cancel := context.WithTimeout(ctx, nativeCatalogDeadline)
	defer cancel()
	if err := r.catalog.mutex.LockContext(ctx); err != nil {
		return nil, err
	}
	defer r.catalog.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.catalog.warmup != nil && time.Since(r.catalog.warmup.started) >= nativeCatalogTTL {
		r.catalog.entries, r.catalog.warmup = nil, nil
	}
	entries := make(map[Id]nativeCatalogEntry)
	var result []NativeRecordingSummary
	budget := nativeCatalogWarmup{started: time.Now(), remainingContainer: MaximumNativeCatalogBytes, remainingCast: MaximumNativeCatalogBytes}
	if r.catalog.warmup != nil {
		budget = *r.catalog.warmup
	}
	inventoried, total := false, 0
	err := r.repository.withSealedDirectory(ctx, func(directory *os.File) error {
		files, err := readNativeCatalogInventory(ctx, directory, r.repository.format.sealedSuffix())
		if err != nil {
			return err
		}
		inventoried, total = true, len(files)
		// Retain only current inventory members inside the existing cache TTL.
		// Every member is still reopened/stamp-checked before a complete result;
		// this map is never authority to publish even a single partial row.
		for _, file := range files {
			if cached, ok := r.catalog.entries[file.ID]; ok && time.Since(cached.verified) < nativeCatalogTTL {
				entries[file.ID] = cached
			}
		}
		for _, file := range files {
			if err := ctx.Err(); err != nil {
				return err
			}
			path := filepath.Join(r.repository.sealedPath, file.Name)
			delete(entries, file.ID)
			item, err := load(ctx, path, file.ID, budget.remainingContainer, budget.remainingCast)
			if err != nil {
				return fmt.Errorf("recording catalog verification failed for %s: %w", file.ID.String(), err)
			}
			if old, ok := r.catalog.entries[file.ID]; !ok || old.verified != item.verified {
				budget.remainingContainer -= int64(item.summary.Bytes)
				budget.remainingCast -= int64(item.castVerificationBytes)
			}
			entries[file.ID] = item
			result = append(result, item.summary)
		}
		return ctx.Err()
	})
	if err != nil {
		if inventoried && ctx.Err() == context.DeadlineExceeded && nativeCatalogErrorOnly(err, func(cause error) bool { return cause == context.DeadlineExceeded }) {
			r.catalog.entries, r.catalog.warmup = entries, &budget
			return nil, &NativeCatalogWarmupError{Cached: len(entries), Total: total, cause: err}
		}
		// A corrupt or over-budget inventory must not leave a partially refreshed
		// index usable by the next query.
		r.catalog.entries, r.catalog.warmup = nil, nil
		return nil, err
	}
	r.catalog.entries = entries
	r.catalog.warmup = nil
	return result, nil
}

func readNativeCatalogInventory(ctx context.Context, directory sealedDirectoryReader, suffix string) ([]SealedRecordingFile, error) {
	var files []SealedRecordingFile
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		batch, readErr := directory.ReadDir(128)
		for _, entry := range batch {
			file, skip, err := sealedPageFile(entry, []string{suffix})
			if err != nil {
				return nil, err
			}
			if skip {
				continue
			}
			if len(files) >= MaximumNativeCatalogEntries {
				return nil, fmt.Errorf("recording catalog exceeds bounded metadata inventory")
			}
			files = append(files, file)
		}
		if readErr == io.EOF {
			return files, ctx.Err()
		}
		if readErr != nil {
			return nil, readErr
		}
	}
}

func (r *LocalNativeRecordingRepository) catalogMetadataEntry(ctx context.Context, path string, id Id, remainingContainer, remainingCast int64) (result nativeCatalogEntry, resultErr error) {
	return r.readCatalogEntry(ctx, path, id, remainingContainer, remainingCast, true)
}

func (r *LocalNativeRecordingRepository) readCatalogEntry(ctx context.Context, path string, id Id, remainingContainer, remainingCast int64, cachedAllowed bool) (result nativeCatalogEntry, resultErr error) {
	file, err := openSealedLocalFile(path)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return result, err
	}
	change, err := nativeCatalogFileChange(file, info)
	if err != nil {
		return result, err
	}
	if cached, ok := r.catalog.entries[id]; cachedAllowed && ok && time.Since(cached.verified) < nativeCatalogTTL &&
		os.SameFile(cached.info, info) && cached.info.Size() == info.Size() &&
		cached.info.ModTime().Equal(info.ModTime()) && reflect.DeepEqual(cached.change, change) {
		return cached, nil
	}
	if info.Size() < 1 || info.Size() > remainingContainer || remainingCast < 1 {
		return result, fmt.Errorf("recording catalog exceeds bounded verification budget")
	}
	summary, castVerificationBytes, err := r.verifyCatalogFile(ctx, file, info.Size(), CatalogVerifyLimits{
		MaximumContainerBytes: uint64(remainingContainer), MaximumCastBytes: uint64(remainingCast),
	})
	if err != nil {
		return result, err
	}
	if summary.RecordingId != id {
		return result, fmt.Errorf("recording catalog identity mismatch")
	}
	current, err := file.Stat()
	if err != nil {
		return result, err
	}
	currentChange, err := nativeCatalogFileChange(file, current)
	if err != nil {
		return result, err
	}
	// A write/chmod/mtime reset during verification invalidates the snapshot.
	pathInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, current) || !os.SameFile(info, pathInfo) ||
		info.Size() != current.Size() || info.ModTime() != current.ModTime() || !reflect.DeepEqual(change, currentChange) {
		return result, errors.Join(fmt.Errorf("recording changed during catalog verification"), err)
	}
	return nativeCatalogEntry{
		info: current, change: currentChange, summary: summary, verified: time.Now(),
		castVerificationBytes: castVerificationBytes,
	}, nil
}
