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
	keyOnce sync.Once
	key     [32]byte
	keyErr  error
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

// CatalogMetadata is called only after the shared management authorization and
// forced-command gates. It stores no actors, credentials, plaintext or rights.
// Each query inventories names/stamps, verifies changed/expired entries within
// hard count, compressed/decoded byte and deadline budgets, and removes stale
// entries. Selected output is independently reverified by the application.
// No private decryption identities are accepted, even for encrypted recordings.
func (r *LocalNativeRecordingRepository) CatalogMetadata(ctx context.Context) ([]NativeRecordingSummary, error) {
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
	entries := make(map[Id]nativeCatalogEntry)
	var result []NativeRecordingSummary
	remainingContainer, remainingCast := int64(MaximumNativeCatalogBytes), int64(MaximumNativeCatalogBytes)
	err := r.repository.withSealedDirectory(ctx, func(directory *os.File) error {
		files, err := readNativeCatalogInventory(ctx, directory, r.repository.format.sealedSuffix())
		if err != nil {
			return err
		}
		for _, file := range files {
			if err := ctx.Err(); err != nil {
				return err
			}
			path := filepath.Join(r.repository.sealedPath, file.Name)
			item, err := r.catalogMetadataEntry(ctx, path, file.ID, remainingContainer, remainingCast)
			if err != nil {
				return err
			}
			if old, ok := r.catalog.entries[file.ID]; !ok || old.verified != item.verified {
				remainingContainer -= int64(item.summary.Bytes)
				remainingCast -= int64(item.castVerificationBytes)
			}
			entries[file.ID] = item
			result = append(result, item.summary)
		}
		return ctx.Err()
	})
	if err != nil {
		// A corrupt or over-budget inventory must not leave a partially refreshed
		// index usable by the next query.
		r.catalog.entries = nil
		return nil, err
	}
	r.catalog.entries = entries
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
	if cached, ok := r.catalog.entries[id]; ok && time.Since(cached.verified) < nativeCatalogTTL &&
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
