package audit

import (
	"context"
	goerrors "errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

type nativeRecorder struct {
	mutex                               sync.Mutex
	file                                *os.File
	lock                                *journalProcessLock
	lockPath, activePath, headDirectory string
	identity                            *Identity
	recipient                           *bfcrypto.AgeSshRecipient
	fingerprint                         string
	state                               nativeSegmentState
	minimumFreeBytes                    uint64
	availableBytes                      func(string) (uint64, error)
	poisoned, closeErr, cleanupErr      error
	closed                              bool
}

// newNativeRecorder is the native implementation entry point for NewRecorder.
func newNativeRecorder(conf *configuration.Auditlog, identity *Identity) (Recorder, error) {
	if conf == nil {
		return nil, fmt.Errorf("nil native audit configuration")
	}
	if !conf.Enabled {
		return NewNoopRecorder(), nil
	}
	if identity == nil || identity.ProducerId().IsZero() {
		return nil, fmt.Errorf("missing native audit identity")
	}
	keys, err := ResolveEncryptionPublicKey(conf.EncryptionPublicKey, conf.EncryptionPublicKeyFile)
	if err != nil {
		return nil, err
	}
	if err := ValidateEncryptionRecipientDedicatedFrom(keys, []bfcrypto.PrivateKey{identity.privateKey}); err != nil {
		return nil, err
	}
	var recipient *bfcrypto.AgeSshRecipient
	fingerprint := ""
	if !keys.IsZero() {
		recipient, fingerprint, err = newJournalEventRecipient(keys)
		if err != nil {
			return nil, err
		}
	}
	root, err := canonicalJournalDirectory(strings.TrimSpace(conf.Directory))
	if err != nil {
		return nil, err
	}
	if err := ensureJournalDirectory(root, true); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(root, journalLockFileName)
	if info, err := os.Lstat(lockPath); err == nil {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("invalid native audit lock path %q", lockPath)
		}
	} else if !goerrors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	lock, err := acquireJournalProcessLock(lockPath, journalFileMode)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = lock.Close()
		}
	}()
	if err := validateLockedJournalPath(lock, lockPath); err != nil {
		return nil, err
	}
	directory := filepath.Join(root, identity.ProducerId().String())
	rootEntries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range rootEntries {
		info, err := os.Lstat(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, err
		}
		switch entry.Name() {
		case journalLockFileName:
			if info.Mode().IsRegular() {
				continue
			}
		case identity.ProducerId().String(), journalWorkDirectoryName, remoteDeliveryStateDirectoryName:
			if info.IsDir() {
				continue
			}
		}
		return nil, fmt.Errorf("invalid native audit root entry %q", entry.Name())
	}
	if err := ensureJournalDirectory(directory, true); err != nil {
		return nil, err
	}
	activeName := nativeActiveClear
	if recipient != nil {
		activeName = nativeActiveEncrypted
	}
	activePath := filepath.Join(directory, activeName)
	file, state, err := nativeRecover(directory, activePath, identity, fingerprint)
	if err != nil {
		return nil, err
	}
	minimum := conf.MinimumFreeBytes
	if minimum == 0 {
		minimum = configuration.DefaultAuditlogJournalMinimumFreeBytes
	}
	committed = true
	return &nativeRecorder{file: file, lock: lock, lockPath: lockPath, activePath: activePath, headDirectory: directory,
		identity: identity, recipient: recipient, fingerprint: fingerprint, state: state,
		minimumFreeBytes: minimum, availableBytes: availableJournalBytes}, nil
}

func nativeRecover(directory, activePath string, identity *Identity, fingerprint string) (*os.File, nativeSegmentState, error) {
	var empty nativeSegmentState
	temps, err := nativeHeadTempsForInventory(directory)
	if err != nil {
		return nil, empty, err
	}
	inventory, err := newNativeSegmentInventory(context.Background(), directory, filepath.Base(activePath), fingerprint != "", temps, func() (*journalSegmentWorkspace, error) {
		return newRecorderJournalSegmentWorkspace(filepath.Dir(directory))
	})
	if err != nil {
		return nil, empty, err
	}
	file, state, recoverErr := nativeRecoverInventory(directory, activePath, identity, fingerprint, temps, inventory)
	if closeErr := inventory.segments.Close(); closeErr != nil {
		if file != nil {
			_ = file.Close()
		}
		return nil, empty, goerrors.Join(recoverErr, closeErr)
	}
	return file, state, recoverErr
}

func nativeHeadTempsForInventory(directory string) (map[string]struct{}, error) {
	temps := make(map[string]struct{})
	err := forEachJournalDirectoryEntry(context.Background(), directory, func(entry os.DirEntry) error {
		name := entry.Name()
		if !strings.HasPrefix(name, ".head-cbor-") {
			return nil
		}
		suffix := strings.TrimPrefix(name, ".head-cbor-")
		if len(suffix) < 6 || len(suffix) > 12 {
			return fmt.Errorf("invalid native head temp name %q", name)
		}
		for _, digit := range suffix {
			if digit < '0' || digit > '9' {
				return fmt.Errorf("invalid native head temp name %q", name)
			}
		}
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > nativeformat.MaxMetadataPayload {
			return fmt.Errorf("invalid native head temp %q", name)
		}
		if len(temps) >= journalSegmentSortChunkSize {
			return fmt.Errorf("excessive native head temps in %q", directory)
		}
		temps[name] = struct{}{}
		return nil
	})
	return temps, err
}

func nativeRecoverInventory(directory, activePath string, identity *Identity, fingerprint string, temps map[string]struct{}, inventory *nativeSegmentInventory) (*os.File, nativeSegmentState, error) {
	var empty nativeSegmentState
	hasActive, hasHead := inventory.hasActive, inventory.hasHead
	if !hasHead {
		_, found, err := inventory.segments.Next(context.Background())
		if err != nil {
			return nil, empty, err
		}
		if hasActive || found || len(temps) != 0 {
			return nil, empty, fmt.Errorf("native audit head missing with existing history")
		}
		if err := writeNativeHead(directory, identity, nil, journalHash{}); err != nil {
			return nil, empty, err
		}
	}
	checkpoint, err := readNativeHead(directory, identity)
	if err != nil {
		return nil, empty, err
	}
	s := nativeSegmentState{checkpointSeen: checkpoint.IsZero()}
	var lastSegment string
	for {
		entry, found, err := inventory.segments.Next(context.Background())
		if err != nil {
			return nil, empty, err
		}
		if !found {
			break
		}
		if s.seq == math.MaxUint64 || entry.sequence != s.seq+1 {
			return nil, empty, fmt.Errorf("native audit sequence gap or overflow")
		}
		f, err := nativeOpenRegular(entry.path)
		if err != nil {
			return nil, empty, err
		}
		scanned, scanErr := nativeScan(f, identity, entry.sequence, s.segmentHash, s.lastRecord, checkpoint, s.checkpointSeen, fingerprint, false)
		closeErr := f.Close()
		if scanErr != nil || closeErr != nil {
			return nil, empty, firstNativeError(scanErr, closeErr)
		}
		if scanned.segmentHash != entry.hash {
			return nil, empty, fmt.Errorf("native audit filename hash mismatch: %s", entry.path)
		}
		s = scanned
		lastSegment = entry.path
	}
	if hasActive {
		f, err := nativeOpenRegular(activePath)
		if err != nil {
			return nil, empty, err
		}
		if s.seq == math.MaxUint64 {
			_ = f.Close()
			return nil, empty, fmt.Errorf("native audit sequence overflow")
		}
		// A published sealed file can still share the active inode if publication
		// was interrupted after creating the target. Never truncate that inode.
		if lastSegment != "" {
			current, err := f.Stat()
			if err != nil {
				_ = f.Close()
				return nil, empty, err
			}
			if err := inventory.segments.Reset(); err != nil {
				_ = f.Close()
				return nil, empty, err
			}
			for {
				segment, found, err := inventory.segments.Next(context.Background())
				if err != nil {
					_ = f.Close()
					return nil, empty, err
				}
				if !found {
					break
				}
				info, err := os.Lstat(segment.path)
				if err != nil {
					_ = f.Close()
					return nil, empty, err
				}
				if os.SameFile(info, current) {
					_ = f.Close()
					return nil, empty, fmt.Errorf("native active aliases a published segment")
				}
			}
		}
		w, err := os.OpenFile(activePath, os.O_RDWR, journalFileMode)
		if err != nil {
			_ = f.Close()
			return nil, empty, err
		}
		original, a := f.Stat()
		writable, b := w.Stat()
		_ = f.Close()
		if a != nil || b != nil || !os.SameFile(original, writable) {
			_ = w.Close()
			return nil, empty, fmt.Errorf("native active changed while opening")
		}
		f = w
		if s.checkpointSeen {
			if err := nativeRecoverActiveStart(f, directory, identity, s.seq+1, s.segmentHash, s.lastRecord, fingerprint); err != nil {
				_ = f.Close()
				return nil, empty, err
			}
		}
		scanned, err := nativeScan(f, identity, s.seq+1, s.segmentHash, s.lastRecord, checkpoint, s.checkpointSeen, fingerprint, true)
		if err != nil {
			_ = f.Close()
			return nil, empty, err
		}
		if !scanned.checkpointSeen {
			_ = f.Close()
			return nil, empty, fmt.Errorf("native audit checkpoint not in chain")
		}
		if err := discardNativeHeadTempsWithInventory(directory, identity, checkpoint, scanned.lastRecord, temps, inventory.segments, activePath); err != nil {
			_ = f.Close()
			return nil, empty, err
		}
		if scanned.sealed {
			if scanned.seq == math.MaxUint64 {
				_ = f.Close()
				return nil, empty, fmt.Errorf("native audit sequence overflow")
			}
			scanned, err = nativePublishActive(f, activePath, scanned, identity)
			if err != nil {
				return nil, empty, err
			}
			s = scanned
		} else {
			if scanned.lastRecord != checkpoint {
				if err := writeNativeHead(directory, identity, &checkpoint, scanned.lastRecord); err != nil {
					_ = f.Close()
					return nil, empty, err
				}
			}
			return f, scanned, nil
		}
	}
	if !s.checkpointSeen {
		return nil, empty, fmt.Errorf("native audit checkpoint not in chain")
	}
	if err := discardNativeHeadTempsWithInventory(directory, identity, checkpoint, s.lastRecord, temps, inventory.segments, activePath); err != nil {
		return nil, empty, err
	}
	if s.lastRecord != checkpoint {
		if err := writeNativeHead(directory, identity, &checkpoint, s.lastRecord); err != nil {
			return nil, empty, err
		}
	}
	if s.seq == math.MaxUint64 {
		return nil, empty, fmt.Errorf("native audit sequence overflow")
	}
	return nativeCreateActive(activePath, identity, s.seq+1, s.segmentHash, s.lastRecord, fingerprint)
}

func discardNativeHeadTempsWithInventory(directory string, identity *Identity, checkpoint, tip journalHash, temps map[string]struct{}, segments *sortedJournalSegmentIterator, activePath string) error {
	if len(temps) == 0 {
		return nil
	}
	infos := make([]os.FileInfo, 0, len(temps))
	for name := range temps {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil {
			return err
		}
		infos = append(infos, info)
	}
	if err := segments.Reset(); err != nil {
		return err
	}
	for {
		segment, found, err := segments.Next(context.Background())
		if err != nil || !found {
			if err != nil {
				return err
			}
			break
		}
		info, err := os.Lstat(segment.path)
		if err != nil {
			return err
		}
		for _, temp := range infos {
			if os.SameFile(info, temp) {
				return fmt.Errorf("native head temp aliases published segment %q", segment.path)
			}
		}
	}
	return discardNativeHeadTemps(directory, identity, checkpoint, tip, temps, nil, activePath)
}

func (r *nativeRecorder) Record(ctx context.Context, e Event) error {
	_, err := r.record(ctx, e, false)
	return err
}

func (r *nativeRecorder) RecordSuppressible(ctx context.Context, e Event) (bool, error) {
	return r.record(ctx, e, true)
}

func (r *nativeRecorder) record(_ context.Context, e Event, suppressible bool) (bool, error) {
	if err := validateAuditEventForWrite(e); err != nil {
		return false, err
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.closed {
		return false, errJournalClosed
	}
	if r.poisoned != nil {
		return false, r.poisoned
	}
	if err := r.checkFile(); err != nil {
		return false, r.poison(err)
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return false, err
	}
	_, payload, hash, err := newNativeAuditRecord(r.identity, r.state.lastRecord, e, id, time.Now().UTC(), r.recipient)
	if err != nil {
		return false, err
	}
	frame, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxAuditRecordPayload)
	if err != nil {
		return false, err
	}
	if suppressible {
		available, err := r.availableBytes(r.headDirectory)
		if err != nil {
			return false, fmt.Errorf("native audit free space: %w", err)
		}
		additional := uint64(len(frame) + nativeformat.MaxMetadataPayload*2)
		if r.minimumFreeBytes > math.MaxUint64-additional || available < r.minimumFreeBytes+additional {
			return false, nil
		}
	}
	if r.state.fileBytes > nativeTargetSize-int64(len(frame)) && r.state.count > 0 {
		if err := r.rotate(); err != nil {
			return false, r.poison(err)
		}
	}
	if r.state.fileBytes > nativeMaxSize-int64(len(frame)) {
		return false, r.poison(fmt.Errorf("native audit record exceeds segment cap"))
	}
	end, err := nativeWriteUnit(r.file, r.state.fileBytes, nativeformat.ContentUnit, payload, nativeformat.MaxAuditRecordPayload)
	if err != nil {
		return false, r.poison(err)
	}
	previous := r.state.lastRecord
	r.state.fileBytes, r.state.contentBytes = end, end
	r.state.lastRecord = hash
	if r.state.count == math.MaxUint64 {
		return false, r.poison(fmt.Errorf("native audit record counter overflow"))
	}
	r.state.count++
	if err := writeNativeHead(r.headDirectory, r.identity, &previous, hash); err != nil {
		return false, r.poison(err)
	}
	return true, nil
}

func (r *nativeRecorder) checkFile() error {
	if err := validateLockedJournalPath(r.lock, r.lockPath); err != nil {
		return err
	}
	if err := validateOpenJournalFile(r.activePath, r.file); err != nil {
		return err
	}
	path, err := os.Lstat(r.activePath)
	if err != nil {
		return err
	}
	open, err := r.file.Stat()
	if err != nil {
		return err
	}
	if !path.Mode().IsRegular() || !os.SameFile(path, open) || open.Size() != r.state.fileBytes {
		return fmt.Errorf("native active file changed")
	}
	checkpoint, err := readNativeHead(r.headDirectory, r.identity)
	if err != nil {
		return err
	}
	if checkpoint != r.state.lastRecord {
		return fmt.Errorf("native audit head changed")
	}
	return nil
}

func (r *nativeRecorder) poison(err error) error {
	if r.poisoned == nil {
		r.poisoned = err
	}
	return r.poisoned
}

func (r *nativeRecorder) rotate() error {
	if r.state.seq == math.MaxUint64 {
		return fmt.Errorf("native audit sequence overflow")
	}
	if err := r.checkFile(); err != nil {
		return err
	}
	s, err := nativePublishActive(r.file, r.activePath, r.state, r.identity)
	if err != nil {
		return err
	}
	r.file = nil
	f, next, err := nativeCreateActive(r.activePath, r.identity, s.seq+1, s.segmentHash, s.lastRecord, r.fingerprint)
	if err != nil {
		return err
	}
	r.file, r.state = f, next
	return nil
}

func (r *nativeRecorder) Seal() error {
	if r == nil {
		return nil
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.closed {
		return errJournalClosed
	}
	if r.poisoned != nil {
		return r.poisoned
	}
	if r.state.count == 0 {
		return nil
	}
	if err := r.rotate(); err != nil {
		return r.poison(err)
	}
	return nil
}

func (r *nativeRecorder) Close() error                     { return r.close(false) }
func (r *nativeRecorder) CloseAfterAcceptedFailure() error { return r.close(true) }

func (r *nativeRecorder) close(accepted bool) error {
	if r == nil {
		return nil
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if !r.closed {
		r.closed = true
		known := r.poisoned
		if known == nil && r.state.count > 0 {
			if err := r.rotate(); err != nil {
				_ = r.poison(err)
			}
		}
		r.closeErr = r.poisoned
		if known == nil {
			r.cleanupErr = r.poisoned
		}
		if r.file != nil {
			if err := r.file.Sync(); err != nil {
				r.closeErr = goerrors.Join(r.closeErr, err)
				r.cleanupErr = goerrors.Join(r.cleanupErr, err)
			}
			if err := r.file.Close(); err != nil {
				r.closeErr = goerrors.Join(r.closeErr, err)
				r.cleanupErr = goerrors.Join(r.cleanupErr, err)
			}
		}
		if err := r.lock.Close(); err != nil {
			r.closeErr = goerrors.Join(r.closeErr, err)
			r.cleanupErr = goerrors.Join(r.cleanupErr, err)
		}
	}
	if accepted {
		return r.cleanupErr
	}
	return r.closeErr
}
