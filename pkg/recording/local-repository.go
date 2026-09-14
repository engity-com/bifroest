package recording

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
)

const (
	localRecordingLockFileName        = ".bifroest-recording.lock"
	localRecordingWorkDirectory       = ".bifroest-work"
	localRecordingActiveDirectory     = "active"
	localRecordingSealedDirectory     = "sealed"
	localRecordingQuarantineDirectory = "quarantine"
	localRecordingContentFileName     = "recording.cast.zst"
	localRecordingHeadFileName        = "head.json"
	localRecordingHeadTempFileName    = "head.tmp"
	localRecordingSealedSuffix        = ".cast.zst"
)

type LocalCastZstdRepository struct {
	mutex          sync.Mutex
	directory      string
	activePath     string
	sealedPath     string
	workPath       string
	quarantinePath string
	lockPath       string
	identity       *audit.Identity
	options        CastZstdVerifyOptions
	processLock    *localRecordingProcessLock
	active         map[Id]*ActiveCastZstd
	recovered      []RecoveredCastZstd
	closed         bool
	poisoned       error
}

type RecoveredCastZstd struct {
	Summary       CastZstdSummary
	Truncated     bool
	AlreadySealed bool
}

type ActiveCastZstd struct {
	mutex      sync.Mutex
	repository *LocalCastZstdRepository
	id         Id
	directory  string
	path       string
	headPath   string
	file       *os.File
	writer     *CastZstdWriter
	poisoned   error
	closed     bool
	sealed     bool
}

func NewLocalCastZstdRepository(ctx context.Context, directory string, identity *audit.Identity, options CastZstdVerifyOptions) (*LocalCastZstdRepository, error) {
	if identity == nil || identity.PublicKey() == nil {
		return nil, fmt.Errorf("nil local recording identity")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	canonical, err := canonicalLocalRecordingDirectory(strings.TrimSpace(directory))
	if err != nil {
		return nil, fmt.Errorf("cannot resolve local recording directory: %w", err)
	}
	if err := ensureLocalRecordingDirectory(canonical); err != nil {
		return nil, fmt.Errorf("cannot prepare local recording directory %q: %w", canonical, err)
	}
	lockPath := filepath.Join(canonical, localRecordingLockFileName)
	processLock, err := acquireLocalRecordingProcessLock(lockPath)
	if err != nil {
		return nil, fmt.Errorf("cannot lock local recording repository %q: %w", canonical, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = processLock.Close()
		}
	}()
	if err := validateLocalRecordingLock(processLock, lockPath); err != nil {
		return nil, err
	}
	result := &LocalCastZstdRepository{
		directory:      canonical,
		activePath:     filepath.Join(canonical, localRecordingActiveDirectory),
		sealedPath:     filepath.Join(canonical, localRecordingSealedDirectory),
		workPath:       filepath.Join(canonical, localRecordingWorkDirectory),
		quarantinePath: filepath.Join(canonical, localRecordingQuarantineDirectory),
		lockPath:       lockPath,
		identity:       identity,
		options:        options,
		processLock:    processLock,
		active:         make(map[Id]*ActiveCastZstd),
	}
	result.options.ExpectedProducerId = identity.ProducerId()
	result.options.AllowUntrusted = false
	result.options.Context = ctx
	for _, path := range []string{result.activePath, result.sealedPath, result.workPath, result.quarantinePath} {
		if err := ensureLocalRecordingDirectory(path); err != nil {
			return nil, fmt.Errorf("cannot prepare local recording repository path %q: %w", path, err)
		}
	}
	if err := result.validateRoot(); err != nil {
		return nil, err
	}
	if err := result.recoverWorkDirectories(); err != nil {
		return nil, err
	}
	if err := result.recoverActive(ctx); err != nil {
		return nil, err
	}
	if err := result.validateSealed(); err != nil {
		return nil, err
	}
	committed = true
	return result, nil
}

func (this *LocalCastZstdRepository) StartupRecoveries() []RecoveredCastZstd {
	if this == nil {
		return nil
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return append([]RecoveredCastZstd(nil), this.recovered...)
}

func (this *LocalCastZstdRepository) CreateActive(ctx context.Context, header CastHeader, metadata CastMetadata, chunkSize int) (*ActiveCastZstd, error) {
	if this == nil {
		return nil, fmt.Errorf("nil local recording repository")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if err := validateCastHeader(header); err != nil {
		return nil, err
	}
	if err := validateCastMetadata(header, metadata); err != nil {
		return nil, err
	}
	if metadata.ProducerId != this.identity.ProducerId() {
		return nil, fmt.Errorf("local recording producer does not match repository identity")
	}

	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return nil, fmt.Errorf("local recording repository is closed")
	}
	if this.poisoned != nil {
		return nil, this.poisoned
	}
	if err := validateLocalRecordingLock(this.processLock, this.lockPath); err != nil {
		return nil, err
	}
	if _, exists := this.active[metadata.RecordingId]; exists {
		return nil, fmt.Errorf("recording %s is already active", metadata.RecordingId)
	}
	activeDirectory := filepath.Join(this.activePath, metadata.RecordingId.String())
	sealedPath := filepath.Join(this.sealedPath, metadata.RecordingId.String()+localRecordingSealedSuffix)
	workDirectory := filepath.Join(this.workPath, metadata.RecordingId.String()+".tmp")
	for _, path := range []string{activeDirectory, sealedPath, workDirectory} {
		if _, err := os.Lstat(path); err == nil {
			return nil, fmt.Errorf("recording path %q already exists", path)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	if err := ensureLocalRecordingDirectory(workDirectory); err != nil {
		return nil, fmt.Errorf("cannot create recording staging directory: %w", err)
	}
	removeWork := true
	defer func() {
		if removeWork {
			_ = os.RemoveAll(workDirectory)
		}
	}()
	contentPath := filepath.Join(workDirectory, localRecordingContentFileName)
	file, err := createLocalRecordingFile(contentPath)
	if err != nil {
		return nil, fmt.Errorf("cannot create active recording: %w", err)
	}
	closeFile := true
	defer func() {
		if closeFile {
			_ = file.Close()
		}
	}()
	writer, err := NewCastZstdWriter(file, this.identity, header, metadata, chunkSize)
	if err != nil {
		return nil, err
	}
	checkpoint, err := writer.Checkpoint()
	if err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, fmt.Errorf("cannot synchronize initial recording: %w", err)
	}
	head, err := encodeCastZstdHead(checkpoint)
	if err != nil {
		return nil, err
	}
	if err := writeLocalRecordingHead(workDirectory, head); err != nil {
		return nil, fmt.Errorf("cannot persist initial recording head: %w", err)
	}
	if err := syncLocalRecordingDirectory(workDirectory); err != nil {
		return nil, err
	}
	originalInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	closeFile = false
	if err := publishLocalRecordingDirectory(workDirectory, activeDirectory); err != nil {
		return nil, fmt.Errorf("cannot publish active recording: %w", err)
	}
	removeWork = false
	if err := syncLocalRecordingDirectory(this.activePath); err != nil {
		return nil, this.poisonLocked(err)
	}
	if err := syncLocalRecordingDirectory(this.workPath); err != nil {
		return nil, this.poisonLocked(err)
	}
	contentPath = filepath.Join(activeDirectory, localRecordingContentFileName)
	file, err = openActiveLocalRecordingFile(contentPath)
	if err != nil {
		return nil, this.poisonLocked(err)
	}
	closeFile = true
	reopenedInfo, err := file.Stat()
	if err != nil || !os.SameFile(originalInfo, reopenedInfo) || reopenedInfo.Size() != int64(checkpoint.PrefixBytes) {
		return nil, this.poisonLocked(fmt.Errorf("active recording changed while being published"))
	}
	verifyOptions := this.options
	verifyOptions.Context = context.Background()
	if err := verifyActiveCastZstdCheckpoint(file, reopenedInfo.Size(), verifyOptions, checkpoint); err != nil {
		return nil, this.poisonLocked(err)
	}
	if err := writer.replaceOutput(file); err != nil {
		return nil, this.poisonLocked(err)
	}
	active := &ActiveCastZstd{
		repository: this,
		id:         metadata.RecordingId,
		directory:  activeDirectory,
		path:       contentPath,
		headPath:   filepath.Join(activeDirectory, localRecordingHeadFileName),
		file:       file,
		writer:     writer,
	}
	if err := validateOpenLocalRecordingFile(active.path, file); err != nil {
		return nil, err
	}
	this.active[active.id] = active
	closeFile = false
	return active, nil
}

func (this *LocalCastZstdRepository) Close() error {
	if this == nil {
		return nil
	}
	this.mutex.Lock()
	if this.closed {
		this.mutex.Unlock()
		return nil
	}
	this.closed = true
	active := make([]*ActiveCastZstd, 0, len(this.active))
	for _, current := range this.active {
		active = append(active, current)
	}
	this.active = make(map[Id]*ActiveCastZstd)
	this.mutex.Unlock()
	result := this.poisoned
	for _, current := range active {
		result = errors.Join(result, current.close(false))
	}
	result = errors.Join(result, this.processLock.Close())
	return result
}

func (this *ActiveCastZstd) WriteOutput(elapsed time.Duration, stream OutputStream, data []byte) error {
	return this.withWriter(func(writer *CastZstdWriter) error { return writer.WriteOutput(elapsed, stream, data) })
}

func (this *ActiveCastZstd) WriteResize(elapsed time.Duration, columns, rows uint32) error {
	return this.withWriter(func(writer *CastZstdWriter) error { return writer.WriteResize(elapsed, columns, rows) })
}

func (this *ActiveCastZstd) WriteMarker(elapsed time.Duration, label string) error {
	return this.withWriter(func(writer *CastZstdWriter) error { return writer.WriteMarker(elapsed, label) })
}

func (this *ActiveCastZstd) Checkpoint() error {
	if this == nil {
		return fmt.Errorf("nil active recording")
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.checkpointLocked()
}

func (this *ActiveCastZstd) Seal(elapsed time.Duration, result CastResult, exitStatus *uint32) (CastZstdSummary, error) {
	if this == nil {
		return CastZstdSummary{}, fmt.Errorf("nil active recording")
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if err := this.validateLocked(); err != nil {
		return CastZstdSummary{}, err
	}
	summary, err := this.writer.Seal(elapsed, result, exitStatus)
	if err != nil {
		return CastZstdSummary{}, this.writerError(err)
	}
	if err := this.file.Sync(); err != nil {
		return CastZstdSummary{}, this.poison(fmt.Errorf("cannot synchronize sealed recording: %w", err))
	}
	size, err := this.file.Seek(0, io.SeekEnd)
	if err != nil {
		return CastZstdSummary{}, this.poison(err)
	}
	options := this.repository.options
	options.Context = context.Background()
	if _, err := VerifyCastZstd(this.file, size, options); err != nil {
		return CastZstdSummary{}, this.poison(fmt.Errorf("cannot verify sealed recording: %w", err))
	}
	headPayload, err := loadLocalRecordingHead(this.headPath)
	if err != nil {
		return CastZstdSummary{}, this.poison(err)
	}
	head, err := decodeCastZstdHead(headPayload)
	if err != nil {
		return CastZstdSummary{}, this.poison(err)
	}
	if err := sealLocalRecordingFile(this.path, this.file); err != nil {
		return CastZstdSummary{}, this.poison(err)
	}
	sealedInfo, err := this.file.Stat()
	if err != nil {
		return CastZstdSummary{}, this.poison(err)
	}
	if err := this.file.Close(); err != nil {
		return CastZstdSummary{}, this.poison(err)
	}
	this.closed = true
	target := filepath.Join(this.repository.sealedPath, this.id.String()+localRecordingSealedSuffix)
	if err := publishLocalRecordingFile(this.path, target); err != nil {
		return CastZstdSummary{}, this.poison(fmt.Errorf("cannot publish sealed recording: %w", err))
	}
	if _, err := verifyPublishedLocalRecording(target, sealedInfo, options, &head); err != nil {
		return CastZstdSummary{}, this.poison(fmt.Errorf("cannot verify published recording: %w", err))
	}
	if err := os.Remove(this.headPath); err != nil {
		return CastZstdSummary{}, this.poison(fmt.Errorf("cannot remove active recording head: %w", err))
	}
	if err := os.Remove(this.directory); err != nil {
		return CastZstdSummary{}, this.poison(fmt.Errorf("cannot remove active recording directory: %w", err))
	}
	if err := syncLocalRecordingDirectory(this.repository.activePath); err != nil {
		return CastZstdSummary{}, this.poison(err)
	}
	this.sealed = true
	this.repository.removeActive(this.id)
	return summary, nil
}

func (this *ActiveCastZstd) Close() error {
	return this.close(true)
}

func (this *ActiveCastZstd) close(remove bool) error {
	if this == nil {
		return nil
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return this.poisoned
	}
	result := this.poisoned
	if this.poisoned == nil && !this.sealed {
		result = this.checkpointForCloseLocked()
	}
	result = errors.Join(result, this.file.Close())
	this.closed = true
	if remove {
		this.repository.removeActive(this.id)
	}
	return result
}

func (this *ActiveCastZstd) withWriter(action func(*CastZstdWriter) error) error {
	if this == nil {
		return fmt.Errorf("nil active recording")
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if err := this.validateLocked(); err != nil {
		return err
	}
	if err := action(this.writer); err != nil {
		return this.writerError(err)
	}
	return nil
}

func (this *ActiveCastZstd) checkpointLocked() error {
	if err := this.validateLocked(); err != nil {
		return err
	}
	return this.persistCheckpointLocked()
}

func (this *ActiveCastZstd) checkpointForCloseLocked() error {
	if err := this.validateStorageLocked(); err != nil {
		return err
	}
	return this.persistCheckpointLocked()
}

func (this *ActiveCastZstd) persistCheckpointLocked() error {
	checkpoint, err := this.writer.Checkpoint()
	if err != nil {
		return this.poison(err)
	}
	if err := this.file.Sync(); err != nil {
		return this.poison(fmt.Errorf("cannot synchronize active recording: %w", err))
	}
	payload, err := encodeCastZstdHead(checkpoint)
	if err != nil {
		return this.poison(err)
	}
	if err := writeLocalRecordingHead(this.directory, payload); err != nil {
		return this.poison(fmt.Errorf("cannot persist active recording head: %w", err))
	}
	return nil
}

func (this *ActiveCastZstd) validateLocked() error {
	if err := this.repository.failure(); err != nil {
		return err
	}
	return this.validateStorageLocked()
}

func (this *ActiveCastZstd) validateStorageLocked() error {
	if this.closed {
		return fmt.Errorf("active recording is closed")
	}
	if this.poisoned != nil {
		return this.poisoned
	}
	if err := validateLocalRecordingLock(this.repository.processLock, this.repository.lockPath); err != nil {
		return this.poison(err)
	}
	if err := validateOpenLocalRecordingFile(this.path, this.file); err != nil {
		return this.poison(err)
	}
	return nil
}

func (this *ActiveCastZstd) poison(err error) error {
	if this.poisoned == nil {
		this.poisoned = err
	}
	return err
}

func (this *ActiveCastZstd) writerError(err error) error {
	if this.writer != nil && ((this.writer.cast != nil && this.writer.cast.poisoned != nil) || (this.writer.sink != nil && this.writer.sink.poisoned != nil)) {
		return this.poison(err)
	}
	return err
}

func (this *LocalCastZstdRepository) removeActive(id Id) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	delete(this.active, id)
}

func (this *LocalCastZstdRepository) validateRoot() error {
	allowed := map[string]bool{
		localRecordingLockFileName:        true,
		localRecordingWorkDirectory:       true,
		localRecordingQuarantineDirectory: true,
		localRecordingActiveDirectory:     true,
		localRecordingSealedDirectory:     true,
	}
	entries, err := os.ReadDir(this.directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return fmt.Errorf("local recording repository contains unsupported entry %q", entry.Name())
		}
	}
	return nil
}

func (this *LocalCastZstdRepository) recoverWorkDirectories() error {
	entries, err := os.ReadDir(this.workPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := strings.TrimSuffix(entry.Name(), ".tmp")
		var id Id
		if name == entry.Name() || id.UnmarshalText([]byte(name)) != nil || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("recording work directory contains unsupported entry %q", entry.Name())
		}
		path := filepath.Join(this.workPath, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if err := secureLocalRecordingDirectory(path, info); err != nil {
			return err
		}
		children, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		if len(children) == 0 {
			if err := os.Remove(path); err != nil {
				return err
			}
			continue
		}
		if err := prepareInterruptedLocalRecordingHead(path); err != nil {
			quarantine := filepath.Join(this.quarantinePath, entry.Name())
			if _, inspectErr := os.Lstat(quarantine); inspectErr == nil {
				return fmt.Errorf("recording quarantine path already exists for %s", id)
			} else if !errors.Is(inspectErr, fs.ErrNotExist) {
				return inspectErr
			}
			if moveErr := publishLocalRecordingDirectory(path, quarantine); moveErr != nil {
				return errors.Join(err, moveErr)
			}
			if syncErr := syncLocalRecordingDirectory(this.quarantinePath); syncErr != nil {
				return syncErr
			}
			if syncErr := syncLocalRecordingDirectory(this.workPath); syncErr != nil {
				return syncErr
			}
			continue
		}
		activeDirectory := filepath.Join(this.activePath, id.String())
		if _, err := os.Lstat(activeDirectory); err == nil {
			return fmt.Errorf("recording work and active directories both exist for %s", id)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := publishLocalRecordingDirectory(path, activeDirectory); err != nil {
			return err
		}
		if err := syncLocalRecordingDirectory(this.activePath); err != nil {
			return err
		}
		if err := syncLocalRecordingDirectory(this.workPath); err != nil {
			return err
		}
	}
	return syncLocalRecordingDirectory(this.workPath)
}

func (this *LocalCastZstdRepository) validateSealed() error {
	entries, err := os.ReadDir(this.sealedPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := strings.TrimSuffix(entry.Name(), localRecordingSealedSuffix)
		var id Id
		if name == entry.Name() || id.UnmarshalText([]byte(name)) != nil || !entry.Type().IsRegular() {
			return fmt.Errorf("sealed recording directory contains unsupported entry %q", entry.Name())
		}
		file, err := openSealedLocalRecordingFile(filepath.Join(this.sealedPath, entry.Name()))
		if err != nil {
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (this *LocalCastZstdRepository) recoverActive(ctx context.Context) error {
	entries, err := os.ReadDir(this.activePath)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	var result error
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		var id Id
		if id.UnmarshalText([]byte(entry.Name())) != nil || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("active recording directory contains unsupported entry %q", entry.Name())
		}
		if err := this.recoverActiveDirectory(id, filepath.Join(this.activePath, entry.Name())); err != nil {
			result = errors.Join(result, fmt.Errorf("cannot recover recording %s: %w", id, err))
		}
	}
	return result
}

func (this *LocalCastZstdRepository) recoverActiveDirectory(id Id, directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if err := secureLocalRecordingDirectory(directory, info); err != nil {
		return err
	}
	if err := prepareInterruptedLocalRecordingHead(directory); err != nil {
		return err
	}
	contentPath := filepath.Join(directory, localRecordingContentFileName)
	headPath := filepath.Join(directory, localRecordingHeadFileName)
	target := filepath.Join(this.sealedPath, id.String()+localRecordingSealedSuffix)
	if aliased, err := completeLocalRecordingPublishAlias(contentPath, target); err != nil {
		return err
	} else if aliased {
		return this.completePublishedRecovery(id, directory, headPath)
	}
	if _, err := os.Lstat(contentPath); errors.Is(err, fs.ErrNotExist) {
		return this.completePublishedRecovery(id, directory, headPath)
	} else if err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	if len(entries) != 2 {
		return fmt.Errorf("active recording directory contains %d entries instead of two", len(entries))
	}
	headPayload, err := loadLocalRecordingHead(headPath)
	if err != nil {
		return err
	}
	head, err := decodeCastZstdHead(headPayload)
	if err != nil {
		return err
	}
	if Id(head.RecordingId) != id || head.ProducerId != this.identity.ProducerId() {
		return fmt.Errorf("active recording head identity does not match its directory")
	}
	file, err := openActiveLocalRecordingFile(contentPath)
	if err != nil {
		return err
	}
	result, recoveryErr := RecoverCastZstd(file, this.identity, head, time.Now().UTC(), this.options)
	if recoveryErr != nil {
		_ = file.Close()
		return recoveryErr
	}
	if err := sealLocalRecordingFile(contentPath, file); err != nil {
		_ = file.Close()
		return err
	}
	sealedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := this.publishRecovered(id, directory, contentPath, headPath, sealedInfo, &head); err != nil {
		return err
	}
	this.recovered = append(this.recovered, RecoveredCastZstd{
		Summary:       result.Verification.Summary,
		Truncated:     result.Truncated,
		AlreadySealed: result.AlreadySealed,
	})
	return nil
}

func (this *LocalCastZstdRepository) completePublishedRecovery(id Id, directory, headPath string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	if len(entries) > 1 || len(entries) == 1 && entries[0].Name() != localRecordingHeadFileName {
		return fmt.Errorf("published recording cleanup directory contains unexpected entries")
	}
	target := filepath.Join(this.sealedPath, id.String()+localRecordingSealedSuffix)
	file, err := openSealedLocalRecordingFile(target)
	if err != nil {
		return fmt.Errorf("active recording content is missing and sealed target is unavailable: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	var head *audit.SessionRecordingZstdHead
	if headPayload, headErr := loadLocalRecordingHead(headPath); headErr == nil {
		decoded, decodeErr := decodeCastZstdHead(headPayload)
		if decodeErr != nil {
			_ = file.Close()
			return decodeErr
		}
		if Id(decoded.RecordingId) != id || decoded.ProducerId != this.identity.ProducerId() {
			_ = file.Close()
			return fmt.Errorf("published recording head identity does not match its directory")
		}
		head = &decoded
	} else if len(entries) != 0 {
		_ = file.Close()
		return fmt.Errorf("active recording content and head are inconsistent: %w", headErr)
	}
	verification, verifyErr := verifyPublishedCastZstd(file, info.Size(), this.options, head)
	closeErr := file.Close()
	if verifyErr != nil {
		return verifyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if verification.Summary.RecordingId != id {
		return fmt.Errorf("sealed recording identity does not match its active directory")
	}
	if err := os.Remove(headPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Remove(directory); err != nil {
		return err
	}
	return syncLocalRecordingDirectory(this.activePath)
}

func (this *LocalCastZstdRepository) publishRecovered(id Id, directory, contentPath, headPath string, sealedInfo os.FileInfo, head *audit.SessionRecordingZstdHead) error {
	target := filepath.Join(this.sealedPath, id.String()+localRecordingSealedSuffix)
	if err := publishLocalRecordingFile(contentPath, target); err != nil {
		return err
	}
	if _, err := verifyPublishedLocalRecording(target, sealedInfo, this.options, head); err != nil {
		return err
	}
	if err := os.Remove(headPath); err != nil {
		return err
	}
	if err := os.Remove(directory); err != nil {
		return err
	}
	return syncLocalRecordingDirectory(this.activePath)
}

func verifyPublishedLocalRecording(path string, expected os.FileInfo, options CastZstdVerifyOptions, head *audit.SessionRecordingZstdHead) (*CastZstdVerification, error) {
	file, err := openSealedLocalRecordingFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(expected, info) {
		return nil, fmt.Errorf("published recording does not match its verified source")
	}
	return verifyPublishedCastZstd(file, info.Size(), options, head)
}

func verifyPublishedCastZstd(file *os.File, size int64, options CastZstdVerifyOptions, head *audit.SessionRecordingZstdHead) (*CastZstdVerification, error) {
	if head != nil {
		stream, err := newCastZstdStreamForRecovery(file, size, options, head, true)
		if err != nil {
			return nil, err
		}
		_, scanErr := io.Copy(io.Discard, stream)
		stream.close()
		if scanErr != nil {
			return nil, scanErr
		}
		if stream.seal == nil {
			return nil, fmt.Errorf("published Cast Zstandard container has no seal")
		}
	}
	return VerifyCastZstd(file, size, options)
}

func verifyActiveCastZstdCheckpoint(file *os.File, size int64, options CastZstdVerifyOptions, head audit.SessionRecordingZstdHead) error {
	stream, err := newCastZstdStreamForRecovery(file, size, options, &head, true)
	if err != nil {
		return err
	}
	defer stream.close()
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return err
	}
	if stream.seal != nil || stream.incompleteTail || stream.validEnd != size {
		return fmt.Errorf("new active recording has an unexpected container state")
	}
	return nil
}

func (this *LocalCastZstdRepository) poisonLocked(err error) error {
	if this.poisoned == nil {
		this.poisoned = err
	}
	return err
}

func (this *LocalCastZstdRepository) failure() error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.poisoned
}
