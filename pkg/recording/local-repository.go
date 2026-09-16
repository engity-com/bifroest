package recording

import (
	"context"
	stderrors "errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	localLockFileName        = ".bifroest-recording.lock"
	localFormatFileName      = ".bifroest-recording-format"
	localFormatTempFileName  = ".bifroest-recording-format.tmp"
	localWorkDirectory       = ".bifroest-work"
	localActiveDirectory     = "active"
	localSealedDirectory     = "sealed"
	localQuarantineDirectory = "quarantine"
	localHeadFileName        = "head.json"
	localHeadTempFileName    = "head.tmp"
)

type localWriter[Head, Summary any] interface {
	WriteOutput(time.Duration, OutputStream, []byte) error
	WriteResize(time.Duration, uint32, uint32) error
	WriteMarker(time.Duration, string) error
	Checkpoint() (Head, error)
	Seal(time.Duration, CastResult, *uint32) (Summary, error)
	replaceOutput(io.Writer) error
	repositoryFailure() error
	release() error
}

type localFormat[Head, Summary any] interface {
	key() string
	contentFileName() string
	sealedSuffix() string
	maximumHeadBytes() int64
	newWriter(io.Writer, CastHeader, CastMetadata, int) (localWriter[Head, Summary], error)
	encodeHead(Head) ([]byte, error)
	decodeHead([]byte) (Head, error)
	headId(Head) Id
	headProducerId(Head) audit.ProducerId
	headPrefixBytes(Head) uint64
	preflight(*os.File, int64, Head, context.Context) error
	verifyActiveCheckpoint(*os.File, int64, Head, context.Context) error
	verifyWorkCheckpoint(*os.File, int64, Head, context.Context) error
	recover(RecoveryFile, Head, time.Time, context.Context) (localRecovery[Summary], error)
	verifyPublished(*os.File, int64, *Head, context.Context) (Summary, error)
	summaryId(Summary) Id
}

type localRecovery[Summary any] struct {
	summary       Summary
	truncated     bool
	alreadySealed bool
}

type validatedLocalWork[Head any] struct {
	head     Head
	file     *os.File
	fileInfo os.FileInfo
}

func (this *validatedLocalWork[Head]) close(cause error) error {
	if this == nil || this.file == nil {
		return cause
	}
	closeErr := this.file.Close()
	this.file = nil
	if closeErr != nil {
		closeErr = errors.System.Newf("cannot close recording work content: %w", closeErr)
	}
	return stderrors.Join(cause, closeErr)
}

type invalidLocalArtifactError struct {
	cause error
}

type localTrackingReaderAt struct {
	source  io.ReaderAt
	size    int64
	failure error
}

func (this *invalidLocalArtifactError) Error() string {
	return this.cause.Error()
}

func (this *invalidLocalArtifactError) Unwrap() error {
	return this.cause
}

func invalidLocalArtifact(err error) error {
	if err == nil {
		return nil
	}
	return &invalidLocalArtifactError{cause: err}
}

func isInvalidLocalArtifact(err error) bool {
	var target *invalidLocalArtifactError
	return stderrors.As(err, &target)
}

func (this *localTrackingReaderAt) ReadAt(target []byte, offset int64) (int, error) {
	read, err := this.source.ReadAt(target, offset)
	withinSource := offset >= 0 && offset <= this.size && int64(len(target)) <= this.size-offset
	if this.failure == nil && withinSource {
		if err != nil {
			this.failure = err
		} else if read != len(target) {
			this.failure = io.ErrUnexpectedEOF
		}
	}
	return read, err
}

type localRepository[Head, Summary any] struct {
	mutex          sync.Mutex
	directory      string
	activePath     string
	sealedPath     string
	workPath       string
	quarantinePath string
	lockPath       string
	identity       *audit.Identity
	format         localFormat[Head, Summary]
	quota          *localQuota
	processLock    *localProcessLock
	active         map[Id]*localActive[Head, Summary]
	recovered      []localRecovery[Summary]
	closed         bool
	poisoned       error
}

type localActive[Head, Summary any] struct {
	mutex      sync.Mutex
	repository *localRepository[Head, Summary]
	id         Id
	directory  string
	path       string
	headPath   string
	file       *os.File
	writer     localWriter[Head, Summary]
	poisoned   error
	closeErr   error
	closed     bool
	sealed     bool
}

func newLocalRepository[Head, Summary any](ctx context.Context, directory string, identity *audit.Identity, format localFormat[Head, Summary], options LocalRepositoryOptions) (*localRepository[Head, Summary], error) {
	if options.MaximumSpoolBytes < 1 {
		return nil, errors.Config.Newf("maximum local recording spool bytes must be positive")
	}
	if identity == nil || identity.PublicKey() == nil {
		return nil, errors.Config.Newf("nil local recording identity")
	}
	if format == nil {
		return nil, errors.Config.Newf("nil local recording format")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	canonical, err := canonicalLocalDirectory(strings.TrimSpace(directory))
	if err != nil {
		return nil, errors.Config.Newf("cannot resolve local recording directory: %w", err)
	}
	if err := ensureLocalDirectory(canonical); err != nil {
		return nil, errors.System.Newf("cannot prepare local recording directory %q: %w", canonical, err)
	}
	lockPath := filepath.Join(canonical, localLockFileName)
	processLock, err := acquireLocalProcessLock(lockPath)
	if err != nil {
		return nil, errors.System.Newf("cannot lock local recording repository %q: %w", canonical, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = processLock.Close()
		}
	}()
	if err := validateLocalLock(processLock, lockPath); err != nil {
		return nil, err
	}
	result := &localRepository[Head, Summary]{
		directory:      canonical,
		activePath:     filepath.Join(canonical, localActiveDirectory),
		sealedPath:     filepath.Join(canonical, localSealedDirectory),
		workPath:       filepath.Join(canonical, localWorkDirectory),
		quarantinePath: filepath.Join(canonical, localQuarantineDirectory),
		lockPath:       lockPath,
		identity:       identity,
		format:         format,
		processLock:    processLock,
		active:         make(map[Id]*localActive[Head, Summary]),
	}
	result.quota, err = newLocalQuota(options.MaximumSpoolBytes, result.workPath, result.activePath, result.sealedPath, result.quarantinePath)
	if err != nil {
		return nil, err
	}
	if err := bindLocalFormat(canonical, format.key()); err != nil {
		return nil, errors.System.Newf("cannot bind local recording repository format: %w", err)
	}
	for _, path := range []string{result.activePath, result.sealedPath, result.workPath, result.quarantinePath} {
		if err := ensureLocalDirectory(path); err != nil {
			return nil, errors.System.Newf("cannot prepare local recording repository path %q: %w", path, err)
		}
	}
	if err := result.validateRoot(); err != nil {
		return nil, err
	}
	if err := result.recoverWorkDirectories(ctx); err != nil {
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

func (this *localRepository[Head, Summary]) startupRecoveries() []localRecovery[Summary] {
	if this == nil {
		return nil
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return append([]localRecovery[Summary](nil), this.recovered...)
}

func (this *localRepository[Head, Summary]) createActive(ctx context.Context, header CastHeader, metadata CastMetadata, chunkSize int) (*localActive[Head, Summary], error) {
	if this == nil {
		return nil, errors.System.Newf("nil local recording repository")
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
		return nil, errors.Config.Newf("local recording producer does not match repository identity")
	}

	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return nil, errors.System.Newf("local recording repository is closed")
	}
	if this.poisoned != nil {
		return nil, this.poisoned
	}
	if err := validateLocalLock(this.processLock, this.lockPath); err != nil {
		return nil, err
	}
	if _, exists := this.active[metadata.RecordingId]; exists {
		return nil, errors.System.Newf("recording %s is already active", metadata.RecordingId)
	}
	activeDirectory := filepath.Join(this.activePath, metadata.RecordingId.String())
	sealedPath := filepath.Join(this.sealedPath, metadata.RecordingId.String()+this.format.sealedSuffix())
	workDirectory := filepath.Join(this.workPath, metadata.RecordingId.String()+".tmp")
	for _, path := range []string{activeDirectory, sealedPath, workDirectory} {
		if _, err := os.Lstat(path); err == nil {
			return nil, errors.System.Newf("recording path %q already exists", path)
		} else if !stderrors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	if err := ensureLocalDirectory(workDirectory); err != nil {
		return nil, errors.System.Newf("cannot create recording staging directory: %w", err)
	}
	removeWork := true
	defer func() {
		if removeWork {
			_ = removeAccountedLocalTree(workDirectory, this.quota)
		}
	}()
	contentPath := filepath.Join(workDirectory, this.format.contentFileName())
	file, err := createLocalFile(contentPath)
	if err != nil {
		return nil, errors.System.Newf("cannot create active recording: %w", err)
	}
	closeFile := true
	defer func() {
		if closeFile {
			_ = file.Close()
		}
	}()
	writer, err := this.format.newWriter(accountLocalFile(file, this.quota), header, metadata, chunkSize)
	if err != nil {
		return nil, err
	}
	checkpoint, err := writer.Checkpoint()
	if err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, errors.System.Newf("cannot synchronize initial recording: %w", err)
	}
	head, err := this.format.encodeHead(checkpoint)
	if err != nil {
		return nil, err
	}
	if err := writeLocalHead(workDirectory, head, this.quota); err != nil {
		return nil, errors.System.Newf("cannot persist initial recording head: %w", err)
	}
	if err := syncLocalDirectory(workDirectory); err != nil {
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
	if err := publishLocalDirectory(workDirectory, activeDirectory); err != nil {
		return nil, errors.System.Newf("cannot publish active recording: %w", err)
	}
	removeWork = false
	if err := syncLocalDirectory(this.activePath); err != nil {
		return nil, this.poisonLocked(err)
	}
	if err := syncLocalDirectory(this.workPath); err != nil {
		return nil, this.poisonLocked(err)
	}
	contentPath = filepath.Join(activeDirectory, this.format.contentFileName())
	file, err = openActiveLocalFile(contentPath)
	if err != nil {
		return nil, this.poisonLocked(err)
	}
	closeFile = true
	reopenedInfo, err := file.Stat()
	if err != nil || !os.SameFile(originalInfo, reopenedInfo) || reopenedInfo.Size() != int64(this.format.headPrefixBytes(checkpoint)) {
		return nil, this.poisonLocked(errors.System.Newf("active recording changed while being published"))
	}
	if err := this.format.verifyActiveCheckpoint(file, reopenedInfo.Size(), checkpoint, context.Background()); err != nil {
		return nil, this.poisonLocked(err)
	}
	if err := writer.replaceOutput(accountLocalFile(file, this.quota)); err != nil {
		return nil, this.poisonLocked(err)
	}
	active := &localActive[Head, Summary]{
		repository: this,
		id:         metadata.RecordingId,
		directory:  activeDirectory,
		path:       contentPath,
		headPath:   filepath.Join(activeDirectory, localHeadFileName),
		file:       file,
		writer:     writer,
	}
	if err := validateOpenLocalFile(active.path, file); err != nil {
		return nil, err
	}
	this.active[active.id] = active
	closeFile = false
	return active, nil
}

func (this *localRepository[Head, Summary]) close() error {
	if this == nil {
		return nil
	}
	this.mutex.Lock()
	if this.closed {
		this.mutex.Unlock()
		return nil
	}
	this.closed = true
	active := make([]*localActive[Head, Summary], 0, len(this.active))
	for _, current := range this.active {
		active = append(active, current)
	}
	this.active = make(map[Id]*localActive[Head, Summary])
	this.mutex.Unlock()
	result := this.poisoned
	for _, current := range active {
		result = stderrors.Join(result, current.close(false))
	}
	result = stderrors.Join(result, this.processLock.Close())
	return result
}

func (this *localActive[Head, Summary]) writeOutput(elapsed time.Duration, stream OutputStream, data []byte) error {
	return this.withWriter(func(writer localWriter[Head, Summary]) error {
		return writer.WriteOutput(elapsed, stream, data)
	})
}

func (this *localActive[Head, Summary]) writeResize(elapsed time.Duration, columns, rows uint32) error {
	return this.withWriter(func(writer localWriter[Head, Summary]) error {
		return writer.WriteResize(elapsed, columns, rows)
	})
}

func (this *localActive[Head, Summary]) writeMarker(elapsed time.Duration, label string) error {
	return this.withWriter(func(writer localWriter[Head, Summary]) error { return writer.WriteMarker(elapsed, label) })
}

func (this *localActive[Head, Summary]) checkpoint() error {
	if this == nil {
		return errors.System.Newf("nil active recording")
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.checkpointLocked()
}

func (this *localActive[Head, Summary]) seal(elapsed time.Duration, result CastResult, exitStatus *uint32) (Summary, error) {
	var zero Summary
	if this == nil {
		return zero, errors.System.Newf("nil active recording")
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if err := this.validateLocked(); err != nil {
		return zero, err
	}
	summary, err := this.writer.Seal(elapsed, result, exitStatus)
	if err != nil {
		return zero, this.writerError(err)
	}
	if err := this.file.Sync(); err != nil {
		return zero, this.poison(errors.System.Newf("cannot synchronize sealed recording: %w", err))
	}
	size, err := this.file.Seek(0, io.SeekEnd)
	if err != nil {
		return zero, this.poison(err)
	}
	if _, err := this.repository.format.verifyPublished(this.file, size, nil, context.Background()); err != nil {
		return zero, this.poison(errors.System.Newf("cannot verify sealed recording: %w", err))
	}
	headPayload, err := loadLocalHead(this.headPath, this.repository.format.maximumHeadBytes())
	if err != nil {
		return zero, this.poison(err)
	}
	head, err := this.repository.format.decodeHead(headPayload)
	if err != nil {
		return zero, this.poison(err)
	}
	if err := sealLocalFile(this.path, this.file); err != nil {
		return zero, this.poison(err)
	}
	sealedInfo, err := this.file.Stat()
	if err != nil {
		return zero, this.poison(err)
	}
	if err := this.file.Close(); err != nil {
		return zero, this.poison(err)
	}
	this.closed = true
	target := filepath.Join(this.repository.sealedPath, this.id.String()+this.repository.format.sealedSuffix())
	if err := publishLocalFile(this.path, target); err != nil {
		return zero, this.poison(errors.System.Newf("cannot publish sealed recording: %w", err))
	}
	if _, err := this.repository.verifyPublished(target, sealedInfo, &head, context.Background()); err != nil {
		return zero, this.poison(errors.System.Newf("cannot verify published recording: %w", err))
	}
	if err := removeAccountedLocalFile(this.headPath, this.repository.quota); err != nil {
		return zero, this.poison(errors.System.Newf("cannot remove active recording head: %w", err))
	}
	if err := os.Remove(this.directory); err != nil {
		return zero, this.poison(errors.System.Newf("cannot remove active recording directory: %w", err))
	}
	if err := syncLocalDirectory(this.repository.activePath); err != nil {
		return zero, this.poison(err)
	}
	this.sealed = true
	this.repository.removeActive(this.id)
	return summary, nil
}

func (this *localActive[Head, Summary]) closeAndRemove() error {
	return this.close(true)
}

func (this *localActive[Head, Summary]) close(remove bool) error {
	if this == nil {
		return nil
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		if this.closeErr != nil {
			return this.closeErr
		}
		return this.poisoned
	}
	result := this.poisoned
	if this.poisoned == nil && !this.sealed {
		result = this.checkpointForCloseLocked()
	}
	if this.writer != nil {
		result = stderrors.Join(result, this.writer.release())
	}
	if this.file != nil {
		result = stderrors.Join(result, this.file.Close())
	}
	this.closeErr = result
	this.closed = true
	if remove {
		this.repository.removeActive(this.id)
	}
	return result
}

func (this *localActive[Head, Summary]) withWriter(action func(localWriter[Head, Summary]) error) error {
	if this == nil {
		return errors.System.Newf("nil active recording")
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

func (this *localActive[Head, Summary]) checkpointLocked() error {
	if err := this.validateLocked(); err != nil {
		return err
	}
	return this.persistCheckpointLocked()
}

func (this *localActive[Head, Summary]) checkpointForCloseLocked() error {
	if err := this.validateStorageLocked(); err != nil {
		return err
	}
	return this.persistCheckpointLocked()
}

func (this *localActive[Head, Summary]) persistCheckpointLocked() error {
	checkpoint, err := this.writer.Checkpoint()
	if err != nil {
		return this.poison(err)
	}
	if err := this.file.Sync(); err != nil {
		return this.poison(errors.System.Newf("cannot synchronize active recording: %w", err))
	}
	payload, err := this.repository.format.encodeHead(checkpoint)
	if err != nil {
		return this.poison(err)
	}
	if err := writeLocalHead(this.directory, payload, this.repository.quota); err != nil {
		return this.poison(errors.System.Newf("cannot persist active recording head: %w", err))
	}
	return nil
}

func (this *localActive[Head, Summary]) validateLocked() error {
	if err := this.repository.failure(); err != nil {
		return err
	}
	return this.validateStorageLocked()
}

func (this *localActive[Head, Summary]) validateStorageLocked() error {
	if this.closed {
		return errors.System.Newf("active recording is closed")
	}
	if this.poisoned != nil {
		return this.poisoned
	}
	if err := validateLocalLock(this.repository.processLock, this.repository.lockPath); err != nil {
		return this.poison(err)
	}
	if err := validateOpenLocalFile(this.path, this.file); err != nil {
		return this.poison(err)
	}
	return nil
}

func (this *localActive[Head, Summary]) poison(err error) error {
	if this.poisoned == nil {
		this.poisoned = err
	}
	return err
}

func (this *localActive[Head, Summary]) writerError(err error) error {
	if this.writer != nil && this.writer.repositoryFailure() != nil {
		return this.poison(err)
	}
	return err
}

func (this *localRepository[Head, Summary]) removeActive(id Id) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	delete(this.active, id)
}

func (this *localRepository[Head, Summary]) validateRoot() error {
	allowed := map[string]bool{
		localLockFileName:        true,
		localFormatFileName:      true,
		localFormatTempFileName:  true,
		localWorkDirectory:       true,
		localQuarantineDirectory: true,
		localActiveDirectory:     true,
		localSealedDirectory:     true,
	}
	entries, err := os.ReadDir(this.directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return errors.Config.Newf("local recording repository contains unsupported entry %q", entry.Name())
		}
	}
	return nil
}

func (this *localRepository[Head, Summary]) recoverWorkDirectories(ctx context.Context) error {
	entries, err := os.ReadDir(this.workPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		name := strings.TrimSuffix(entry.Name(), ".tmp")
		var id Id
		if name == entry.Name() || id.UnmarshalText([]byte(name)) != nil || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.Config.Newf("recording work directory contains unsupported entry %q", entry.Name())
		}
		path := filepath.Join(this.workPath, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if err := secureLocalDirectory(path, info); err != nil {
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
		validated, err := this.validateWorkDirectory(ctx, id, path)
		if err != nil {
			if !isInvalidLocalArtifact(err) {
				return err
			}
			quarantine := filepath.Join(this.quarantinePath, entry.Name())
			if _, inspectErr := os.Lstat(quarantine); inspectErr == nil {
				return errors.System.Newf("recording quarantine path already exists for %s", id)
			} else if !stderrors.Is(inspectErr, fs.ErrNotExist) {
				return inspectErr
			}
			if moveErr := publishLocalDirectory(path, quarantine); moveErr != nil {
				return stderrors.Join(err, moveErr)
			}
			if syncErr := syncLocalDirectory(this.quarantinePath); syncErr != nil {
				return syncErr
			}
			if syncErr := syncLocalDirectory(this.workPath); syncErr != nil {
				return syncErr
			}
			continue
		}
		activeDirectory := filepath.Join(this.activePath, id.String())
		if err := this.publishValidatedWork(ctx, path, activeDirectory, validated); err != nil {
			return err
		}
	}
	return syncLocalDirectory(this.workPath)
}

func (this *localRepository[Head, Summary]) validateWorkDirectory(ctx context.Context, id Id, directory string) (*validatedLocalWork[Head], error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, errors.System.Newf("cannot inspect recording work directory: %w", err)
	}
	if err := this.validateWorkDirectoryEntries(entries, true); err != nil {
		return nil, err
	}
	head, err := this.prepareInterruptedWorkHead(directory)
	if err != nil {
		return nil, err
	}
	if this.format.headId(head) != id || this.format.headProducerId(head) != this.identity.ProducerId() {
		return nil, invalidLocalArtifact(errors.System.Newf("recording work head identity does not match its directory"))
	}
	entries, err = os.ReadDir(directory)
	if err != nil {
		return nil, errors.System.Newf("cannot inspect recording work directory: %w", err)
	}
	if err := this.validateWorkDirectoryEntries(entries, false); err != nil {
		return nil, err
	}
	contentPath := filepath.Join(directory, this.format.contentFileName())
	if err := this.preflightWorkContent(contentPath, head, ctx); err != nil {
		return nil, err
	}
	file, err := openActiveLocalFile(contentPath)
	if err != nil {
		err = errors.System.Newf("cannot open recording work content: %w", err)
		if errors.Config.IsErr(err) {
			err = invalidLocalArtifact(err)
		}
		return nil, err
	}
	validated := &validatedLocalWork[Head]{head: head, file: file}
	validated.fileInfo, err = file.Stat()
	if err != nil {
		return nil, validated.close(errors.System.Newf("cannot inspect recording work content: %w", err))
	}
	if err := this.format.verifyWorkCheckpoint(file, validated.fileInfo.Size(), head, ctx); err != nil {
		return nil, validated.close(err)
	}
	return validated, nil
}

func (this *localRepository[Head, Summary]) preflightWorkContent(path string, head Head, ctx context.Context) (result error) {
	file, err := openReadOnlyLocalFile(path)
	if err != nil {
		if errors.Config.IsErr(err) {
			err = invalidLocalArtifact(err)
		}
		return errors.System.Newf("cannot safely open recording work content: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			result = stderrors.Join(result, errors.System.Newf("cannot close recording work preflight: %w", closeErr))
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return errors.System.Newf("cannot inspect recording work content: %w", err)
	}
	return this.format.preflight(file, info.Size(), head, ctx)
}

func (this *localRepository[Head, Summary]) publishValidatedWork(ctx context.Context, source, target string, validated *validatedLocalWork[Head]) (result error) {
	defer func() {
		result = validated.close(result)
	}()
	if _, err := os.Lstat(target); err == nil {
		return errors.System.Newf("recording work and active directories both exist for %q", target)
	} else if !stderrors.Is(err, fs.ErrNotExist) {
		return errors.System.Newf("cannot inspect recording active path: %w", err)
	}
	if err := publishLocalDirectory(source, target); err != nil {
		return errors.System.Newf("cannot publish recording work directory: %w", err)
	}
	if err := this.verifyPublishedWork(ctx, target, validated); err != nil {
		return err
	}
	if err := syncLocalDirectory(this.activePath); err != nil {
		return errors.System.Newf("cannot synchronize recording active directory: %w", err)
	}
	if err := syncLocalDirectory(this.workPath); err != nil {
		return errors.System.Newf("cannot synchronize recording work directory: %w", err)
	}
	return nil
}

func (this *localRepository[Head, Summary]) verifyPublishedWork(ctx context.Context, directory string, validated *validatedLocalWork[Head]) (result error) {
	if validated == nil || validated.file == nil || validated.fileInfo == nil {
		return errors.System.Newf("nil validated recording work")
	}
	path := filepath.Join(directory, this.format.contentFileName())
	file, err := openActiveLocalFile(path)
	if err != nil {
		return errors.System.Newf("cannot reopen published recording work content: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			result = stderrors.Join(result, errors.System.Newf("cannot close published recording work content: %w", closeErr))
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return errors.System.Newf("cannot inspect published recording work content: %w", err)
	}
	if !os.SameFile(validated.fileInfo, info) {
		return errors.System.Newf("published recording work content does not match its validated source")
	}
	if info.Size() < 0 || uint64(info.Size()) != this.format.headPrefixBytes(validated.head) {
		return errors.System.Newf("published recording work content does not match its checkpoint size")
	}
	if err := this.format.verifyActiveCheckpoint(file, info.Size(), validated.head, ctx); err != nil {
		return errors.System.Newf("cannot verify published recording work checkpoint: %w", err)
	}
	return nil
}

func (this *localRepository[Head, Summary]) validateWorkDirectoryEntries(entries []os.DirEntry, allowTemporary bool) error {
	minimum, maximum := 2, 2
	if allowTemporary {
		maximum = 3
	}
	if len(entries) < minimum || len(entries) > maximum {
		return invalidLocalArtifact(errors.Config.Newf("recording work directory does not contain exactly its head and content"))
	}
	names := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return invalidLocalArtifact(errors.Config.Newf("recording work directory entry %q is not a regular file", entry.Name()))
		}
		names[entry.Name()] = true
	}
	if !names[this.format.contentFileName()] || !names[localHeadFileName] && (!allowTemporary || !names[localHeadTempFileName]) {
		return invalidLocalArtifact(errors.Config.Newf("recording work directory does not contain exactly its head and content"))
	}
	for name := range names {
		if name != this.format.contentFileName() && name != localHeadFileName && (!allowTemporary || name != localHeadTempFileName) {
			return invalidLocalArtifact(errors.Config.Newf("recording work directory contains unsupported entry %q", name))
		}
	}
	return nil
}

func (this *localRepository[Head, Summary]) prepareInterruptedWorkHead(directory string) (Head, error) {
	var result Head
	err := prepareInterruptedLocalHead(directory, this.format.maximumHeadBytes(), this.quota, func(payload []byte) error {
		decoded, decodeErr := this.format.decodeHead(payload)
		if decodeErr != nil {
			return invalidLocalArtifact(decodeErr)
		}
		result = decoded
		return nil
	})
	if err != nil && !isInvalidLocalArtifact(err) && errors.Config.IsErr(err) {
		err = invalidLocalArtifact(err)
	}
	return result, err
}

func (this *localRepository[Head, Summary]) prepareInterruptedHead(directory string) (Head, error) {
	var result Head
	err := prepareInterruptedLocalHead(directory, this.format.maximumHeadBytes(), this.quota, func(payload []byte) error {
		decoded, decodeErr := this.format.decodeHead(payload)
		if decodeErr == nil {
			result = decoded
		}
		return decodeErr
	})
	return result, err
}

func (this *localRepository[Head, Summary]) validateSealed() error {
	entries, err := os.ReadDir(this.sealedPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := strings.TrimSuffix(entry.Name(), this.format.sealedSuffix())
		var id Id
		if name == entry.Name() || id.UnmarshalText([]byte(name)) != nil || !entry.Type().IsRegular() {
			return errors.Config.Newf("sealed recording directory contains unsupported entry %q", entry.Name())
		}
		file, err := openSealedLocalFile(filepath.Join(this.sealedPath, entry.Name()))
		if err != nil {
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (this *localRepository[Head, Summary]) recoverActive(ctx context.Context) error {
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
			return errors.Config.Newf("active recording directory contains unsupported entry %q", entry.Name())
		}
		if err := this.recoverActiveDirectory(ctx, id, filepath.Join(this.activePath, entry.Name())); err != nil {
			result = stderrors.Join(result, errors.System.Newf("cannot recover recording %s: %w", id, err))
		}
	}
	return result
}

func (this *localRepository[Head, Summary]) recoverActiveDirectory(ctx context.Context, id Id, directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if err := secureLocalDirectory(directory, info); err != nil {
		return err
	}
	contentPath := filepath.Join(directory, this.format.contentFileName())
	headPath := filepath.Join(directory, localHeadFileName)
	target := filepath.Join(this.sealedPath, id.String()+this.format.sealedSuffix())
	if _, err := os.Lstat(contentPath); stderrors.Is(err, fs.ErrNotExist) {
		return this.completePublishedRecovery(ctx, id, directory, headPath)
	} else if err != nil {
		return err
	}
	head, err := this.prepareInterruptedHead(directory)
	if err != nil {
		return err
	}
	if this.format.headId(head) != id || this.format.headProducerId(head) != this.identity.ProducerId() {
		return errors.System.Newf("active recording head identity does not match its directory")
	}
	if aliased, err := completeLocalPublishAlias(contentPath, target); err != nil {
		return err
	} else if aliased {
		return this.completePublishedRecovery(ctx, id, directory, headPath)
	}
	if err := this.preflightActiveContent(contentPath, head, ctx); err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	if len(entries) != 2 {
		return errors.Config.Newf("active recording directory contains %d entries instead of two", len(entries))
	}
	file, err := openActiveLocalFile(contentPath)
	if err != nil {
		return err
	}
	result, recoveryErr := this.format.recover(accountLocalFile(file, this.quota), head, time.Now().UTC(), ctx)
	if recoveryErr != nil {
		_ = file.Close()
		return recoveryErr
	}
	if err := sealLocalFile(contentPath, file); err != nil {
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
	if err := this.publishRecovered(ctx, id, directory, contentPath, headPath, sealedInfo, &head); err != nil {
		return err
	}
	this.recovered = append(this.recovered, result)
	return nil
}

func (this *localRepository[Head, Summary]) preflightActiveContent(path string, head Head, ctx context.Context) (result error) {
	file, err := openReadOnlyLocalFile(path)
	if err != nil {
		return errors.System.Newf("cannot safely open active recording content: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			result = stderrors.Join(result, errors.System.Newf("cannot close active recording preflight: %w", closeErr))
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return errors.System.Newf("cannot inspect active recording content: %w", err)
	}
	return this.format.preflight(file, info.Size(), head, ctx)
}

func (this *localRepository[Head, Summary]) completePublishedRecovery(ctx context.Context, id Id, directory, headPath string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	if len(entries) > 1 || len(entries) == 1 && entries[0].Name() != localHeadFileName {
		return errors.Config.Newf("published recording cleanup directory contains unexpected entries")
	}
	target := filepath.Join(this.sealedPath, id.String()+this.format.sealedSuffix())
	file, err := openSealedLocalFile(target)
	if err != nil {
		return errors.System.Newf("active recording content is missing and sealed target is unavailable: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	var head *Head
	if headPayload, headErr := loadLocalHead(headPath, this.format.maximumHeadBytes()); headErr == nil {
		decoded, decodeErr := this.format.decodeHead(headPayload)
		if decodeErr != nil {
			_ = file.Close()
			return decodeErr
		}
		if this.format.headId(decoded) != id || this.format.headProducerId(decoded) != this.identity.ProducerId() {
			_ = file.Close()
			return errors.System.Newf("published recording head identity does not match its directory")
		}
		head = &decoded
	} else if len(entries) != 0 {
		_ = file.Close()
		return errors.System.Newf("active recording content and head are inconsistent: %w", headErr)
	}
	summary, verifyErr := this.format.verifyPublished(file, info.Size(), head, ctx)
	closeErr := file.Close()
	if verifyErr != nil {
		return verifyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if this.format.summaryId(summary) != id {
		return errors.System.Newf("sealed recording identity does not match its active directory")
	}
	if err := removeAccountedLocalFile(headPath, this.quota); err != nil && !stderrors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Remove(directory); err != nil {
		return err
	}
	return syncLocalDirectory(this.activePath)
}

func (this *localRepository[Head, Summary]) publishRecovered(ctx context.Context, id Id, directory, contentPath, headPath string, sealedInfo os.FileInfo, head *Head) error {
	target := filepath.Join(this.sealedPath, id.String()+this.format.sealedSuffix())
	if err := publishLocalFile(contentPath, target); err != nil {
		return err
	}
	if _, err := this.verifyPublished(target, sealedInfo, head, ctx); err != nil {
		return err
	}
	if err := removeAccountedLocalFile(headPath, this.quota); err != nil {
		return err
	}
	if err := os.Remove(directory); err != nil {
		return err
	}
	return syncLocalDirectory(this.activePath)
}

func (this *localRepository[Head, Summary]) verifyPublished(path string, expected os.FileInfo, head *Head, ctx context.Context) (Summary, error) {
	var zero Summary
	file, err := openSealedLocalFile(path)
	if err != nil {
		return zero, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return zero, err
	}
	if !os.SameFile(expected, info) {
		return zero, errors.System.Newf("published recording does not match its verified source")
	}
	return this.format.verifyPublished(file, info.Size(), head, ctx)
}

func (this *localRepository[Head, Summary]) poisonLocked(err error) error {
	if this.poisoned == nil {
		this.poisoned = err
	}
	return err
}

func (this *localRepository[Head, Summary]) failure() error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.poisoned
}
