package audit

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	goerrors "errors"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	journalRecordSchema         = "bifroest.audit-record/v1"
	journalActiveFileName       = "active.journal"
	journalLockFileName         = ".bifroest.lock"
	journalFrameCommitMarker    = "BIFROEST-AUDIT\r\n"
	journalDirectoryMode        = 0700
	journalFileMode             = 0600
	journalFrameLengthSize      = 4
	journalFrameChecksumSize    = 4
	maxJournalRecordPayloadSize = 64 * 1024
	maxAuditEventNameSize       = 256
)

var (
	journalChecksumTable = crc32.MakeTable(crc32.Castagnoli)
	errJournalClosed     = errors.System.Newf("audit journal is closed")
)

type journalRecord struct {
	Schema     string     `json:"schema"`
	Id         uuid.UUID  `json:"id"`
	RecordedAt time.Time  `json:"recordedAt"`
	ProducerId ProducerId `json:"producerId"`
	Event      Event      `json:"event"`
}

type localJournalRecorder struct {
	mutex       sync.Mutex
	file        *os.File
	processLock *journalProcessLock
	activePath  string
	lockPath    string
	producerId  ProducerId
	closed      bool
	poisoned    error
	closeErr    error
}

// NewRecorder creates the configured audit recorder. Disabled audit logging
// returns a no-op recorder without inspecting the identity or filesystem.
func NewRecorder(conf *configuration.Auditlog, identity *Identity) (Recorder, error) {
	if conf == nil {
		return nil, errors.Config.Newf("nil auditlog configuration")
	}
	if !conf.Enabled {
		return NewNoopRecorder(), nil
	}
	if identity == nil || identity.ProducerId().IsZero() {
		return nil, errors.Config.Newf("nil audit identity")
	}

	journalDirectory, err := canonicalJournalDirectory(strings.TrimSpace(conf.Journal.Directory))
	if err != nil {
		return nil, err
	}
	if err := ensureJournalDirectory(journalDirectory, true); err != nil {
		return nil, errors.System.Newf("cannot prepare audit journal directory %q: %w", journalDirectory, err)
	}
	lockPath := filepath.Join(journalDirectory, journalLockFileName)
	processLock, err := acquireJournalProcessLock(lockPath, journalFileMode)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = processLock.Close()
		}
	}()

	if err := validateLockedJournalPath(processLock, lockPath); err != nil {
		return nil, err
	}
	producerDirectory := filepath.Join(journalDirectory, identity.ProducerId().String())
	if err := validateJournalRoot(journalDirectory, identity.ProducerId()); err != nil {
		return nil, err
	}
	if err := ensureJournalDirectory(producerDirectory, true); err != nil {
		return nil, errors.System.Newf("cannot prepare audit producer directory %q: %w", producerDirectory, err)
	}
	if err := validateProducerDirectory(producerDirectory); err != nil {
		return nil, err
	}

	activePath := filepath.Join(producerDirectory, journalActiveFileName)
	file, err := openActiveJournal(activePath)
	if err != nil {
		return nil, err
	}
	if err := recoverActiveJournal(file, identity.ProducerId()); err != nil {
		_ = file.Close()
		return nil, errors.System.Newf("cannot recover active audit journal %q: %w", activePath, err)
	}

	committed = true
	return &localJournalRecorder{
		file:        file,
		processLock: processLock,
		activePath:  activePath,
		lockPath:    lockPath,
		producerId:  identity.ProducerId(),
	}, nil
}

func (this *localJournalRecorder) Record(_ context.Context, event Event) error {
	if err := validateAuditEvent(event); err != nil {
		return err
	}

	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return errJournalClosed
	}
	if this.poisoned != nil {
		return this.poisoned
	}
	if err := validateLockedJournalPath(this.processLock, this.lockPath); err != nil {
		return this.poison(err)
	}
	if err := validateOpenJournalFile(this.activePath, this.file); err != nil {
		return this.poison(err)
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return errors.System.Newf("cannot generate audit record ID: %w", err)
	}
	record := journalRecord{
		Schema:     journalRecordSchema,
		Id:         id,
		RecordedAt: time.Now().UTC(),
		ProducerId: this.producerId,
		Event:      event,
	}
	frame, err := encodeJournalRecord(record)
	if err != nil {
		return err
	}
	commitOffset := len(frame) - len(journalFrameCommitMarker)
	written, err := this.file.Write(frame[:commitOffset])
	if err == nil && written != commitOffset {
		err = io.ErrShortWrite
	}
	if err != nil {
		return this.poison(errors.System.Newf("cannot append audit record: %w", err))
	}
	if err := this.file.Sync(); err != nil {
		return this.poison(errors.System.Newf("cannot flush audit record body: %w", err))
	}
	written, err = this.file.Write(frame[commitOffset:])
	if err == nil && written != len(journalFrameCommitMarker) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return this.poison(errors.System.Newf("cannot commit audit record: %w", err))
	}
	if err := this.file.Sync(); err != nil {
		return this.poison(errors.System.Newf("cannot flush audit record commit: %w", err))
	}
	return nil
}

func (this *localJournalRecorder) poison(err error) error {
	if this.poisoned == nil {
		this.poisoned = err
	}
	return this.poisoned
}

func (this *localJournalRecorder) Close() error {
	if this == nil {
		return nil
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return this.closeErr
	}
	this.closed = true

	this.closeErr = this.poisoned
	if this.file != nil {
		if err := this.file.Sync(); err != nil {
			this.closeErr = goerrors.Join(this.closeErr, errors.System.Newf("cannot flush active audit journal while closing: %w", err))
		}
		if err := this.file.Close(); err != nil {
			this.closeErr = goerrors.Join(this.closeErr, errors.System.Newf("cannot close active audit journal: %w", err))
		}
	}
	this.closeErr = goerrors.Join(this.closeErr, this.processLock.Close())
	return this.closeErr
}

func validateAuditEvent(event Event) error {
	if event.Name == "" {
		return errors.System.Newf("audit event name is empty")
	}
	if strings.TrimSpace(event.Name) != event.Name {
		return errors.System.Newf("audit event name contains leading or trailing whitespace")
	}
	if len(event.Name) > maxAuditEventNameSize {
		return errors.System.Newf("audit event name exceeds %d bytes", maxAuditEventNameSize)
	}
	return nil
}

func encodeJournalRecord(record journalRecord) ([]byte, error) {
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, errors.System.Newf("cannot encode audit record: %w", err)
	}
	if len(payload) > maxJournalRecordPayloadSize {
		return nil, errors.System.Newf("encoded audit record exceeds %d bytes", maxJournalRecordPayloadSize)
	}
	frame := make([]byte, journalFrameLengthSize+len(payload)+journalFrameChecksumSize+len(journalFrameCommitMarker))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[journalFrameLengthSize:], payload)
	checksumOffset := journalFrameLengthSize + len(payload)
	binary.BigEndian.PutUint32(frame[checksumOffset:], crc32.Checksum(payload, journalChecksumTable))
	copy(frame[checksumOffset+journalFrameChecksumSize:], journalFrameCommitMarker)
	return frame, nil
}

func decodeJournalRecord(payload []byte, expectedProducerId ProducerId) (journalRecord, error) {
	var record journalRecord
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return journalRecord{}, errors.System.Newf("cannot decode audit record: %w", err)
	}
	if err := ensureJsonEof(decoder); err != nil {
		return journalRecord{}, err
	}
	if record.Schema != journalRecordSchema {
		return journalRecord{}, errors.System.Newf("unsupported audit record schema %q", record.Schema)
	}
	if record.Id == uuid.Nil || record.Id.Version() != 4 || record.Id.Variant() != uuid.RFC4122 {
		return journalRecord{}, errors.System.Newf("illegal audit record ID %q", record.Id)
	}
	if record.RecordedAt.IsZero() {
		return journalRecord{}, errors.System.Newf("audit record time is empty")
	}
	if record.ProducerId != expectedProducerId {
		return journalRecord{}, errors.Config.Newf("audit record belongs to producer %s instead of %s", record.ProducerId, expectedProducerId)
	}
	if err := validateAuditEvent(record.Event); err != nil {
		return journalRecord{}, err
	}
	return record, nil
}

func ensureJsonEof(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.System.Newf("audit record contains trailing JSON value")
		}
		return errors.System.Newf("cannot finish decoding audit record: %w", err)
	}
	return nil
}

func recoverActiveJournal(file *os.File, producerId ProducerId) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.System.Newf("active audit journal is not a regular file")
	}
	size := info.Size()
	var offset int64
	lengthBuffer := make([]byte, journalFrameLengthSize)
	checksumBuffer := make([]byte, journalFrameChecksumSize)
	for offset < size {
		remaining := size - offset
		if remaining < journalFrameLengthSize {
			return truncateJournalTail(file, offset)
		}
		if _, err := file.ReadAt(lengthBuffer, offset); err != nil {
			return err
		}
		payloadSize := int64(binary.BigEndian.Uint32(lengthBuffer))
		if payloadSize <= 0 || payloadSize > maxJournalRecordPayloadSize {
			committed, commitErr := journalTailHasCommitMarker(file, offset, size)
			if commitErr != nil {
				return commitErr
			}
			if !committed {
				return truncateJournalTail(file, offset)
			}
			return errors.System.Newf("illegal audit record size %d at offset %d", payloadSize, offset)
		}
		frameSize := int64(journalFrameLengthSize+journalFrameChecksumSize+len(journalFrameCommitMarker)) + payloadSize
		if remaining < frameSize {
			committed, commitErr := journalTailHasCommitMarker(file, offset, size)
			if commitErr != nil {
				return commitErr
			}
			if committed {
				return errors.System.Newf("audit record at offset %d has a corrupted size", offset)
			}
			return truncateJournalTail(file, offset)
		}
		payload := make([]byte, payloadSize)
		if _, err := file.ReadAt(payload, offset+journalFrameLengthSize); err != nil {
			return err
		}
		checksumOffset := offset + journalFrameLengthSize + payloadSize
		if _, err := file.ReadAt(checksumBuffer, checksumOffset); err != nil {
			return err
		}
		commitMarker := make([]byte, len(journalFrameCommitMarker))
		if _, err := file.ReadAt(commitMarker, checksumOffset+journalFrameChecksumSize); err != nil {
			return err
		}
		if string(commitMarker) != journalFrameCommitMarker {
			return errors.System.Newf("audit record commit marker mismatch at offset %d", offset)
		}
		expectedChecksum := binary.BigEndian.Uint32(checksumBuffer)
		if actual := crc32.Checksum(payload, journalChecksumTable); actual != expectedChecksum {
			return errors.System.Newf("audit record checksum mismatch at offset %d", offset)
		}
		if _, err := decodeJournalRecord(payload, producerId); err != nil {
			return errors.System.Newf("illegal audit record at offset %d: %w", offset, err)
		}
		offset += frameSize
	}
	_, err = file.Seek(0, io.SeekEnd)
	return err
}

func journalTailHasCommitMarker(file *os.File, offset, size int64) (bool, error) {
	if size-offset < int64(len(journalFrameCommitMarker)) {
		return false, nil
	}
	marker := make([]byte, len(journalFrameCommitMarker))
	if _, err := file.ReadAt(marker, size-int64(len(marker))); err != nil {
		return false, err
	}
	return string(marker) == journalFrameCommitMarker, nil
}

func truncateJournalTail(file *os.File, offset int64) error {
	if err := file.Truncate(offset); err != nil {
		return errors.System.Newf("cannot discard incomplete audit record at offset %d: %w", offset, err)
	}
	if err := file.Sync(); err != nil {
		return errors.System.Newf("cannot flush recovered audit journal at offset %d: %w", offset, err)
	}
	_, err := file.Seek(0, io.SeekEnd)
	return err
}

func canonicalJournalDirectory(path string) (string, error) {
	if path == "" {
		return "", errors.Config.Newf("audit journal directory is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.Config.Newf("cannot resolve audit journal directory %q: %w", path, err)
	}
	parent := filepath.Dir(absolute)
	if err := ensureJournalDirectory(parent, false); err != nil {
		return "", errors.System.Newf("cannot prepare parent of audit journal directory %q: %w", absolute, err)
	}
	if canonical, err := filepath.EvalSymlinks(absolute); err == nil {
		return canonical, nil
	} else if !sys.IsNotExist(err) {
		return "", errors.Config.Newf("cannot canonicalize audit journal directory %q: %w", absolute, err)
	}
	if info, err := os.Lstat(absolute); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.Config.Newf("cannot canonicalize dangling audit journal symlink %q", absolute)
	} else if err != nil && !sys.IsNotExist(err) {
		return "", errors.System.Newf("cannot inspect audit journal directory %q: %w", absolute, err)
	}
	canonicalParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", errors.Config.Newf("cannot canonicalize parent of audit journal directory %q: %w", absolute, err)
	}
	return filepath.Join(canonicalParent, filepath.Base(absolute)), nil
}

func ensureJournalDirectory(path string, private bool) error {
	var missing []string
	current := filepath.Clean(path)
	for {
		info, err := os.Stat(current)
		if err == nil {
			if !info.IsDir() {
				return errors.Config.Newf("%q is not a directory", current)
			}
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return err
		}
		current = parent
	}
	if len(missing) > 0 {
		if err := os.MkdirAll(path, journalDirectoryMode); err != nil {
			return err
		}
		for _, created := range missing {
			if err := syncJournalDirectory(filepath.Dir(created)); err != nil {
				return err
			}
		}
	}
	if !private {
		return syncJournalDirectoryHierarchy(path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if err := secureJournalDirectory(path, info); err != nil {
		return err
	}
	if err := syncJournalDirectory(path); err != nil {
		return err
	}
	return syncJournalDirectory(filepath.Dir(path))
}

func syncJournalDirectoryHierarchy(path string) error {
	current := filepath.Clean(path)
	for {
		if err := syncJournalDirectory(current); err != nil {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func validateJournalRoot(directory string, producerId ProducerId) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return errors.System.Newf("cannot inspect audit journal %q: %w", directory, err)
	}
	expected := producerId.String()
	for _, entry := range entries {
		if entry.Name() == journalLockFileName {
			lockPath := filepath.Join(directory, entry.Name())
			info, err := os.Lstat(lockPath)
			if err != nil {
				return errors.System.Newf("cannot inspect audit journal lock in %q: %w", directory, err)
			}
			if !info.Mode().IsRegular() {
				return errors.Config.Newf("audit journal lock %q is not a regular file", lockPath)
			}
			continue
		}
		if entry.Name() != expected || !entry.IsDir() {
			return errors.Config.Newf("audit journal %q contains unsupported entry %q for producer %s", directory, entry.Name(), producerId)
		}
	}
	return nil
}

func validateProducerDirectory(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return errors.System.Newf("cannot inspect audit producer directory %q: %w", directory, err)
	}
	for _, entry := range entries {
		if entry.Name() != journalActiveFileName || entry.Type()&os.ModeType != 0 {
			return errors.Config.Newf("audit producer directory %q contains unsupported entry %q", directory, entry.Name())
		}
	}
	return nil
}

func openActiveJournal(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|os.O_APPEND, journalFileMode)
	if err == nil {
		return prepareActiveJournal(path, file)
	}
	if !errors.Is(err, fs.ErrExist) {
		return nil, errors.System.Newf("cannot create active audit journal %q: %w", path, err)
	}
	info, lstatErr := os.Lstat(path)
	if lstatErr != nil {
		return nil, errors.System.Newf("cannot inspect active audit journal %q: %w", path, lstatErr)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.Config.Newf("active audit journal %q is not a regular file", path)
	}
	file, err = os.OpenFile(path, os.O_RDWR|os.O_APPEND, journalFileMode)
	if err != nil {
		return nil, errors.System.Newf("cannot open active audit journal %q: %w", path, err)
	}
	return prepareActiveJournal(path, file)
}

func openJournalLockFile(path string, mode os.FileMode) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, mode)
	if err == nil {
		return prepareJournalLockFile(path, file)
	}
	if !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.Config.Newf("audit journal lock %q is not a regular file", path)
	}
	file, err = os.OpenFile(path, os.O_RDWR, mode)
	if err != nil {
		return nil, err
	}
	return prepareJournalLockFile(path, file)
}

func prepareJournalLockFile(path string, file *os.File) (*os.File, error) {
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() || !os.SameFile(openedInfo, pathInfo) {
		_ = file.Close()
		return nil, errors.System.Newf("audit journal lock path %q changed while opening the file", path)
	}
	if err := secureJournalFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func prepareActiveJournal(path string, file *os.File) (*os.File, error) {
	if err := validateOpenJournalFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := secureJournalFile(path, file); err != nil {
		_ = file.Close()
		return nil, errors.System.Newf("cannot secure active audit journal %q: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, errors.System.Newf("cannot flush active audit journal %q: %w", path, err)
	}
	if err := syncJournalDirectory(filepath.Dir(path)); err != nil {
		_ = file.Close()
		return nil, errors.System.Newf("cannot flush audit producer directory %q: %w", filepath.Dir(path), err)
	}
	return file, nil
}

func validateOpenJournalFile(path string, file *os.File) error {
	openedInfo, err := file.Stat()
	if err != nil {
		return errors.System.Newf("cannot inspect open active audit journal %q: %w", path, err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return errors.System.Newf("cannot inspect active audit journal path %q: %w", path, err)
	}
	if !pathInfo.Mode().IsRegular() || !os.SameFile(openedInfo, pathInfo) {
		return errors.System.Newf("active audit journal path %q changed while opening the file", path)
	}
	return nil
}

func validateLockedJournalPath(processLock *journalProcessLock, path string) error {
	lockedInfo, err := processLock.file.Stat()
	if err != nil {
		return errors.System.Newf("cannot inspect locked audit journal path %q: %w", path, err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return errors.System.Newf("cannot inspect audit journal lock path %q: %w", path, err)
	}
	if !pathInfo.Mode().IsRegular() || !os.SameFile(lockedInfo, pathInfo) {
		return errors.System.Newf("audit journal lock path %q no longer identifies the locked file", path)
	}
	return nil
}
