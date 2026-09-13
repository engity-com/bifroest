package audit

import (
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
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	journalActiveFileName       = "active.journal"
	journalLockFileName         = ".bifroest.lock"
	journalFrameCommitMarker    = "BIFROEST-AUDIT\r\n"
	journalDirectoryMode        = 0700
	journalFileMode             = 0600
	journalFrameLengthSize      = 4
	journalFrameChecksumSize    = 4
	maxJournalRecordPayloadSize = 64 * 1024
	maxAuditEventNameSize       = 256
	maxAuditEventTokenSize      = 256
)

var (
	journalChecksumTable = crc32.MakeTable(crc32.Castagnoli)
	errJournalClosed     = errors.System.Newf("audit journal is closed")
)

type localJournalRecorder struct {
	mutex       sync.Mutex
	file        *os.File
	processLock *journalProcessLock
	activePath  string
	lockPath    string
	producerId  ProducerId
	identity    *Identity
	encryptor   *journalEventEncryptor
	headPath    string
	state       journalSegmentState
	targetSize  int64
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
	encryptionPublicKey, err := ResolveEncryptionPublicKey(conf.EncryptionPublicKey, conf.EncryptionPublicKeyFile)
	if err != nil {
		return nil, err
	}
	if err := ValidateEncryptionRecipientDedicatedFrom(encryptionPublicKey, []bfcrypto.PrivateKey{identity.privateKey}); err != nil {
		return nil, err
	}
	encryptor, err := newJournalEventEncryptor(encryptionPublicKey)
	if err != nil {
		return nil, err
	}
	encryptionRecipient := ""
	if encryptor != nil {
		encryptionRecipient = encryptor.recipientFingerprint
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
	activePath := filepath.Join(producerDirectory, journalActiveFileName)
	head, err := loadOrCreateJournalHead(producerDirectory, identity)
	if err != nil {
		return nil, err
	}
	file, state, err := recoverJournalSegments(producerDirectory, activePath, identity, head.LastRecordHash, encryptionRecipient)
	if err != nil {
		return nil, err
	}
	if state.previousRecordHash != head.LastRecordHash {
		if err := writeJournalHead(producerDirectory, identity, state.previousRecordHash); err != nil {
			_ = file.Close()
			return nil, err
		}
	}

	committed = true
	return &localJournalRecorder{
		file:        file,
		processLock: processLock,
		activePath:  activePath,
		lockPath:    lockPath,
		producerId:  identity.ProducerId(),
		identity:    identity,
		encryptor:   encryptor,
		headPath:    filepath.Join(producerDirectory, journalHeadFileName),
		state:       state,
		targetSize:  defaultJournalSegmentTargetSize,
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
	_, payload, recordHash, err := newJournalRecord(this.identity, this.state.previousRecordHash, event, id, time.Now().UTC(), this.encryptor)
	if err != nil {
		return err
	}
	frame, err := encodeJournalFrame(payload)
	if err != nil {
		return err
	}
	if this.state.recordCount > 0 && this.state.contentBytes+int64(len(frame)) > this.targetSize {
		if err := this.rotate(time.Now().UTC()); err != nil {
			return this.poison(err)
		}
	}
	if err := writeCommittedJournalFrame(this.file, frame); err != nil {
		return this.poison(err)
	}
	this.state.previousRecordHash = recordHash
	this.state.recordCount++
	this.state.contentBytes += int64(len(frame))
	this.state.fileBytes = this.state.contentBytes
	if err := writeJournalHead(filepath.Dir(this.headPath), this.identity, recordHash); err != nil {
		return this.poison(err)
	}
	return nil
}

func (this *localJournalRecorder) rotate(at time.Time) error {
	producerDirectory := filepath.Dir(this.activePath)
	sealed, err := sealActiveJournal(this.file, this.activePath, producerDirectory, this.identity, this.state, at)
	if err != nil {
		return err
	}
	file, state, err := createActiveJournal(this.activePath, this.identity, sealed.sequence+1, sealed.segmentHash, sealed.previousRecordHash)
	if err != nil {
		return err
	}
	this.file = file
	this.state = state
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

	this.closeErr = this.sealLocked()
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

func (this *localJournalRecorder) Seal() error {
	if this == nil {
		return nil
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return errJournalClosed
	}
	return this.sealLocked()
}

func (this *localJournalRecorder) sealLocked() error {
	if this.poisoned != nil {
		return this.poisoned
	}
	if this.file == nil || this.state.recordCount == 0 {
		return nil
	}
	if err := this.rotate(time.Now().UTC()); err != nil {
		return this.poison(err)
	}
	return nil
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
	if event.Domain != "" && event.Domain != EventDomainAuthentication && event.Domain != EventDomainConnection &&
		event.Domain != EventDomainHousekeeping && event.Domain != EventDomainPortForwarding && event.Domain != EventDomainSession {
		return errors.System.Newf("unknown audit event domain %q", event.Domain)
	}
	if event.Outcome != "" && event.Outcome != EventOutcomeSuccess && event.Outcome != EventOutcomeDenied &&
		event.Outcome != EventOutcomeFailure && event.Outcome != EventOutcomeCanceled {
		return errors.System.Newf("unknown audit event outcome %q", event.Outcome)
	}
	if event.AuthenticationMethod != "" && event.AuthenticationMethod != AuthenticationMethodPublicKey &&
		event.AuthenticationMethod != AuthenticationMethodPassword && event.AuthenticationMethod != AuthenticationMethodKeyboardInteractive {
		return errors.System.Newf("unknown audit authentication method %q", event.AuthenticationMethod)
	}
	if event.AuthenticationPhase != "" && event.AuthenticationPhase != AuthenticationPhaseCandidate &&
		event.AuthenticationPhase != AuthenticationPhaseVerified {
		return errors.System.Newf("unknown audit authentication phase %q", event.AuthenticationPhase)
	}
	if event.SessionTask != "" && event.SessionTask != SessionTaskShell && event.SessionTask != SessionTaskExec && event.SessionTask != SessionTaskSftp {
		return errors.System.Newf("unknown audit session task %q", event.SessionTask)
	}
	if event.ErrorCategory != "" && event.ErrorCategory != ErrorCategoryUnknown && event.ErrorCategory != ErrorCategorySystem &&
		event.ErrorCategory != ErrorCategoryConfig && event.ErrorCategory != ErrorCategoryNetwork && event.ErrorCategory != ErrorCategoryUser &&
		event.ErrorCategory != ErrorCategoryPermission && event.ErrorCategory != ErrorCategoryExpired {
		return errors.System.Newf("unknown audit error category %q", event.ErrorCategory)
	}
	if err := validateAuditFlow(event.Flow); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"authorization kind": event.AuthorizationKind,
		"reason":             event.Reason,
	} {
		if err := validateAuditToken(name, value); err != nil {
			return err
		}
	}
	for name, value := range map[string]string{
		"connection ID": event.ConnectionId,
		"session ID":    event.SessionId,
		"operation ID":  event.OperationId,
	} {
		if err := validateAuditUuid(name, value); err != nil {
			return err
		}
	}
	if event.ExitCode != nil && *event.ExitCode < 0 {
		return errors.System.Newf("audit event exit code is negative")
	}
	for name, value := range map[string]*int64{
		"bytes read":      event.BytesRead,
		"bytes written":   event.BytesWritten,
		"duration millis": event.DurationMillis,
	} {
		if value != nil && *value < 0 {
			return errors.System.Newf("audit event %s is negative", name)
		}
	}
	return nil
}

func validateAuditFlow(value string) error {
	if value == "" {
		return nil
	}
	if value == "." || value == ".." {
		return errors.System.Newf("illegal audit event flow %q", value)
	}
	for _, candidate := range value {
		if !isAuditTokenCharacter(candidate) {
			return errors.System.Newf("illegal audit event flow %q", value)
		}
	}
	return nil
}

func validateAuditToken(name, value string) error {
	if value == "" {
		return nil
	}
	if len(value) > maxAuditEventTokenSize {
		return errors.System.Newf("audit event %s exceeds %d bytes", name, maxAuditEventTokenSize)
	}
	for _, candidate := range value {
		if !isAuditTokenCharacter(candidate) {
			return errors.System.Newf("illegal audit event %s %q", name, value)
		}
	}
	return nil
}

func isAuditTokenCharacter(candidate rune) bool {
	return candidate >= 'a' && candidate <= 'z' || candidate >= 'A' && candidate <= 'Z' ||
		candidate >= '0' && candidate <= '9' || candidate == '-' || candidate == '.'
}

func validateAuditUuid(name, value string) error {
	if value == "" {
		return nil
	}
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return errors.System.Newf("illegal audit event %s %q", name, value)
	}
	return nil
}

func encodeJournalFrame(payload []byte) ([]byte, error) {
	if len(payload) > maxJournalRecordPayloadSize {
		return nil, errors.System.Newf("encoded audit journal payload exceeds %d bytes", maxJournalRecordPayloadSize)
	}
	frame := make([]byte, journalFrameLengthSize+len(payload)+journalFrameChecksumSize+len(journalFrameCommitMarker))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[journalFrameLengthSize:], payload)
	checksumOffset := journalFrameLengthSize + len(payload)
	binary.BigEndian.PutUint32(frame[checksumOffset:], crc32.Checksum(payload, journalChecksumTable))
	copy(frame[checksumOffset+journalFrameChecksumSize:], journalFrameCommitMarker)
	return frame, nil
}

func writeCommittedJournalFrame(file *os.File, frame []byte) error {
	commitOffset := len(frame) - len(journalFrameCommitMarker)
	written, err := file.Write(frame[:commitOffset])
	if err == nil && written != commitOffset {
		err = io.ErrShortWrite
	}
	if err != nil {
		return errors.System.Newf("cannot append audit journal frame: %w", err)
	}
	if err := file.Sync(); err != nil {
		return errors.System.Newf("cannot flush audit journal frame body: %w", err)
	}
	written, err = file.Write(frame[commitOffset:])
	if err == nil && written != len(journalFrameCommitMarker) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return errors.System.Newf("cannot commit audit journal frame: %w", err)
	}
	if err := file.Sync(); err != nil {
		return errors.System.Newf("cannot flush audit journal frame commit: %w", err)
	}
	return nil
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

func truncateJournalTail(file *os.File, offset int64) error {
	if err := file.Truncate(offset); err != nil {
		return errors.System.Newf("cannot discard incomplete audit frame at offset %d: %w", offset, err)
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
		if entry.Name() == remoteDeliveryStateDirectoryName {
			path := filepath.Join(directory, entry.Name())
			info, err := os.Lstat(path)
			if err != nil {
				return errors.System.Newf("cannot inspect remote delivery state in %q: %w", directory, err)
			}
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.Config.Newf("remote delivery state %q is not a directory", path)
			}
			if err := secureJournalDirectory(path, info); err != nil {
				return err
			}
			continue
		}
		if entry.Name() != expected || !entry.IsDir() {
			return errors.Config.Newf("audit journal %q contains unsupported entry %q for producer %s", directory, entry.Name(), producerId)
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
