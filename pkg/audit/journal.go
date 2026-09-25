package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/configuration"
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
	return newNativeRecorder(conf, identity)
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
	if event.ErrorCategory != "" && !isErrorCategory(event.ErrorCategory) {
		return errors.System.Newf("unknown audit error category %q", event.ErrorCategory)
	}
	if event.Target != "" {
		if err := event.Target.Validate(); err != nil {
			return errors.System.Newf("illegal audit event target: %w", err)
		}
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
	if err := validateAuditRecordingUuid(event.RecordingId); err != nil {
		return err
	}
	if err := validateAuditRecordingDigest(event.RecordingDigest); err != nil {
		return err
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
	if event.Count != nil && *event.Count == 0 {
		return errors.System.Newf("audit event count is zero")
	}
	return nil
}

func validateAuditEventForWrite(event Event) error {
	if err := validateAuditEvent(event); err != nil {
		return err
	}
	if err := validateSessionRecordingAuditEvent(event); err != nil {
		return err
	}
	return validateSessionRecordingDeliveryAuditEvent(event)
}

func validateSessionRecordingAuditEvent(event Event) error {
	switch event.Name {
	case EventNameSessionRecordingStarted, EventNameSessionRecordingCompleted, EventNameSessionRecordingIncomplete, EventNameSessionRecordingFailed:
	default:
		return nil
	}
	if event.Domain != EventDomainSession || event.Flow == "" || event.ConnectionId == "" || event.SessionId == "" || event.OperationId == "" || event.RecordingId == "" {
		return errors.System.Newf("session recording audit event lacks required correlation fields")
	}
	if event.SessionTask != SessionTaskShell && event.SessionTask != SessionTaskExec {
		return errors.System.Newf("session recording audit event has illegal task %q", event.SessionTask)
	}
	if event.AuthenticationMethod != "" || event.AuthenticationPhase != "" || event.AuthorizationKind != "" ||
		event.Target != "" || event.BytesRead != nil || event.BytesWritten != nil || event.Count != nil || event.AgentForwarding != nil || event.ForcedCommand != nil {
		return errors.System.Newf("session recording audit event has unrelated fields")
	}
	switch event.Name {
	case EventNameSessionRecordingStarted:
		if event.Outcome != "" || event.Reason != "" || event.ErrorCategory != "" || event.RecordingDigest != "" || event.Pty == nil || event.DurationMillis != nil || event.ExitCode != nil {
			return errors.System.Newf("session recording started audit event has illegal lifecycle fields")
		}
	case EventNameSessionRecordingCompleted:
		if event.Outcome != EventOutcomeSuccess || event.Reason != "" || event.ErrorCategory != "" || event.RecordingDigest == "" || event.Pty != nil || event.DurationMillis == nil || event.ExitCode == nil {
			return errors.System.Newf("session recording completed audit event lacks required completion fields")
		}
	case EventNameSessionRecordingIncomplete:
		if event.RecordingDigest == "" || event.Pty != nil || event.DurationMillis == nil {
			return errors.System.Newf("session recording incomplete audit event lacks required completion fields")
		}
		valid := event.Outcome == EventOutcomeCanceled && event.ErrorCategory == "" &&
			(event.Reason == EventReasonContextCanceled || event.Reason == EventReasonDeadlineExceeded) ||
			event.Outcome == EventOutcomeFailure && event.ErrorCategory == "" && event.Reason == EventReasonInvalidExitCode ||
			event.Outcome == EventOutcomeFailure && event.ErrorCategory == "" && event.Reason == EventReasonStartupRecovery && event.ExitCode == nil ||
			event.Outcome == EventOutcomeFailure && event.Reason == EventReasonSessionError && event.ErrorCategory != ""
		if !valid {
			return errors.System.Newf("session recording incomplete audit event has illegal outcome and reason")
		}
		if event.Reason == EventReasonInvalidExitCode && event.ExitCode != nil {
			return errors.System.Newf("session recording invalid-exit audit event has an exit code")
		}
	case EventNameSessionRecordingFailed:
		validReason := event.Reason == EventReasonRecordingCreate || event.Reason == EventReasonRecordingCapture || event.Reason == EventReasonRecordingSeal || event.Reason == EventReasonAuditWrite
		startupFieldsInvalid := (event.Reason == EventReasonRecordingCreate || event.Reason == EventReasonAuditWrite) && event.ExitCode != nil
		createFieldsInvalid := event.Reason == EventReasonRecordingCreate && (event.RecordingDigest != "" || event.DurationMillis != nil)
		if event.Outcome != EventOutcomeFailure || !validReason || event.ErrorCategory == "" || event.Pty != nil || event.RecordingDigest != "" && event.DurationMillis == nil || startupFieldsInvalid || createFieldsInvalid {
			return errors.System.Newf("session recording failed audit event lacks required failure fields")
		}
	}
	return nil
}

func validateSessionRecordingDeliveryAuditEvent(event Event) error {
	switch event.Name {
	case EventNameSessionRecordingDeliveryFailed, EventNameSessionRecordingDeliverySucceeded:
	default:
		return nil
	}
	if event.Domain != EventDomainSession || event.OperationId == "" || event.RecordingId == "" || event.Target == "" {
		return errors.System.Newf("session recording delivery audit event lacks required correlation fields")
	}
	if event.Flow != "" || event.ConnectionId != "" || event.SessionId != "" || event.RecordingDigest != "" ||
		event.AuthenticationMethod != "" || event.AuthenticationPhase != "" || event.AuthorizationKind != "" || event.SessionTask != "" ||
		event.Reason != "" || event.ExitCode != nil || event.BytesRead != nil || event.BytesWritten != nil || event.DurationMillis != nil ||
		event.Count != nil || event.Pty != nil || event.AgentForwarding != nil || event.ForcedCommand != nil {
		return errors.System.Newf("session recording delivery audit event has unrelated fields")
	}
	if event.Name == EventNameSessionRecordingDeliveryFailed {
		if event.Outcome != EventOutcomeFailure || event.ErrorCategory == "" {
			return errors.System.Newf("session recording delivery failed audit event lacks required failure fields")
		}
	} else if event.Outcome != EventOutcomeSuccess || event.ErrorCategory != "" {
		return errors.System.Newf("session recording delivery succeeded audit event has illegal outcome fields")
	}
	return nil
}

func isErrorCategory(value ErrorCategory) bool {
	return value == ErrorCategoryUnknown || value == ErrorCategorySystem || value == ErrorCategoryConfig || value == ErrorCategoryNetwork ||
		value == ErrorCategoryUser || value == ErrorCategoryPermission || value == ErrorCategoryExpired
}

func validateAuditFlow(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > configuration.MaxFlowNameBytes {
		return errors.System.Newf("audit event flow exceeds %d bytes", configuration.MaxFlowNameBytes)
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

func validateAuditRecordingUuid(value string) error {
	if value == "" {
		return nil
	}
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.Version() != 4 || parsed.Variant() != uuid.RFC4122 || parsed.String() != value {
		return errors.System.Newf("illegal audit event recording ID %q", value)
	}
	return nil
}

func validateAuditRecordingDigest(value string) error {
	if value == "" {
		return nil
	}
	if len(value) != sha256.Size*2 {
		return errors.System.Newf("illegal audit event recording digest %q", value)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return errors.System.Newf("illegal audit event recording digest %q", value)
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

func prepareJournalLockFile(path string, file *os.File) (*os.File, error) {
	if err := secureJournalFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validateOpenJournalFile(path string, file *os.File) error {
	if file == nil {
		return errors.System.Newf("active audit journal %q is closed", path)
	}
	info, err := file.Stat()
	if err != nil {
		return errors.System.Newf("cannot inspect open active audit journal %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return errors.Config.Newf("active audit journal %q is not a regular file", path)
	}
	return nil
}

func validateLockedJournalPath(processLock *journalProcessLock, path string) error {
	if processLock == nil || processLock.file == nil {
		return errors.System.Newf("audit journal lock %q is closed", path)
	}
	same, err := sameJournalProcessLockFile(processLock.file, path)
	if err != nil {
		return errors.System.Newf("cannot inspect audit journal lock path %q: %w", path, err)
	}
	if !same {
		return errors.System.Newf("audit journal lock path %q no longer refers to the acquired lock", path)
	}
	return nil
}

func removeJournalProcessLock(processLock *journalProcessLock, path string) error {
	if err := validateLockedJournalPath(processLock, path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return errors.System.Newf("cannot remove audit journal lock %q: %w", path, err)
	}
	if err := syncJournalDirectory(filepath.Dir(path)); err != nil {
		return errors.System.Newf("cannot synchronize audit journal lock directory %q: %w", filepath.Dir(path), err)
	}
	return nil
}
