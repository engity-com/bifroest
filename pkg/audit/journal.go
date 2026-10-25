package audit

import (
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
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
	maxAuditEventNameSize       = evidence.MaximumEventNameBytes
	maxAuditEventTokenSize      = evidence.MaximumEventTokenBytes
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
	return evidence.ValidateEvent(event)
}

func validateAuditEventForWrite(event Event) error {
	return evidence.ValidateEventForWrite(event)
}

func isErrorCategory(value ErrorCategory) bool {
	return evidence.IsErrorCategory(value)
}

func validateAuditToken(name, value string) error {
	return evidence.ValidateToken(name, value)
}

func validateAuditRecordingDigest(value string) error {
	return evidence.ValidateRecordingDigest(value)
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
