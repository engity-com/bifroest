package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
)

const (
	FsFileRuntimeOwnership       = "ro"
	FsFileRuntimeRevocation      = "rr"
	FsFileRuntimeState           = ".bifroest-runtime-state"
	FsFileRuntimeKey             = ".bifroest-runtime-key"
	FsFileRuntimePending         = ".bifroest-runtime-pending"
	maximumRuntimeStateBytes     = 4 << 20
	maximumRuntimeOwnershipBytes = 2048
)

// Keep process metadata beside the canonical storage, like its exclusive lock.
// Every valid flow name remains available inside the storage root.
func (this *FsRepository) runtimeFile(name string) string {
	return filepath.Join(filepath.Dir(this.storage), "."+filepath.Base(this.storage)+name)
}

func (this *FacadeRepository) RuntimeKey(ctx context.Context) ([]byte, error) {
	if repository, ok := this.CloseableRepository.(RuntimeRepository); ok {
		return repository.RuntimeKey(ctx)
	}
	return nil, ErrRuntimeOwnershipUnavailable
}

func (this *FacadeRepository) RuntimeState(ctx context.Context) (*RuntimeState, error) {
	if repository, ok := this.CloseableRepository.(RuntimeRepository); ok {
		return repository.RuntimeState(ctx)
	}
	return nil, ErrRuntimeOwnershipUnavailable
}

func (this *FacadeRepository) CommitRuntimeState(ctx context.Context, expected RuntimeRevision, next RuntimeState) RuntimeCommit {
	if repository, ok := this.CloseableRepository.(RuntimeRepository); ok {
		return repository.CommitRuntimeState(ctx, expected, next)
	}
	return RuntimeCommit{Err: ErrRuntimeOwnershipUnavailable}
}

// Private metadata is bounded and must remain the same regular file throughout
// reading. Never follow a symlink or expose decoded secret-bearing input in an
// error. Missing is distinct from a damaged/unknown schema.
func readFsRuntimeFile(path string, maximum int) ([]byte, error) {
	raw, err := crypto.ReadSecurePrivateFile(path, int64(maximum))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || len(raw) == 0 {
		return nil, ErrInvalidRuntimeState
	}
	return raw, nil
}

func (this *FsRepository) RuntimeKey(ctx context.Context) ([]byte, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateFsRepositoryProcessLock(this.processLock, this.processLockPath()); err != nil {
		return nil, err
	}
	path := this.runtimeFile(FsFileRuntimeKey)
	raw, err := readFsRuntimeFile(path, 32)
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if !validRuntimeKey(raw) {
			return nil, ErrInvalidRuntimeState
		}
		return raw, nil
	}
	// Losing a key never permits reinterpreting existing digests under a new
	// one. An existing state with no key needs explicit operator recovery.
	for _, name := range []string{FsFileRuntimeState, FsFileRuntimePending} {
		if _, err := os.Lstat(this.runtimeFile(name)); !errors.Is(err, os.ErrNotExist) {
			return nil, ErrInvalidRuntimeState
		}
	}
	raw = make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	if !validRuntimeKey(raw) {
		return nil, ErrInvalidRuntimeState
	}
	if err := writeFsPrivateFileAtomically(path, raw, os.FileMode(this.dirFileMode())); err != nil {
		return nil, err
	}
	return raw, nil
}

func (this *FsRepository) RuntimeState(ctx context.Context) (*RuntimeState, error) {
	this.mutex.RLock()
	defer this.mutex.RUnlock()
	return this.readRuntimeState(ctx)
}

func (this *FsRepository) readRuntimeState(ctx context.Context) (*RuntimeState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(this.runtimeFile(FsFileRuntimePending)); !errors.Is(err, os.ErrNotExist) {
		return nil, ErrInvalidRuntimeState
	}
	raw, err := readFsRuntimeFile(this.runtimeFile(FsFileRuntimeState), maximumRuntimeStateBytes)
	if err != nil || raw == nil {
		return nil, err
	}
	var result RuntimeState
	if strictRuntimeJSON(raw, &result) != nil || result.Validate() != nil {
		return nil, ErrInvalidRuntimeState
	}
	return &result, nil
}

func (this *FsRepository) CommitRuntimeState(ctx context.Context, expected RuntimeRevision, next RuntimeState) RuntimeCommit {
	return this.commitRuntimeState(ctx, expected, next, writeFsPrivateFileAtomically)
}

func (this *FsRepository) commitRuntimeState(ctx context.Context, expected RuntimeRevision, next RuntimeState, write func(string, []byte, os.FileMode) error) RuntimeCommit {
	if next.Validate() != nil || next.Revision == expected || expected != "" && expected.Validate() != nil {
		return RuntimeCommit{Err: ErrInvalidRuntimeState}
	}
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > maximumRuntimeStateBytes {
		return RuntimeCommit{Err: ErrInvalidRuntimeState}
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return RuntimeCommit{Err: err}
	}
	if err := validateFsRepositoryProcessLock(this.processLock, this.processLockPath()); err != nil {
		return RuntimeCommit{Err: err}
	}
	key, err := readFsRuntimeFile(this.runtimeFile(FsFileRuntimeKey), 32)
	if err != nil || !validRuntimeKey(key) {
		return RuntimeCommit{Err: ErrInvalidRuntimeState}
	}
	current, err := this.readRuntimeState(ctx)
	if err != nil {
		return RuntimeCommit{Err: err}
	}
	if current == nil && expected != "" || current != nil && current.Revision != expected {
		return RuntimeCommit{Err: ErrRuntimeStateConflict}
	}
	path := this.runtimeFile(FsFileRuntimeState)
	if err := this.beginRuntimeWrite(); err != nil {
		return RuntimeCommit{Uncertain: true, Err: err}
	}
	err = write(path, raw, os.FileMode(this.dirFileMode()))
	if err == nil {
		return RuntimeCommit{Published: true, Err: this.finishRuntimeWrite()}
	}
	// A directory-sync/close error can occur after replacement. Never report
	// rejection when the new revision is already visible to a restart.
	published, readErr := readFsRuntimeFile(path, maximumRuntimeStateBytes)
	if readErr == nil && bytes.Equal(published, raw) {
		return RuntimeCommit{Published: true, Err: err}
	}
	if readErr == nil {
		if current == nil && published == nil {
			return this.rejectedRuntimeWrite(err)
		}
		var remaining RuntimeState
		if current != nil && strictRuntimeJSON(published, &remaining) == nil {
			before, beforeErr := json.Marshal(current)
			after, afterErr := json.Marshal(remaining)
			if beforeErr == nil && afterErr == nil && bytes.Equal(before, after) {
				return this.rejectedRuntimeWrite(err)
			}
		}
	}
	// If publication cannot be determined, the caller must stop admission,
	// not guess that the previous state is still authoritative.
	return RuntimeCommit{Uncertain: true, Err: errors.Join(ErrInvalidRuntimeState, err)}
}

// The durable intent precedes any authority/tombstone replacement. A crash or
// post-rename sync failure can therefore never silently roll authority back to
// a previous revision. Startup refuses an unfinished intent; no auto-recovery
// guesses whether memory publication or revocation already happened.
func (this *FsRepository) beginRuntimeWrite() error {
	path := this.runtimeFile(FsFileRuntimePending)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return ErrInvalidRuntimeState
	}
	return writeFsPrivateFileAtomically(path, []byte(`{"schema":"bifroest-runtime-pending-v1"}`), os.FileMode(this.dirFileMode()))
}

func (this *FsRepository) finishRuntimeWrite() error {
	path := this.runtimeFile(FsFileRuntimePending)
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncFsDirectory(filepath.Dir(path))
}

func (this *FsRepository) rejectedRuntimeWrite(cause error) RuntimeCommit {
	if err := this.finishRuntimeWrite(); err != nil {
		return RuntimeCommit{Uncertain: true, Err: errors.Join(cause, err)}
	}
	return RuntimeCommit{Err: cause}
}

func validRuntimeKey(raw []byte) bool {
	return len(raw) == 32 && !bytes.Equal(raw, make([]byte, 32))
}

func (this *fs) RuntimeOwnership(ctx context.Context) (*RuntimeOwnership, error) {
	this.repository.mutex.RLock()
	defer this.repository.mutex.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return this.repository.readRuntimeOwnership(this.flow, this.id)
}

func (this *FacadeRepository) RevokeRuntimeSession(ctx context.Context, flow configuration.FlowName, id Id) error {
	if repository, ok := this.CloseableRepository.(RuntimeSessionRevoker); ok {
		return repository.RevokeRuntimeSession(ctx, flow, id)
	}
	return ErrRuntimeOwnershipUnavailable
}

func (this *FsRepository) RevokeRuntimeSession(ctx context.Context, flow configuration.FlowName, id Id) error {
	return this.revokeRuntimeSession(ctx, flow, id, writeFsPrivateFileAtomically)
}

func (this *FsRepository) revokeRuntimeSession(ctx context.Context, flow configuration.FlowName, id Id, write func(string, []byte, os.FileMode) error) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateFsRepositoryProcessLock(this.processLock, this.processLockPath()); err != nil {
		return err
	}
	owner, err := this.readRuntimeOwnership(flow, id)
	if err != nil || owner == nil {
		return err // Legacy/missing sessions never gain a new runtime identity.
	}
	raw, err := json.Marshal(owner)
	if err != nil {
		return ErrInvalidRuntimeOwnership
	}
	path, err := this.file(flow, id, FsFileRuntimeRevocation)
	if err != nil {
		return err
	}
	existing, err := readFsRuntimeFile(path, maximumRuntimeOwnershipBytes)
	if err != nil {
		return ErrInvalidRuntimeOwnership
	}
	if existing != nil {
		var previous RuntimeOwnership
		if strictRuntimeJSON(existing, &previous) != nil || previous != *owner {
			return ErrInvalidRuntimeOwnership
		}
	}
	if err := this.beginRuntimeWrite(); err != nil {
		return err
	}
	if err := write(path, raw, os.FileMode(this.dirFileMode())); err != nil {
		return err // Retain the durable intent, even if the marker is visible.
	}
	return this.finishRuntimeWrite()
}

func (this *fs) RuntimeRevoked(ctx context.Context) (bool, error) {
	this.repository.mutex.RLock()
	defer this.repository.mutex.RUnlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	path, err := this.repository.file(this.flow, this.id, FsFileRuntimeRevocation)
	if err != nil {
		return false, err
	}
	raw, err := readFsRuntimeFile(path, maximumRuntimeOwnershipBytes)
	if err != nil {
		return true, ErrInvalidRuntimeOwnership
	}
	if raw == nil {
		return false, nil
	}
	var marker RuntimeOwnership
	owner, err := this.repository.readRuntimeOwnership(this.flow, this.id)
	if err != nil || owner == nil || strictRuntimeJSON(raw, &marker) != nil || marker != *owner {
		return true, ErrInvalidRuntimeOwnership
	}
	return true, nil
}

func (this *FsRepository) readRuntimeOwnership(flow configuration.FlowName, id Id) (*RuntimeOwnership, error) {
	path, err := this.file(flow, id, FsFileRuntimeOwnership)
	if err != nil {
		return nil, err
	}
	raw, err := readFsRuntimeFile(path, maximumRuntimeOwnershipBytes)
	if err != nil {
		return nil, ErrInvalidRuntimeOwnership
	}
	if raw == nil {
		return nil, nil
	}
	var result RuntimeOwnership
	if strictRuntimeJSON(raw, &result) != nil || result.Validate() != nil || result.Flow != flow || result.SessionID != id {
		return nil, ErrInvalidRuntimeOwnership
	}
	return &result, nil
}

func (this *FsRepository) writeRuntimeOwnership(flow configuration.FlowName, id Id, owner RuntimeOwnership) error {
	if owner.Validate() != nil || owner.Flow != flow || owner.SessionID != id {
		return ErrInvalidRuntimeOwnership
	}
	raw, err := json.Marshal(owner)
	if err != nil || len(raw) > maximumRuntimeOwnershipBytes {
		return ErrInvalidRuntimeOwnership
	}
	path, err := this.file(flow, id, FsFileRuntimeOwnership)
	if err != nil {
		return err
	}
	return writeFsPrivateFileAtomically(path, raw, os.FileMode(this.dirFileMode()))
}

// Reject duplicate/unknown fields, nulls, trailing documents and invalid Unicode
// at every level. encoding/json alone accepts duplicate keys and repairs UTF-16.
func strictRuntimeJSON(raw []byte, target any) error {
	if !utf8.Valid(raw) || !associationStringScalarsValid(raw) {
		return ErrInvalidRuntimeState
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := checkRuntimeJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidRuntimeState
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalidRuntimeState
	}
	canonical, err := json.Marshal(target)
	if err != nil || !sameRuntimeJSONShape(raw, canonical) {
		return ErrInvalidRuntimeState
	}
	return nil
}

// encoding/json accepts case-insensitive struct field aliases. Compare against
// the typed encoding to require exact field names and canonical identifiers.
func sameRuntimeJSONShape(raw, canonical []byte) bool {
	if len(raw) == 0 || len(canonical) == 0 {
		return false
	}
	if bytes.TrimSpace(canonical)[0] != '{' {
		var left, right string
		return json.Unmarshal(raw, &left) == nil && json.Unmarshal(canonical, &right) == nil && left == right
	}
	var left, right map[string]json.RawMessage
	if json.Unmarshal(raw, &left) != nil || json.Unmarshal(canonical, &right) != nil || len(left) != len(right) {
		return false
	}
	for key, value := range right {
		if !sameRuntimeJSONShape(left[key], value) {
			return false
		}
	}
	return true
}

func checkRuntimeJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 8 {
		return ErrInvalidRuntimeState
	}
	value, err := decoder.Token()
	if err != nil || value == nil {
		return ErrInvalidRuntimeState
	}
	delim, container := value.(json.Delim)
	if !container {
		return nil
	}
	if delim != '{' {
		return ErrInvalidRuntimeState
	}
	seen := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return ErrInvalidRuntimeState
		}
		seen[name] = true
		if err := checkRuntimeJSONValue(decoder, depth+1); err != nil {
			return err
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return ErrInvalidRuntimeState
	}
	return nil
}
