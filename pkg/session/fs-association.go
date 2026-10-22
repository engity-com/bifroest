package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"unicode/utf8"

	"github.com/engity-com/bifroest/pkg/configuration"
)

const maximumAssociationBytes = 16 << 10

func (this *fs) SessionAssociation(ctx context.Context) (*Association, error) {
	this.repository.mutex.RLock()
	defer this.repository.mutex.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result, err := this.repository.readAssociation(this.flow, this.id)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return result, err
}

func (this *fs) BindSessionAssociation(ctx context.Context, association Association) error {
	if err := association.Validate(); err != nil {
		return err
	}
	this.repository.mutex.Lock()
	defer this.repository.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateFsRepositoryProcessLock(this.repository.processLock, this.repository.processLockPath()); err != nil {
		return err
	}
	current, err := this.repository.findBy(ctx, this.flow, this.id, nil, false)
	if err != nil {
		return err
	}
	if current.info.VState == StateDisposed {
		return fmt.Errorf("cannot bind a disposed session")
	}
	existing, err := this.repository.readAssociation(this.flow, this.id)
	if err != nil {
		return err
	}
	if existing != nil {
		if *existing == association {
			return nil
		}
		return ErrAssociationConflict
	}
	if current.info.VState != StateNew {
		return fmt.Errorf("%w: established legacy session needs explicit migration", ErrAssociationConflict)
	}
	if path, err := this.repository.file(this.flow, this.id, FsFileEnvironmentToken); err != nil {
		return err
	} else if exists, err := fsEnvironmentTokenExists(path); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("%w: environment already exists", ErrAssociationConflict)
	}
	if byFlow := this.repository.connectionInterceptors[this.flow]; byFlow != nil {
		if interceptor := byFlow[this.id]; interceptor != nil && interceptor.active.Load() > 0 {
			return fmt.Errorf("%w: session already has active connections", ErrAssociationConflict)
		}
	}
	return this.repository.writeAssociation(ctx, this.flow, this.id, association)
}

func (this *FsRepository) writeAssociation(ctx context.Context, flow configuration.FlowName, id Id, association Association) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := association.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(association)
	if err != nil || len(raw) > maximumAssociationBytes {
		return ErrInvalidAssociation
	}
	path, err := this.file(flow, id, FsFileAssociation)
	if err != nil {
		return err
	}
	return writeFsFileAtomically(path, raw, os.FileMode(this.conf.FileMode), os.FileMode(this.dirFileMode()))
}

// Association errors intentionally are not ErrCorruptSession: automatic cleanup
// must not remove evidence of an unknown/malformed ownership record, even when
// no environment token exists (Docker/Kubernetes resources can live elsewhere).
func (this *FsRepository) readAssociation(flow configuration.FlowName, id Id) (*Association, error) {
	path, err := this.file(flow, id, FsFileAssociation)
	if err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > maximumAssociationBytes {
		return nil, ErrInvalidAssociation
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalidAssociation
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, ErrInvalidAssociation
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumAssociationBytes+1))
	if err != nil || len(raw) > maximumAssociationBytes {
		return nil, ErrInvalidAssociation
	}
	after, err := file.Stat()
	pathAfter, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !pathAfter.Mode().IsRegular() || !os.SameFile(opened, after) || !os.SameFile(after, pathAfter) || opened.Size() != after.Size() || opened.Mode() != after.Mode() || !opened.ModTime().Equal(after.ModTime()) {
		return nil, ErrInvalidAssociation
	}
	return decodeAssociation(raw)
}

func decodeAssociation(raw []byte) (*Association, error) {
	if !utf8.Valid(raw) {
		return nil, ErrInvalidAssociation
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, ErrInvalidAssociation
	}
	var result Association
	seen := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, ErrInvalidAssociation
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return nil, ErrInvalidAssociation
		}
		seen[name] = true
		var rawValue json.RawMessage
		if err := decoder.Decode(&rawValue); err != nil || bytes.Equal(bytes.TrimSpace(rawValue), []byte("null")) {
			return nil, ErrInvalidAssociation
		}
		var value string
		if err := json.Unmarshal(rawValue, &value); err != nil {
			return nil, ErrInvalidAssociation
		}
		if !associationStringScalarsValid(rawValue) {
			return nil, ErrInvalidAssociation
		}
		switch name {
		case "schema":
			result.Schema = value
		case "issuer":
			result.Issuer = value
		case "subject":
			result.Subject = value
		case "target":
			result.Target = Target(value)
		default:
			return nil, ErrInvalidAssociation
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, ErrInvalidAssociation
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidAssociation
	}
	if err := result.Validate(); err != nil {
		return nil, err
	}
	return &result, nil
}

// encoding/json replaces malformed UTF-16 escape pairs rather than failing.
// Ownership identifiers must never be silently normalized into another subject.
func associationStringScalarsValid(raw []byte) bool {
	for i := 1; i+1 < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		if i+5 >= len(raw) {
			return false
		}
		value, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value < 0xd800 || value > 0xdbff {
			continue
		}
		if i+7 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
