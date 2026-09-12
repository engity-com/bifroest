package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	goerrors "errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	remoteDeliveryStateDirectoryName = ".delivery"
	remoteDeliveryCursorFileName     = "cursor.json"
	remoteDeliveryCursorTempFileName = "cursor.tmp"
	remoteDeliveryCursorSchema       = "bifroest.audit-remote-delivery-cursor/v1"
	remoteDeliveryCursorSignDomain   = "BIFROEST-AUDIT-REMOTE-DELIVERY-CURSOR-SIGNATURE/v1\x00"
)

type remoteDeliveryCursorContent struct {
	Schema      string                           `json:"schema"`
	ProducerId  ProducerId                       `json:"producerId"`
	Target      configuration.AuditlogTargetName `json:"target"`
	Sequence    uint64                           `json:"sequence"`
	SegmentHash SegmentHash                      `json:"segmentHash"`
	PublicKey   []byte                           `json:"publicKey"`
}

type remoteDeliveryCursor struct {
	remoteDeliveryCursorContent
	Signature []byte `json:"signature"`
}

func newRemoteDeliveryCursor(identity *Identity, target configuration.AuditlogTargetName, sequence uint64, hash SegmentHash) (remoteDeliveryCursor, []byte, error) {
	if identity == nil || identity.ProducerId().IsZero() {
		return remoteDeliveryCursor{}, nil, errors.Config.Newf("nil audit identity")
	}
	if err := target.Validate(); err != nil {
		return remoteDeliveryCursor{}, nil, errors.Config.Newf("illegal remote target name: %w", err)
	}
	if sequence == 0 || hash.IsZero() {
		return remoteDeliveryCursor{}, nil, errors.System.Newf("remote delivery cursor requires a confirmed segment")
	}
	content := remoteDeliveryCursorContent{
		Schema:      remoteDeliveryCursorSchema,
		ProducerId:  identity.ProducerId(),
		Target:      target,
		Sequence:    sequence,
		SegmentHash: hash,
		PublicKey:   identity.PublicKey().Marshal(),
	}
	unsigned, err := json.Marshal(content)
	if err != nil {
		return remoteDeliveryCursor{}, nil, errors.System.Newf("cannot encode remote delivery cursor: %w", err)
	}
	signature, err := identity.sign(append([]byte(remoteDeliveryCursorSignDomain), unsigned...))
	if err != nil {
		return remoteDeliveryCursor{}, nil, err
	}
	cursor := remoteDeliveryCursor{remoteDeliveryCursorContent: content, Signature: signature}
	payload, err := json.Marshal(cursor)
	if err != nil {
		return remoteDeliveryCursor{}, nil, errors.System.Newf("cannot encode signed remote delivery cursor: %w", err)
	}
	return cursor, payload, nil
}

func decodeRemoteDeliveryCursor(payload []byte, identity *Identity, target configuration.AuditlogTargetName) (remoteDeliveryCursor, error) {
	var cursor remoteDeliveryCursor
	if err := decodeCanonicalJournalPayload(payload, &cursor); err != nil {
		return remoteDeliveryCursor{}, errors.System.Newf("cannot decode remote delivery cursor: %w", err)
	}
	if identity == nil || cursor.Schema != remoteDeliveryCursorSchema || cursor.ProducerId != identity.ProducerId() || cursor.Target != target || !bytes.Equal(cursor.PublicKey, identity.journalPublicKey()) {
		return remoteDeliveryCursor{}, errors.Config.Newf("remote delivery cursor belongs to a different producer or target")
	}
	if cursor.Sequence == 0 || cursor.SegmentHash.IsZero() {
		return remoteDeliveryCursor{}, errors.System.Newf("remote delivery cursor does not confirm a segment")
	}
	unsigned, err := json.Marshal(cursor.remoteDeliveryCursorContent)
	if err != nil {
		return remoteDeliveryCursor{}, errors.System.Newf("cannot re-encode remote delivery cursor: %w", err)
	}
	if err := identity.verify(append([]byte(remoteDeliveryCursorSignDomain), unsigned...), cursor.Signature); err != nil {
		return remoteDeliveryCursor{}, errors.System.Newf("cannot verify remote delivery cursor: %w", err)
	}
	return cursor, nil
}

func prepareRemoteDeliveryState(journalDirectory string, producerId ProducerId) (string, error) {
	root := filepath.Join(journalDirectory, remoteDeliveryStateDirectoryName)
	if err := ensureJournalDirectory(root, true); err != nil {
		return "", errors.System.Newf("cannot prepare remote delivery state directory %q: %w", root, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", errors.System.Newf("cannot inspect remote delivery state directory %q: %w", root, err)
	}
	expected := producerId.String()
	for _, entry := range entries {
		if entry.Name() == journalLockFileName && entry.Type().IsRegular() {
			continue
		}
		if entry.Name() != expected || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return "", errors.Config.Newf("remote delivery state %q contains unsupported entry %q", root, entry.Name())
		}
	}
	producerDirectory := filepath.Join(root, expected)
	if err := ensureJournalDirectory(producerDirectory, true); err != nil {
		return "", errors.System.Newf("cannot prepare remote delivery producer state %q: %w", producerDirectory, err)
	}
	entries, err = os.ReadDir(producerDirectory)
	if err != nil {
		return "", errors.System.Newf("cannot inspect remote delivery producer state %q: %w", producerDirectory, err)
	}
	for _, entry := range entries {
		if !isRemoteDeliveryTargetStateName(entry.Name()) || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return "", errors.Config.Newf("remote delivery producer state %q contains unsupported entry %q", producerDirectory, entry.Name())
		}
	}
	return producerDirectory, nil
}

func loadRemoteDeliveryCursor(producerStateDirectory string, identity *Identity, target configuration.AuditlogTargetName) (remoteDeliveryCursor, error) {
	directory := filepath.Join(producerStateDirectory, remoteDeliveryTargetStateName(target))
	if err := ensureJournalDirectory(directory, true); err != nil {
		return remoteDeliveryCursor{}, errors.System.Newf("cannot prepare state for remote target %q: %w", target, err)
	}
	if err := validateRemoteDeliveryTargetState(directory); err != nil {
		return remoteDeliveryCursor{}, err
	}
	targetPath := filepath.Join(directory, remoteDeliveryCursorFileName)
	temporaryPath := filepath.Join(directory, remoteDeliveryCursorTempFileName)
	cursor, exists, err := readRemoteDeliveryCursor(targetPath, identity, target)
	if err != nil {
		return remoteDeliveryCursor{}, err
	}
	temporary, temporaryExists, temporaryErr := readRemoteDeliveryCursor(temporaryPath, identity, target)
	if temporaryErr != nil {
		if removeErr := removeRemoteDeliveryCursorFile(temporaryPath, directory); removeErr != nil {
			return remoteDeliveryCursor{}, goerrors.Join(temporaryErr, removeErr)
		}
	} else if temporaryExists {
		if exists && temporary.Sequence == cursor.Sequence && temporary.SegmentHash == cursor.SegmentHash {
			if err := removeRemoteDeliveryCursorFile(temporaryPath, directory); err != nil {
				return remoteDeliveryCursor{}, err
			}
			return cursor, nil
		}
		expectedSequence := uint64(1)
		if exists {
			expectedSequence = cursor.Sequence + 1
		}
		if temporary.Sequence != expectedSequence {
			return remoteDeliveryCursor{}, errors.System.Newf("temporary remote delivery cursor for target %q advances from %d to %d", target, expectedSequence-1, temporary.Sequence)
		}
		if err := replaceJournalFile(temporaryPath, targetPath); err != nil {
			return remoteDeliveryCursor{}, errors.System.Newf("cannot recover remote delivery cursor for target %q: %w", target, err)
		}
		if err := syncJournalDirectory(directory); err != nil {
			return remoteDeliveryCursor{}, errors.System.Newf("cannot flush recovered remote delivery cursor for target %q: %w", target, err)
		}
		cursor = temporary
		exists = true
	}
	if !exists {
		return remoteDeliveryCursor{}, nil
	}
	return cursor, nil
}

func remoteDeliveryTargetStateName(target configuration.AuditlogTargetName) string {
	hash := sha256.Sum256([]byte(target.String()))
	return hex.EncodeToString(hash[:])
}

func isRemoteDeliveryTargetStateName(name string) bool {
	if len(name) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(name)
	return err == nil && hex.EncodeToString(decoded) == name
}

func writeRemoteDeliveryCursor(directory string, identity *Identity, target configuration.AuditlogTargetName, sequence uint64, hash SegmentHash) (remoteDeliveryCursor, error) {
	cursor, payload, err := newRemoteDeliveryCursor(identity, target, sequence, hash)
	if err != nil {
		return remoteDeliveryCursor{}, err
	}
	temporary := filepath.Join(directory, remoteDeliveryCursorTempFileName)
	if err := removeRemoteDeliveryCursorFile(temporary, directory); err != nil {
		return remoteDeliveryCursor{}, err
	}
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_RDWR, journalFileMode)
	if err != nil {
		return remoteDeliveryCursor{}, errors.System.Newf("cannot create temporary remote delivery cursor for target %q: %w", target, err)
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if err := secureJournalFile(temporary, file); err != nil {
		_ = file.Close()
		return remoteDeliveryCursor{}, err
	}
	written, err := file.Write(payload)
	if err == nil && written != len(payload) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return remoteDeliveryCursor{}, errors.System.Newf("cannot write remote delivery cursor for target %q: %w", target, err)
	}
	if closeErr != nil {
		return remoteDeliveryCursor{}, errors.System.Newf("cannot close remote delivery cursor for target %q: %w", target, closeErr)
	}
	targetPath := filepath.Join(directory, remoteDeliveryCursorFileName)
	if err := replaceJournalFile(temporary, targetPath); err != nil {
		return remoteDeliveryCursor{}, errors.System.Newf("cannot publish remote delivery cursor for target %q: %w", target, err)
	}
	removeTemporary = false
	if err := syncJournalDirectory(directory); err != nil {
		return remoteDeliveryCursor{}, errors.System.Newf("cannot flush remote delivery cursor for target %q: %w", target, err)
	}
	return cursor, nil
}

func validateRemoteDeliveryTargetState(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return errors.System.Newf("cannot inspect remote delivery target state %q: %w", directory, err)
	}
	for _, entry := range entries {
		if (entry.Name() != remoteDeliveryCursorFileName && entry.Name() != remoteDeliveryCursorTempFileName) || !entry.Type().IsRegular() {
			return errors.Config.Newf("remote delivery target state %q contains unsupported entry %q", directory, entry.Name())
		}
	}
	return nil
}

func readRemoteDeliveryCursor(path string, identity *Identity, target configuration.AuditlogTargetName) (remoteDeliveryCursor, bool, error) {
	pathInfo, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return remoteDeliveryCursor{}, false, nil
	}
	if err != nil {
		return remoteDeliveryCursor{}, false, errors.System.Newf("cannot inspect remote delivery cursor %q: %w", path, err)
	}
	if !pathInfo.Mode().IsRegular() {
		return remoteDeliveryCursor{}, false, errors.Config.Newf("remote delivery cursor %q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return remoteDeliveryCursor{}, false, errors.System.Newf("cannot open remote delivery cursor %q: %w", path, err)
	}
	if err := secureJournalFile(path, file); err != nil {
		_ = file.Close()
		return remoteDeliveryCursor{}, false, err
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) {
		_ = file.Close()
		if err != nil {
			return remoteDeliveryCursor{}, false, errors.System.Newf("cannot inspect open remote delivery cursor %q: %w", path, err)
		}
		return remoteDeliveryCursor{}, false, errors.System.Newf("remote delivery cursor %q changed while opening", path)
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, maxJournalRecordPayloadSize+1))
	closeErr := file.Close()
	if readErr != nil {
		return remoteDeliveryCursor{}, false, errors.System.Newf("cannot read remote delivery cursor %q: %w", path, readErr)
	}
	if closeErr != nil {
		return remoteDeliveryCursor{}, false, errors.System.Newf("cannot close remote delivery cursor %q: %w", path, closeErr)
	}
	if len(payload) > maxJournalRecordPayloadSize {
		return remoteDeliveryCursor{}, false, errors.System.Newf("remote delivery cursor %q exceeds %d bytes", path, maxJournalRecordPayloadSize)
	}
	cursor, err := decodeRemoteDeliveryCursor(payload, identity, target)
	if err != nil {
		return remoteDeliveryCursor{}, false, errors.System.Newf("cannot use remote delivery cursor %q: %w", path, err)
	}
	return cursor, true, nil
}

func removeRemoteDeliveryCursorFile(path, directory string) error {
	err := os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.System.Newf("cannot remove temporary remote delivery cursor %q: %w", path, err)
	}
	if err := syncJournalDirectory(directory); err != nil {
		return errors.System.Newf("cannot flush temporary remote delivery cursor removal: %w", err)
	}
	return nil
}
