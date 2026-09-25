package audit

import (
	"bytes"
	"context"
	goerrors "errors"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func verifyNativeJournals(ctx context.Context, sources []JournalSource, collect bool) (*Verification, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(sources) == 0 {
		return nil, errors.Config.Newf("no audit journals selected")
	}
	result := &Verification{Journals: make([]VerifiedJournal, 0, len(sources))}
	result.withSensitive = true
	budget := &verifierBudget{}
	names := map[string]bool{}
	var directories []os.FileInfo
	prepared := make([]JournalSource, 0, len(sources))
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if source.Name == "" || source.Directory == "" || names[source.Name] {
			return nil, errors.Config.Newf("missing or duplicate audit journal source")
		}
		names[source.Name] = true
		path, err := filepath.EvalSymlinks(source.Directory)
		if err != nil {
			return nil, err
		}
		path, err = filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			return nil, errors.Config.Newf("invalid audit journal directory %q: %v", path, err)
		}
		for _, previous := range directories {
			if os.SameFile(previous, info) {
				return nil, errors.Config.Newf("audit journal directory %q is selected more than once", path)
			}
		}
		directories = append(directories, info)
		source.Directory = path
		prepared = append(prepared, source)
	}
	selectedDirectories := make([]string, len(prepared))
	for index, source := range prepared {
		selectedDirectories[index] = source.Directory
	}
	for _, source := range prepared {
		result.withSensitive = result.withSensitive && source.WithSensitive
		journal, records, err := verifyNativeJournal(ctx, source, collect, budget, selectedDirectories)
		if err != nil {
			return nil, err
		}
		result.Journals = append(result.Journals, journal)
		result.records = append(result.records, records...)
	}
	return result, nil
}

func verifyNativeJournal(ctx context.Context, source JournalSource, collect bool, budget *verifierBudget, selectedDirectories []string) (VerifiedJournal, []VerifiedRecord, error) {
	rootBefore, err := snapshotVerifierDirectory(ctx, source.Directory)
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	journal := VerifiedJournal{Name: source.Name, Directory: source.Directory}
	var records []VerifiedRecord
	verified := verifierDirectorySnapshot{}
	err = forEachJournalDirectoryEntry(ctx, source.Directory, func(entry os.DirEntry) error {
		name := entry.Name()
		if name == journalLockFileName || name == remoteDeliveryStateDirectoryName || name == journalWorkDirectoryName {
			if name == journalLockFileName && entry.Type().IsRegular() || name != journalLockFileName && entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
				return nil
			}
			return errors.Config.Newf("invalid native audit root entry %q", name)
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.Config.Newf("unsupported native audit root entry %q", name)
		}
		var id ProducerId
		if err := id.UnmarshalText([]byte(name)); err != nil {
			return err
		}
		if !source.ExpectedProducerId.IsZero() && id != source.ExpectedProducerId {
			return errors.System.Newf("audit journal %q contains producer %s instead of expected producer %s", source.Name, id, source.ExpectedProducerId)
		}
		before := budget.records
		found, count, snapshot, err := verifyNativeProducer(ctx, source, filepath.Join(source.Directory, name), id, collect, budget, selectedDirectories)
		if err != nil {
			return err
		}
		if journal.ProducerCount == math.MaxUint64 || count > math.MaxUint64-journal.SegmentCount || budget.records-before > math.MaxUint64-journal.RecordCount {
			return errors.System.Newf("native audit counters overflow")
		}
		journal.ProducerCount++
		journal.SegmentCount += count
		journal.RecordCount += budget.records - before
		records = append(records, found...)
		verified.addSnapshot(name, snapshot)
		return nil
	})
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	if journal.ProducerCount == 0 || !source.ExpectedProducerId.IsZero() && journal.ProducerCount != 1 {
		return VerifiedJournal{}, nil, errors.System.Newf("audit journal %q does not contain exactly one expected producer", source.Name)
	}
	after, err := snapshotNativeJournalContent(ctx, source.Directory)
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	rootAfter, err := snapshotVerifierDirectory(ctx, source.Directory)
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	if verified != after || rootBefore != rootAfter {
		return VerifiedJournal{}, nil, errors.System.Newf("audit journal %q changed during verification", source.Name)
	}
	return journal, records, nil
}

func verifyNativeProducer(ctx context.Context, source JournalSource, directory string, id ProducerId, collect bool, budget *verifierBudget, selectedDirectories []string) (result []VerifiedRecord, segmentCount uint64, snapshot verifierDirectorySnapshot, resultErr error) {
	headPath := filepath.Join(directory, nativeHeadFileName)
	headBytes, headSnapshot, err := readVerifierFile(headPath, nativeformat.MaxMetadataPayload)
	if err != nil {
		return nil, 0, verifierDirectorySnapshot{}, err
	}
	unsigned, err := nativeformat.Unmarshal[nativeAuditHead](headBytes, nativeformat.MaxMetadataPayload)
	if err != nil {
		return nil, 0, verifierDirectorySnapshot{}, err
	}
	identity, err := newJournalPublicIdentity(ProducerId(unsigned.ProducerId), unsigned.PublicKey)
	if err != nil || identity.ProducerId() != id {
		return nil, 0, verifierDirectorySnapshot{}, errors.System.Newf("native audit head %q has invalid producer identity: %v", headPath, err)
	}
	head, err := decodeNativeAuditHead(headBytes, identity)
	if err != nil {
		return nil, 0, verifierDirectorySnapshot{}, err
	}
	var identities *bfcrypto.AgeSshIdentities
	if len(source.DecryptionIdentities) > 0 {
		identities, err = bfcrypto.NewAgeSshIdentities(source.DecryptionIdentities)
		if err != nil {
			return nil, 0, verifierDirectorySnapshot{}, err
		}
	}
	encrypted := source.ExpectedEncryptionRecipient != ""
	activeName := nativeActiveClear
	if encrypted {
		activeName = nativeActiveEncrypted
	}
	inventory, err := newNativeSegmentInventory(ctx, directory, activeName, encrypted, nil, func() (*journalSegmentWorkspace, error) {
		return newNativeVerifierWorkspace(selectedDirectories)
	})
	if err != nil {
		return nil, 0, verifierDirectorySnapshot{}, errors.System.Newf("invalid native audit inventory %q: %v", directory, err)
	}
	defer func() {
		if closeErr := inventory.segments.Close(); closeErr != nil {
			result, segmentCount, snapshot = nil, 0, verifierDirectorySnapshot{}
			resultErr = goerrors.Join(resultErr, closeErr)
		}
	}()
	if !inventory.hasHead {
		return nil, 0, verifierDirectorySnapshot{}, errors.System.Newf("invalid native audit inventory %q: missing head", directory)
	}
	pathSnapshot, err := snapshotVerifierPath(directory)
	if err != nil || !pathSnapshot.info.IsDir() {
		return nil, 0, verifierDirectorySnapshot{}, errors.System.Newf("native producer directory %q changed", directory)
	}
	verified := verifierDirectorySnapshot{}
	verified.add(".", pathSnapshot)
	verified.add(nativeHeadFileName, headSnapshot)
	var records []VerifiedRecord
	var seq, count uint64
	var segmentHash, lastRecord journalHash
	var lastInfo os.FileInfo
	var lastDigest [32]byte
	for {
		segment, found, err := inventory.segments.Next(ctx)
		if err != nil {
			return nil, 0, verifierDirectorySnapshot{}, err
		}
		if !found {
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, 0, verifierDirectorySnapshot{}, err
		}
		if seq == math.MaxUint64 || segment.sequence != seq+1 {
			return nil, 0, verifierDirectorySnapshot{}, fmt.Errorf("native audit segment sequence gap or duplicate in %q", directory)
		}
		data, snap, err := readVerifierFile(segment.path, nativeMaxSize)
		if err != nil {
			return nil, 0, verifierDirectorySnapshot{}, err
		}
		batch, hash, last, sealed, err := verifyNativeSegment(ctx, data, identity, source, identities, segment.sequence, segmentHash, lastRecord, budget, collect)
		if err != nil || !sealed || hash != segment.hash {
			return nil, 0, verifierDirectorySnapshot{}, errors.System.Newf("invalid native audit segment %q: %v", segment.path, err)
		}
		verified.add(filepath.Base(segment.path), snap)
		records = append(records, batch...)
		seq, segmentHash, lastRecord, count = segment.sequence, hash, last, count+1
		lastInfo, lastDigest = snap.info, snap.digest
	}
	if inventory.hasActive {
		path := filepath.Join(directory, activeName)
		data, snap, err := readVerifierFile(path, nativeMaxSize)
		if err != nil {
			return nil, 0, verifierDirectorySnapshot{}, err
		}
		verified.add(activeName, snap)
		if err := inventory.segments.Reset(); err != nil {
			return nil, 0, verifierDirectorySnapshot{}, err
		}
		for {
			segment, found, err := inventory.segments.Next(ctx)
			if err != nil {
				return nil, 0, verifierDirectorySnapshot{}, err
			}
			if !found {
				break
			}
			info, err := os.Lstat(segment.path)
			if err != nil {
				return nil, 0, verifierDirectorySnapshot{}, err
			}
			if os.SameFile(info, snap.info) && segment.sequence != seq {
				return nil, 0, verifierDirectorySnapshot{}, fmt.Errorf("native active aliases an earlier published segment")
			}
		}
		if lastInfo != nil && os.SameFile(lastInfo, snap.info) {
			if lastDigest != snap.digest {
				return nil, 0, verifierDirectorySnapshot{}, fmt.Errorf("native active alias changed during verification")
			}
		} else {
			if seq == math.MaxUint64 {
				return nil, 0, verifierDirectorySnapshot{}, fmt.Errorf("native audit sequence overflow")
			}
			found, _, last, _, err := verifyNativeSegment(ctx, data, identity, source, identities, seq+1, segmentHash, lastRecord, budget, collect)
			if err != nil {
				return nil, 0, verifierDirectorySnapshot{}, fmt.Errorf("invalid native active segment %q: %w", path, err)
			}
			records = append(records, found...)
			lastRecord, count = last, count+1
		}
	}
	if journalHash(head.LastRecordHash) != lastRecord {
		return nil, 0, verifierDirectorySnapshot{}, fmt.Errorf("native audit producer %s does not end at its signed head", id)
	}
	headAfter, _, err := readVerifierFile(headPath, nativeformat.MaxMetadataPayload)
	if err != nil || !bytes.Equal(headBytes, headAfter) {
		return nil, 0, verifierDirectorySnapshot{}, fmt.Errorf("native audit head %q changed during verification: %v", headPath, err)
	}
	after, err := snapshotNativeProducerContent(ctx, directory)
	if err != nil {
		return nil, 0, verifierDirectorySnapshot{}, err
	}
	if verified != after {
		return nil, 0, verifierDirectorySnapshot{}, fmt.Errorf("native producer %s changed during verification", id)
	}
	return records, count, after, nil
}

func newNativeVerifierWorkspace(selectedDirectories []string) (*journalSegmentWorkspace, error) {
	temporary, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		return nil, fmt.Errorf("cannot resolve audit verification temporary directory: %w", err)
	}
	temporary, err = filepath.Abs(temporary)
	if err != nil {
		return nil, err
	}
	for _, journal := range selectedDirectories {
		journalInfo, err := os.Stat(journal)
		if err != nil {
			return nil, err
		}
		for parent := temporary; ; parent = filepath.Dir(parent) {
			parentInfo, err := os.Stat(parent)
			if err != nil {
				return nil, err
			}
			if os.SameFile(journalInfo, parentInfo) {
				return nil, fmt.Errorf("audit verification temporary directory %q is inside selected journal %q", temporary, journal)
			}
			if filepath.Dir(parent) == parent {
				break
			}
		}
	}
	return newJournalSegmentWorkspace(temporary)
}

func verifyNativeSegment(ctx context.Context, data []byte, identity journalIdentity, source JournalSource, identities *bfcrypto.AgeSshIdentities, seq uint64, previousSegment, previousRecord journalHash, budget *verifierBudget, collect bool) ([]VerifiedRecord, journalHash, journalHash, bool, error) {
	records, segment, last, sealed, _, err := verifyNativeSegmentUntil(ctx, data, identity, source, identities, seq, previousSegment, previousRecord, budget, collect, nil, false, false)
	return records, segment, last, sealed, err
}

// Active may stop at the checkpoint; a published segment must also validate
// every following unit, its seal and its physical hash without exporting or
// charging records beyond the captured checkpoint.
func verifyNativeSegmentUntil(ctx context.Context, data []byte, identity journalIdentity, source JournalSource, identities *bfcrypto.AgeSshIdentities, seq uint64, previousSegment, previousRecord journalHash, budget *verifierBudget, collect bool, stop *journalHash, published, reached bool) ([]VerifiedRecord, journalHash, journalHash, bool, bool, error) {
	if !bytes.HasPrefix(data, []byte(nativeformat.AuditMagic)) {
		return nil, journalHash{}, journalHash{}, false, false, fmt.Errorf("invalid native audit magic")
	}
	var records []VerifiedRecord
	var count uint64
	var recipient string
	var sealed, header bool
	offset := int64(len(nativeformat.AuditMagic))
	contentEnd := offset
	last := previousRecord
	var segmentHash journalHash
	for offset < int64(len(data)) {
		if err := ctx.Err(); err != nil {
			return nil, journalHash{}, journalHash{}, false, false, err
		}
		unit, next, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(data), offset, int64(len(data)), nativeformat.MaxAuditRecordPayload)
		if err != nil || tail {
			return nil, journalHash{}, journalHash{}, false, false, fmt.Errorf("invalid or uncommitted native audit unit: %v", err)
		}
		switch unit.Type {
		case nativeformat.HeaderUnit:
			if header || offset != int64(len(nativeformat.AuditMagic)) || len(unit.Payload) > nativeformat.MaxMetadataPayload {
				return nil, journalHash{}, journalHash{}, false, false, fmt.Errorf("unexpected native audit header")
			}
			candidate, err := nativeformat.Unmarshal[nativeAuditHeader](unit.Payload, nativeformat.MaxMetadataPayload)
			if err != nil {
				return nil, journalHash{}, journalHash{}, false, false, err
			}
			recipient = candidate.Recipient
			if recipient != source.ExpectedEncryptionRecipient {
				return nil, journalHash{}, journalHash{}, false, false, fmt.Errorf("native audit encryption recipient differs from configured recipient")
			}
			if _, err := decodeNativeAuditHeader(unit.Payload, identity, seq, previousSegment, previousRecord, recipient); err != nil {
				return nil, journalHash{}, journalHash{}, false, false, err
			}
			if source.WithSensitive && recipient != "" && identities == nil {
				return nil, journalHash{}, journalHash{}, false, false, fmt.Errorf("encrypted audit records require a matching decryption identity")
			}
			header = true
			contentEnd = next
			if stop != nil && stop.IsZero() && previousRecord.IsZero() && seq == 1 {
				reached = true
				if !published {
					return records, journalHash{}, last, false, true, nil
				}
			}
		case nativeformat.ContentUnit:
			if !header || sealed || count == math.MaxUint64 {
				return nil, journalHash{}, journalHash{}, false, false, fmt.Errorf("unexpected native audit record")
			}
			decodeIdentities := identities
			withSensitive := source.WithSensitive || len(source.DecryptionIdentities) > 0
			if reached {
				decodeIdentities, withSensitive = nil, false
			}
			r, event, hash, err := decodeNativeAuditRecord(unit.Payload, identity, last, recipient, decodeIdentities, withSensitive)
			if err != nil {
				return nil, journalHash{}, journalHash{}, false, false, err
			}
			if !source.WithSensitive {
				event = Event{Name: event.Name, Domain: event.Domain, Outcome: event.Outcome}
			}
			if !reached {
				if err := budget.consume(int64(len(unit.Payload)), collect); err != nil {
					return nil, journalHash{}, journalHash{}, false, false, err
				}
				if collect {
					at, _ := r.RecordedAt.Time()
					records = append(records, VerifiedRecord{Auditlog: source.Name, ProducerId: identity.ProducerId(), SegmentSequence: seq, SegmentRecordIndex: count, Id: uuid.UUID(r.Id), RecordedAt: at.UTC(), Event: event, PreviousHash: last.String(), Hash: hash.String()})
				}
			}
			count++
			last = hash
			contentEnd = next
			if stop != nil && last == *stop {
				reached = true
				if !published {
					return records, journalHash{}, last, false, true, nil
				}
			}
		case nativeformat.SealUnit:
			if !header || sealed || count == 0 || next != int64(len(data)) || len(unit.Payload) > nativeformat.MaxMetadataPayload || contentEnd != offset {
				return nil, journalHash{}, journalHash{}, false, false, fmt.Errorf("unexpected native audit seal")
			}
			if _, err := decodeNativeAuditSeal(unit.Payload, identity, seq, count, uint64(offset), hashNativeAuditContent(data[:offset]), last); err != nil {
				return nil, journalHash{}, journalHash{}, false, false, err
			}
			sealed = true
			segmentHash = hashNativeAuditSegment(data)
		default:
			return nil, journalHash{}, journalHash{}, false, false, fmt.Errorf("unexpected native audit unit")
		}
		offset = next
	}
	if !header {
		return nil, journalHash{}, journalHash{}, false, false, fmt.Errorf("missing native audit header")
	}
	return records, segmentHash, last, sealed, reached, nil
}

func snapshotNativeProducerContent(ctx context.Context, directory string) (verifierDirectorySnapshot, error) {
	result := verifierDirectorySnapshot{}
	path, err := snapshotVerifierPath(directory)
	if err != nil || !path.info.IsDir() {
		return result, fmt.Errorf("native producer directory %q changed: %v", directory, err)
	}
	result.add(".", path)
	err = forEachJournalDirectoryEntry(ctx, directory, func(entry os.DirEntry) error {
		name := entry.Name()
		if name != nativeHeadFileName && name != nativeActiveClear && name != nativeActiveEncrypted {
			if _, _, clear := parseNativeSegmentName(name, false); !clear {
				if _, _, encrypted := parseNativeSegmentName(name, true); !encrypted {
					return fmt.Errorf("unsupported native audit producer entry %q", name)
				}
			}
		}
		snapshot, err := digestVerifierFile(ctx, filepath.Join(directory, name))
		if err != nil {
			return err
		}
		result.add(name, snapshot)
		return nil
	})
	return result, err
}

func snapshotNativeJournalContent(ctx context.Context, directory string) (verifierDirectorySnapshot, error) {
	result := verifierDirectorySnapshot{}
	err := forEachJournalDirectoryEntry(ctx, directory, func(entry os.DirEntry) error {
		name := entry.Name()
		if name == journalLockFileName || name == journalWorkDirectoryName || name == remoteDeliveryStateDirectoryName {
			return nil
		}
		var id ProducerId
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || id.UnmarshalText([]byte(name)) != nil {
			return fmt.Errorf("unsupported native audit root entry %q", name)
		}
		snapshot, err := snapshotNativeProducerContent(ctx, filepath.Join(directory, name))
		if err == nil {
			result.addSnapshot(name, snapshot)
		}
		return err
	})
	return result, err
}
