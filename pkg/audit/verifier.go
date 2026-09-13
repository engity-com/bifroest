package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	goerrors "errors"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

type JournalSource struct {
	Name                        string
	Directory                   string
	ExpectedProducerId          ProducerId
	ExpectedEncryptionRecipient string
	DecryptionIdentities        []bfcrypto.PrivateKey
}

type VerifiedRecord struct {
	Auditlog           string     `json:"auditlog"`
	ProducerId         ProducerId `json:"producerId"`
	SegmentSequence    uint64     `json:"segmentSequence"`
	SegmentRecordIndex uint64     `json:"segmentRecordIndex"`
	Id                 uuid.UUID  `json:"id"`
	RecordedAt         time.Time  `json:"recordedAt"`
	Event              Event      `json:"event"`
	PreviousHash       string     `json:"previousHash"`
	Hash               string     `json:"hash"`
}

type VerifiedJournal struct {
	Name          string `json:"name"`
	Directory     string `json:"directory"`
	ProducerCount uint64 `json:"producerCount"`
	SegmentCount  uint64 `json:"segmentCount"`
	RecordCount   uint64 `json:"recordCount"`
}

type Verification struct {
	Journals []VerifiedJournal `json:"journals"`
	records  []VerifiedRecord
}

const (
	maxMaterializedVerifiedRecords = 250_000
	maxMaterializedVerifiedBytes   = 64 << 20
)

type verifierBudget struct {
	records uint64
	bytes   int64
}

func (this *verifierBudget) consume(payloadBytes int64, materialize bool) error {
	if materialize && (this.records >= maxMaterializedVerifiedRecords || payloadBytes > maxMaterializedVerifiedBytes-this.bytes) {
		return errors.System.Newf("verified audit output exceeds the materialization limit of %d records or %d bytes", maxMaterializedVerifiedRecords, maxMaterializedVerifiedBytes)
	}
	this.records++
	if materialize {
		this.bytes += payloadBytes
	}
	return nil
}

func (this *Verification) Records() []VerifiedRecord {
	if this == nil {
		return nil
	}
	return append([]VerifiedRecord(nil), this.records...)
}

type verifierSegmentFile struct {
	name     string
	path     string
	sequence uint64
	hash     journalHash
	active   bool
	size     int64
	info     os.FileInfo
	digest   [sha256.Size]byte
}

type verifierDirectorySnapshot struct {
	entries uint64
	digest  [sha256.Size]byte
}

type verifierFileSnapshot struct {
	info       os.FileInfo
	identity   [16]byte
	digest     [sha256.Size]byte
	hasContent bool
}

// VerifyJournalIntegrity verifies bytes read from stable file handles and then
// revalidates the selected journal tree. It does not lock live journals, so a
// writer may change a file after that file's final revalidation.
func VerifyJournalIntegrity(ctx context.Context, sources []JournalSource) error {
	_, err := verifyJournals(ctx, sources, false)
	return err
}

// VerifyJournals has the same point-in-time semantics as VerifyJournalIntegrity
// and materializes records from the handles whose contents were verified.
func VerifyJournals(ctx context.Context, sources []JournalSource) (*Verification, error) {
	return verifyJournals(ctx, sources, true)
}

func verifyJournals(ctx context.Context, sources []JournalSource, collectRecords bool) (*Verification, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(sources) == 0 {
		return nil, errors.Config.Newf("no audit journals selected")
	}
	result := &Verification{Journals: make([]VerifiedJournal, 0, len(sources))}
	budget := &verifierBudget{}
	names := make(map[string]struct{}, len(sources))
	directories := make(map[string]struct{}, len(sources))
	directoryInfos := make([]os.FileInfo, 0, len(sources))
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, errors.System.Newf("audit verification canceled: %w", err)
		}
		if source.Name == "" || source.Directory == "" {
			return nil, errors.Config.Newf("audit journal source name and directory are required")
		}
		if _, exists := names[source.Name]; exists {
			return nil, errors.Config.Newf("audit journal source name %q is duplicated", source.Name)
		}
		names[source.Name] = struct{}{}
		canonical, err := filepath.EvalSymlinks(source.Directory)
		if err != nil {
			return nil, errors.System.Newf("cannot resolve audit journal %q: %w", source.Name, err)
		}
		canonical, err = filepath.Abs(canonical)
		if err != nil {
			return nil, errors.System.Newf("cannot resolve audit journal %q: %w", source.Name, err)
		}
		if _, exists := directories[canonical]; exists {
			return nil, errors.Config.Newf("audit journal directory %q is selected more than once", canonical)
		}
		directoryInfo, err := os.Stat(canonical)
		if err != nil {
			return nil, errors.System.Newf("cannot inspect audit journal %q: %w", source.Name, err)
		}
		for _, selectedInfo := range directoryInfos {
			if os.SameFile(directoryInfo, selectedInfo) {
				return nil, errors.Config.Newf("audit journal directory %q is selected more than once", canonical)
			}
		}
		directories[canonical] = struct{}{}
		directoryInfos = append(directoryInfos, directoryInfo)
		journal, records, err := verifyJournalSource(ctx, JournalSource{
			Name:                        source.Name,
			Directory:                   canonical,
			ExpectedProducerId:          source.ExpectedProducerId,
			ExpectedEncryptionRecipient: source.ExpectedEncryptionRecipient,
			DecryptionIdentities:        source.DecryptionIdentities,
		}, collectRecords, budget)
		if err != nil {
			return nil, err
		}
		result.Journals = append(result.Journals, journal)
		result.records = append(result.records, records...)
	}
	return result, nil
}

func verifyJournalSource(ctx context.Context, source JournalSource, collectRecords bool, budget *verifierBudget) (VerifiedJournal, []VerifiedRecord, error) {
	return verifyJournalSourceWithProducerObserver(ctx, source, collectRecords, budget, nil)
}

func verifyJournalSourceWithProducerObserver(ctx context.Context, source JournalSource, collectRecords bool, budget *verifierBudget, afterProducer func(string) error) (VerifiedJournal, []VerifiedRecord, error) {
	workspace, err := newVerifierJournalSegmentWorkspace(source.Directory)
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	journal, records, verifyErr := verifyJournalSourceInWorkspace(ctx, source, collectRecords, budget, afterProducer, workspace.path)
	if closeErr := workspace.Close(); closeErr != nil {
		return VerifiedJournal{}, nil, goerrors.Join(verifyErr, closeErr)
	}
	return journal, records, verifyErr
}

func verifyJournalSourceInWorkspace(ctx context.Context, source JournalSource, collectRecords bool, budget *verifierBudget, afterProducer func(string) error, workspace string) (VerifiedJournal, []VerifiedRecord, error) {
	rootBefore, err := snapshotVerifierDirectory(ctx, source.Directory)
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	journal := VerifiedJournal{Name: source.Name, Directory: source.Directory}
	var records []VerifiedRecord
	verifiedProducers := verifierDirectorySnapshot{}
	err = forEachJournalDirectoryEntry(ctx, source.Directory, func(entry os.DirEntry) error {
		if entry.Name() == journalLockFileName {
			if !entry.Type().IsRegular() {
				return errors.Config.Newf("audit journal lock %q is not a regular file", filepath.Join(source.Directory, entry.Name()))
			}
			return nil
		}
		if entry.Name() == remoteDeliveryStateDirectoryName {
			if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return errors.Config.Newf("remote delivery state %q is not a directory", filepath.Join(source.Directory, entry.Name()))
			}
			return nil
		}
		if entry.Name() == journalWorkDirectoryName {
			if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return errors.Config.Newf("audit work path %q is not a directory", filepath.Join(source.Directory, entry.Name()))
			}
			return nil
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.Config.Newf("audit journal %q contains unsupported entry %q", source.Name, entry.Name())
		}
		var producerId ProducerId
		if err := producerId.UnmarshalText([]byte(entry.Name())); err != nil {
			return errors.Config.Newf("audit journal %q contains illegal producer directory %q: %w", source.Name, entry.Name(), err)
		}
		if !source.ExpectedProducerId.IsZero() && producerId != source.ExpectedProducerId {
			return errors.System.Newf("audit journal %q contains producer %s instead of expected producer %s", source.Name, producerId, source.ExpectedProducerId)
		}
		beforeRecords := budget.records
		producerRecords, segmentCount, producerSnapshot, err := verifyProducer(ctx, source.Name, filepath.Join(source.Directory, entry.Name()), producerId, source.ExpectedEncryptionRecipient, source.DecryptionIdentities, collectRecords, budget, workspace)
		if err != nil {
			return err
		}
		if journal.ProducerCount == ^uint64(0) || segmentCount > ^uint64(0)-journal.SegmentCount {
			return errors.System.Newf("audit journal %q counters overflow", source.Name)
		}
		journal.ProducerCount++
		journal.SegmentCount += segmentCount
		journal.RecordCount += budget.records - beforeRecords
		records = append(records, producerRecords...)
		verifiedProducers.addSnapshot(entry.Name(), producerSnapshot)
		if afterProducer != nil {
			return afterProducer(entry.Name())
		}
		return nil
	})
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	if journal.ProducerCount == 0 {
		return VerifiedJournal{}, nil, errors.System.Newf("audit journal %q contains no producers", source.Name)
	}
	if !source.ExpectedProducerId.IsZero() && journal.ProducerCount != 1 {
		return VerifiedJournal{}, nil, errors.System.Newf("audit journal %q does not contain exactly one expected producer", source.Name)
	}
	contentAfter, err := snapshotVerifierJournalContent(ctx, source.Directory)
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	rootAfter, err := snapshotVerifierDirectory(ctx, source.Directory)
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	if verifiedProducers != contentAfter || !equalVerifierDirectorySnapshots(rootBefore, rootAfter) {
		return VerifiedJournal{}, nil, errors.System.Newf("audit journal %q changed during verification", source.Name)
	}
	return journal, records, nil
}

func verifyProducer(ctx context.Context, auditlogName, directory string, producerId ProducerId, expectedEncryptionRecipient string, decryptionIdentities []bfcrypto.PrivateKey, collectRecords bool, budget *verifierBudget, workspace string) ([]VerifiedRecord, uint64, verifierDirectorySnapshot, error) {
	decrypter, err := newJournalEventDecrypter(decryptionIdentities)
	if err != nil {
		return nil, 0, verifierDirectorySnapshot{}, err
	}
	headPath := filepath.Join(directory, journalHeadFileName)
	headBefore, headSnapshot, err := readVerifierFile(headPath, maxJournalRecordPayloadSize)
	if err != nil {
		return nil, 0, verifierDirectorySnapshot{}, err
	}
	var unsignedHead journalHead
	if err := decodeCanonicalJournalPayload(headBefore, &unsignedHead); err != nil {
		return nil, 0, verifierDirectorySnapshot{}, errors.System.Newf("cannot decode audit journal head %q: %w", headPath, err)
	}
	identity, err := newJournalPublicIdentity(unsignedHead.ProducerId, unsignedHead.PublicKey)
	if err != nil {
		return nil, 0, verifierDirectorySnapshot{}, errors.System.Newf("cannot verify audit journal head %q: %w", headPath, err)
	}
	if identity.ProducerId() != producerId {
		return nil, 0, verifierDirectorySnapshot{}, errors.System.Newf("audit producer directory %q does not match its signed identity", directory)
	}
	head, err := decodeJournalHead(headBefore, identity)
	if err != nil {
		return nil, 0, verifierDirectorySnapshot{}, errors.System.Newf("cannot verify audit journal head %q: %w", headPath, err)
	}

	state := journalSegmentState{checkpointHash: head.LastRecordHash, checkpointSeen: head.LastRecordHash.IsZero()}
	var records []VerifiedRecord
	emit := func(sequence uint64) func(journalRecord, journalHash, uint64, int64) error {
		return func(record journalRecord, recordHash journalHash, index uint64, payloadBytes int64) error {
			if err := ctx.Err(); err != nil {
				return errors.System.Newf("audit verification canceled: %w", err)
			}
			if err := budget.consume(payloadBytes, collectRecords); err != nil {
				return err
			}
			if record.encryptionRecipient != "" && decrypter == nil {
				return errors.Config.Newf("encrypted audit records require a matching decryption identity")
			}
			if !collectRecords {
				return nil
			}
			records = append(records, VerifiedRecord{
				Auditlog:           auditlogName,
				ProducerId:         record.ProducerId,
				SegmentSequence:    sequence,
				SegmentRecordIndex: index,
				Id:                 record.Id,
				RecordedAt:         record.RecordedAt.UTC(),
				Event:              record.Event,
				PreviousHash:       record.PreviousHash.String(),
				Hash:               recordHash.String(),
			})
			return nil
		}
	}

	producerSnapshot, err := snapshotVerifierPath(directory)
	if err != nil || !producerSnapshot.info.IsDir() {
		return nil, 0, verifierDirectorySnapshot{}, errors.System.Newf("audit producer directory %q changed before verification", directory)
	}
	verifiedSnapshot := verifierDirectorySnapshot{}
	verifiedSnapshot.add(".", producerSnapshot)
	verifiedSnapshot.add(journalHeadFileName, headSnapshot)

	segments, active, err := newVerifierSegmentInventory(ctx, directory, workspace)
	if err != nil {
		return nil, 0, verifierDirectorySnapshot{}, err
	}
	closeSegments := func(cause error) error {
		return goerrors.Join(cause, segments.Close())
	}
	var activeAliasDigest *[sha256.Size]byte
	var segmentCount uint64
	previousSegmentName := ""
	for {
		candidate, found, err := segments.Next(ctx)
		if err != nil {
			return nil, 0, verifierDirectorySnapshot{}, closeSegments(err)
		}
		if !found {
			break
		}
		if candidate.sequence == state.sequence {
			return nil, 0, verifierDirectorySnapshot{}, closeSegments(errors.System.Newf("audit producer directory %q contains multiple segments %q and %q with sequence %d", directory, previousSegmentName, candidate.name, candidate.sequence))
		}
		if state.sequence == math.MaxUint64 || candidate.sequence != state.sequence+1 {
			return nil, 0, verifierDirectorySnapshot{}, closeSegments(errors.System.Newf("audit segment sequence does not continue after %d", state.sequence))
		}
		info, err := os.Lstat(candidate.path)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxJournalSegmentFileSize {
			return nil, 0, verifierDirectorySnapshot{}, closeSegments(errors.System.Newf("audit segment %q changed before verification", candidate.path))
		}
		segment := verifierSegmentFile{name: candidate.name, path: candidate.path, sequence: candidate.sequence, hash: candidate.hash, size: info.Size(), info: info}
		scanned, fileSnapshot, err := verifyJournalSegmentFile(&segment, identity, state, expectedEncryptionRecipient, decrypter, emit(segment.sequence))
		if err != nil {
			return nil, 0, verifierDirectorySnapshot{}, closeSegments(err)
		}
		if !scanned.sealed || scanned.segmentHash != segment.hash {
			return nil, 0, verifierDirectorySnapshot{}, closeSegments(errors.System.Newf("audit segment %q does not match its sealed file name", segment.path))
		}
		verifiedSnapshot.add(segment.name, fileSnapshot)
		if active != nil && os.SameFile(active.info, segment.info) {
			copyOfDigest := fileSnapshot.digest
			activeAliasDigest = &copyOfDigest
		}
		if segmentCount == math.MaxUint64 {
			return nil, 0, verifierDirectorySnapshot{}, closeSegments(errors.System.Newf("audit segment count overflows"))
		}
		segmentCount++
		state = scanned
		previousSegmentName = segment.name
	}
	if err := segments.Close(); err != nil {
		return nil, 0, verifierDirectorySnapshot{}, err
	}
	if active != nil {
		if activeAliasDigest != nil {
			fileSnapshot, err := digestVerifierFile(ctx, active.path)
			if err != nil {
				return nil, 0, verifierDirectorySnapshot{}, err
			}
			if fileSnapshot.info.Size() != active.size || !os.SameFile(fileSnapshot.info, active.info) || fileSnapshot.digest != *activeAliasDigest {
				return nil, 0, verifierDirectorySnapshot{}, errors.System.Newf("active audit segment %q changed during verification", active.path)
			}
			verifiedSnapshot.add(active.name, fileSnapshot)
		} else {
			if state.sequence == math.MaxUint64 {
				return nil, 0, verifierDirectorySnapshot{}, errors.System.Newf("audit segment sequence overflows after %d", state.sequence)
			}
			scanned, fileSnapshot, err := verifyJournalSegmentFile(active, identity, state, expectedEncryptionRecipient, decrypter, emit(state.sequence+1))
			if err != nil {
				return nil, 0, verifierDirectorySnapshot{}, errors.System.Newf("cannot verify active audit segment %q: %w", active.path, err)
			}
			verifiedSnapshot.add(active.name, fileSnapshot)
			state = scanned
			if segmentCount == math.MaxUint64 {
				return nil, 0, verifierDirectorySnapshot{}, errors.System.Newf("audit segment count overflows")
			}
			segmentCount++
		}
	}
	if !state.checkpointSeen || state.previousRecordHash != head.LastRecordHash {
		return nil, 0, verifierDirectorySnapshot{}, errors.System.Newf("audit producer %s does not end at its signed journal head", producerId)
	}
	headAfter, _, err := readVerifierFile(headPath, maxJournalRecordPayloadSize)
	if err != nil {
		return nil, 0, verifierDirectorySnapshot{}, err
	}
	contentAfter, err := snapshotVerifierProducerContent(ctx, directory)
	if err != nil {
		return nil, 0, verifierDirectorySnapshot{}, err
	}
	if !bytes.Equal(headBefore, headAfter) || verifiedSnapshot != contentAfter {
		return nil, 0, verifierDirectorySnapshot{}, errors.System.Newf("audit producer %s changed during verification", producerId)
	}
	return records, segmentCount, contentAfter, nil
}

func newVerifierSegmentInventory(ctx context.Context, directory, workspace string) (*sortedJournalSegmentIterator, *verifierSegmentFile, error) {
	var active *verifierSegmentFile
	segments, err := newSortedJournalSegmentIterator(ctx, directory, workspace, func(entry os.DirEntry) (*journalSegmentFile, error) {
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return nil, errors.System.Newf("cannot inspect audit producer entry %q: %w", path, err)
		}
		if entry.Name() == journalHeadFileName {
			if !info.Mode().IsRegular() {
				return nil, errors.Config.Newf("audit journal head %q is not a regular file", path)
			}
			return nil, nil
		}
		if entry.Name() == journalHeadTempFileName {
			return nil, errors.System.Newf("audit producer directory %q contains an interrupted journal-head update", directory)
		}
		if !info.Mode().IsRegular() {
			return nil, errors.Config.Newf("audit producer directory %q contains unsupported entry %q", directory, entry.Name())
		}
		if info.Size() < 0 || info.Size() > maxJournalSegmentFileSize {
			return nil, errors.System.Newf("audit segment %q exceeds %d bytes", path, maxJournalSegmentFileSize)
		}
		if entry.Name() == journalActiveFileName {
			candidate := verifierSegmentFile{name: entry.Name(), path: path, active: true, size: info.Size(), info: info}
			active = &candidate
			return nil, nil
		}
		sequence, hash, ok := parseSealedJournalFileName(entry.Name())
		if !ok {
			return nil, errors.Config.Newf("audit producer directory %q contains unsupported entry %q", directory, entry.Name())
		}
		return &journalSegmentFile{name: entry.Name(), path: path, sequence: sequence, hash: hash}, nil
	})
	if err != nil {
		return nil, nil, err
	}
	return segments, active, nil
}

func verifyJournalSegmentFile(segment *verifierSegmentFile, identity journalIdentity, state journalSegmentState, expectedEncryptionRecipient string, decrypter *journalEventDecrypter, emit func(journalRecord, journalHash, uint64, int64) error) (journalSegmentState, verifierFileSnapshot, error) {
	file, err := openVerifierFile(segment.path)
	if err != nil {
		return journalSegmentState{}, verifierFileSnapshot{}, err
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || openedInfo.Size() != segment.size || !os.SameFile(segment.info, openedInfo) {
		_ = file.Close()
		return journalSegmentState{}, verifierFileSnapshot{}, errors.System.Newf("audit segment %q changed before verification", segment.path)
	}
	openedIdentity, err := verifierFileIdentity(segment.path, file, openedInfo)
	if err != nil {
		_ = file.Close()
		return journalSegmentState{}, verifierFileSnapshot{}, err
	}
	sequence := segment.sequence
	if segment.active {
		sequence = state.sequence + 1
	}
	digestWriter := sha256.New()
	scanned, scanErr := scanJournalSegment(file, journalSegmentScanOptions{
		identity:                    identity,
		sequence:                    sequence,
		previousSegmentHash:         state.segmentHash,
		previousRecordHash:          state.previousRecordHash,
		checkpointHash:              state.checkpointHash,
		checkpointSeen:              state.checkpointSeen,
		expectedEncryptionRecipient: expectedEncryptionRecipient,
		decrypter:                   decrypter,
		emit:                        emit,
		digest:                      digestWriter,
	})
	afterInfo, afterStatErr := file.Stat()
	if scanErr != nil {
		_ = file.Close()
		return journalSegmentState{}, verifierFileSnapshot{}, errors.System.Newf("cannot verify audit segment %q: %w", segment.path, scanErr)
	}
	if afterStatErr != nil || afterInfo.Size() != segment.size || !os.SameFile(openedInfo, afterInfo) {
		_ = file.Close()
		return journalSegmentState{}, verifierFileSnapshot{}, errors.System.Newf("audit segment %q changed during verification", segment.path)
	}
	afterIdentity, err := verifierFileIdentity(segment.path, file, afterInfo)
	if err != nil {
		_ = file.Close()
		return journalSegmentState{}, verifierFileSnapshot{}, err
	}
	if openedIdentity != afterIdentity {
		_ = file.Close()
		return journalSegmentState{}, verifierFileSnapshot{}, errors.System.Newf("audit segment %q changed during verification", segment.path)
	}
	closeErr := file.Close()
	if closeErr != nil {
		return journalSegmentState{}, verifierFileSnapshot{}, errors.System.Newf("cannot close audit segment %q: %w", segment.path, closeErr)
	}
	var digest [sha256.Size]byte
	copy(digest[:], digestWriter.Sum(nil))
	return scanned, verifierFileSnapshot{info: afterInfo, identity: afterIdentity, digest: digest, hasContent: true}, nil
}

func snapshotVerifierProducerContent(ctx context.Context, directory string) (verifierDirectorySnapshot, error) {
	result := verifierDirectorySnapshot{}
	directorySnapshot, err := snapshotVerifierPath(directory)
	if err != nil {
		return verifierDirectorySnapshot{}, err
	}
	if !directorySnapshot.info.IsDir() {
		return verifierDirectorySnapshot{}, errors.Config.Newf("audit producer path %q is not a directory", directory)
	}
	result.add(".", directorySnapshot)
	err = forEachJournalDirectoryEntry(ctx, directory, func(entry os.DirEntry) error {
		if entry.Name() == journalHeadTempFileName {
			return errors.System.Newf("audit producer directory %q contains an interrupted journal-head update", directory)
		}
		if entry.Name() != journalHeadFileName && entry.Name() != journalActiveFileName {
			if _, _, ok := parseSealedJournalFileName(entry.Name()); !ok {
				return errors.Config.Newf("audit producer directory %q contains unsupported entry %q", directory, entry.Name())
			}
		}
		path := filepath.Join(directory, entry.Name())
		fileSnapshot, err := digestVerifierFile(ctx, path)
		if err != nil {
			return err
		}
		result.add(entry.Name(), fileSnapshot)
		return nil
	})
	if err != nil {
		return verifierDirectorySnapshot{}, err
	}
	return result, nil
}

func snapshotVerifierJournalContent(ctx context.Context, directory string) (verifierDirectorySnapshot, error) {
	result := verifierDirectorySnapshot{}
	err := forEachJournalDirectoryEntry(ctx, directory, func(entry os.DirEntry) error {
		if entry.Name() == journalLockFileName {
			if !entry.Type().IsRegular() {
				return errors.Config.Newf("audit journal lock %q is not a regular file", filepath.Join(directory, entry.Name()))
			}
			return nil
		}
		if entry.Name() == remoteDeliveryStateDirectoryName {
			if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return errors.Config.Newf("remote delivery state %q is not a directory", filepath.Join(directory, entry.Name()))
			}
			return nil
		}
		if entry.Name() == journalWorkDirectoryName {
			if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return errors.Config.Newf("audit work path %q is not a directory", filepath.Join(directory, entry.Name()))
			}
			return nil
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.Config.Newf("audit journal contains unsupported entry %q", entry.Name())
		}
		var producerId ProducerId
		if err := producerId.UnmarshalText([]byte(entry.Name())); err != nil {
			return errors.Config.Newf("audit journal contains illegal producer directory %q: %w", entry.Name(), err)
		}
		snapshot, err := snapshotVerifierProducerContent(ctx, filepath.Join(directory, entry.Name()))
		if err != nil {
			return err
		}
		result.addSnapshot(entry.Name(), snapshot)
		return nil
	})
	if err != nil {
		return verifierDirectorySnapshot{}, err
	}
	return result, nil
}

func (this *verifierDirectorySnapshot) add(name string, file verifierFileSnapshot) {
	hash := sha256.New()
	_, _ = io.WriteString(hash, "BIFROEST-AUDIT-VERIFIER-DIRECTORY-ENTRY/v1\x00")
	var fixed [8]byte
	binary.BigEndian.PutUint64(fixed[:], uint64(len(name)))
	_, _ = hash.Write(fixed[:])
	_, _ = io.WriteString(hash, name)
	binary.BigEndian.PutUint64(fixed[:], uint64(file.info.Mode()))
	_, _ = hash.Write(fixed[:])
	binary.BigEndian.PutUint64(fixed[:], uint64(file.info.Size()))
	_, _ = hash.Write(fixed[:])
	binary.BigEndian.PutUint64(fixed[:], uint64(file.info.ModTime().UnixNano()))
	_, _ = hash.Write(fixed[:])
	_, _ = hash.Write(file.identity[:])
	if file.hasContent {
		_, _ = hash.Write([]byte{1})
		_, _ = hash.Write(file.digest[:])
	} else {
		_, _ = hash.Write([]byte{0})
	}
	this.addDigest(hash.Sum(nil))
}

func (this *verifierDirectorySnapshot) addSnapshot(name string, snapshot verifierDirectorySnapshot) {
	hash := sha256.New()
	_, _ = io.WriteString(hash, "BIFROEST-AUDIT-VERIFIER-PRODUCER-SNAPSHOT/v1\x00")
	var fixed [8]byte
	binary.BigEndian.PutUint64(fixed[:], uint64(len(name)))
	_, _ = hash.Write(fixed[:])
	_, _ = io.WriteString(hash, name)
	binary.BigEndian.PutUint64(fixed[:], snapshot.entries)
	_, _ = hash.Write(fixed[:])
	_, _ = hash.Write(snapshot.digest[:])
	this.addDigest(hash.Sum(nil))
}

func (this *verifierDirectorySnapshot) addDigest(entryDigest []byte) {
	carry := uint16(0)
	for index := len(this.digest) - 1; index >= 0; index-- {
		sum := uint16(this.digest[index]) + uint16(entryDigest[index]) + carry
		this.digest[index] = byte(sum)
		carry = sum >> 8
	}
	this.entries++
}

func equalVerifierDirectorySnapshots(left, right verifierDirectorySnapshot) bool {
	return left == right
}

func snapshotVerifierDirectory(ctx context.Context, directory string) (verifierDirectorySnapshot, error) {
	result := verifierDirectorySnapshot{}
	directorySnapshot, err := snapshotVerifierPath(directory)
	if err != nil {
		return verifierDirectorySnapshot{}, err
	}
	if !directorySnapshot.info.IsDir() {
		return verifierDirectorySnapshot{}, errors.Config.Newf("audit journal path %q is not a directory", directory)
	}
	result.add(".", directorySnapshot)
	err = forEachJournalDirectoryEntry(ctx, directory, func(entry os.DirEntry) error {
		if entry.Name() == remoteDeliveryStateDirectoryName || entry.Name() == journalWorkDirectoryName {
			return nil
		}
		fileSnapshot, err := snapshotVerifierPath(filepath.Join(directory, entry.Name()))
		if err != nil {
			return errors.System.Newf("cannot inspect audit directory entry %q: %w", entry.Name(), err)
		}
		result.add(entry.Name(), fileSnapshot)
		return nil
	})
	if err != nil {
		return verifierDirectorySnapshot{}, err
	}
	return result, nil
}

func equalVerifierSegments(left, right []verifierSegmentFile) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].name != right[index].name || left[index].size != right[index].size || left[index].active != right[index].active || left[index].digest != right[index].digest || !os.SameFile(left[index].info, right[index].info) {
			return false
		}
	}
	return true
}

func digestVerifierFile(ctx context.Context, path string) (verifierFileSnapshot, error) {
	file, err := openVerifierFile(path)
	if err != nil {
		return verifierFileSnapshot{}, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return verifierFileSnapshot{}, errors.System.Newf("cannot inspect audit file %q before hashing: %w", path, err)
	}
	identity, err := verifierFileIdentity(path, file, info)
	if err != nil {
		_ = file.Close()
		return verifierFileSnapshot{}, err
	}
	maximum := int64(maxJournalSegmentFileSize)
	if info.Size() > maximum {
		_ = file.Close()
		return verifierFileSnapshot{}, errors.System.Newf("audit segment %q exceeds %d bytes", path, maximum)
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			_ = file.Close()
			return verifierFileSnapshot{}, errors.System.Newf("audit verification canceled: %w", err)
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			total += int64(read)
			if total > maximum {
				_ = file.Close()
				return verifierFileSnapshot{}, errors.System.Newf("audit segment %q exceeds %d bytes", path, maximum)
			}
			_, _ = hash.Write(buffer[:read])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = file.Close()
			return verifierFileSnapshot{}, errors.System.Newf("cannot hash audit file %q: %w", path, readErr)
		}
	}
	infoAfter, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return verifierFileSnapshot{}, errors.System.Newf("cannot inspect audit file %q after hashing: %w", path, err)
	}
	if info.Size() != infoAfter.Size() || !os.SameFile(info, infoAfter) {
		_ = file.Close()
		return verifierFileSnapshot{}, errors.System.Newf("audit file %q changed while hashing", path)
	}
	identityAfter, err := verifierFileIdentity(path, file, infoAfter)
	if err != nil {
		_ = file.Close()
		return verifierFileSnapshot{}, err
	}
	if identity != identityAfter {
		_ = file.Close()
		return verifierFileSnapshot{}, errors.System.Newf("audit file %q changed while hashing", path)
	}
	closeErr := file.Close()
	if closeErr != nil {
		return verifierFileSnapshot{}, errors.System.Newf("cannot close audit file %q after hashing: %w", path, closeErr)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return verifierFileSnapshot{info: infoAfter, identity: identityAfter, digest: digest, hasContent: true}, nil
}

func readVerifierFile(path string, maximum int64) ([]byte, verifierFileSnapshot, error) {
	file, err := openVerifierFile(path)
	if err != nil {
		return nil, verifierFileSnapshot{}, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, verifierFileSnapshot{}, errors.System.Newf("cannot inspect audit file %q before reading: %w", path, err)
	}
	identity, err := verifierFileIdentity(path, file, info)
	if err != nil {
		_ = file.Close()
		return nil, verifierFileSnapshot{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		_ = file.Close()
		return nil, verifierFileSnapshot{}, errors.System.Newf("cannot read audit file %q: %w", path, err)
	}
	if int64(len(raw)) > maximum {
		_ = file.Close()
		return nil, verifierFileSnapshot{}, errors.System.Newf("audit file %q exceeds %d bytes", path, maximum)
	}
	infoAfter, err := file.Stat()
	if err != nil || info.Size() != infoAfter.Size() || !os.SameFile(info, infoAfter) {
		_ = file.Close()
		return nil, verifierFileSnapshot{}, errors.System.Newf("audit file %q changed while reading", path)
	}
	identityAfter, err := verifierFileIdentity(path, file, infoAfter)
	if err != nil {
		_ = file.Close()
		return nil, verifierFileSnapshot{}, err
	}
	if identity != identityAfter {
		_ = file.Close()
		return nil, verifierFileSnapshot{}, errors.System.Newf("audit file %q changed while reading", path)
	}
	if err := file.Close(); err != nil {
		return nil, verifierFileSnapshot{}, errors.System.Newf("cannot close audit file %q: %w", path, err)
	}
	return raw, verifierFileSnapshot{info: infoAfter, identity: identityAfter, digest: sha256.Sum256(raw), hasContent: true}, nil
}

func snapshotVerifierPath(path string) (verifierFileSnapshot, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return verifierFileSnapshot{}, errors.System.Newf("cannot inspect audit path %q: %w", path, err)
	}
	if !pathInfo.Mode().IsRegular() && !pathInfo.IsDir() {
		return verifierFileSnapshot{}, errors.Config.Newf("audit path %q is neither a regular file nor a directory", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return verifierFileSnapshot{}, errors.System.Newf("cannot open audit path %q: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) {
		_ = file.Close()
		return verifierFileSnapshot{}, errors.System.Newf("audit path %q changed while opening", path)
	}
	identity, err := verifierFileIdentity(path, file, info)
	if err != nil {
		_ = file.Close()
		return verifierFileSnapshot{}, err
	}
	if err := file.Close(); err != nil {
		return verifierFileSnapshot{}, errors.System.Newf("cannot close audit path %q: %w", path, err)
	}
	return verifierFileSnapshot{info: info, identity: identity}, nil
}

func openVerifierFile(path string) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errors.System.Newf("required audit file %q does not exist: %w", path, err)
		}
		return nil, errors.System.Newf("cannot inspect audit file %q: %w", path, err)
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.Config.Newf("audit file %q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.System.Newf("cannot open audit file %q: %w", path, err)
	}
	fileInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, errors.System.Newf("cannot inspect open audit file %q: %w", path, err)
	}
	if !os.SameFile(pathInfo, fileInfo) {
		_ = file.Close()
		return nil, errors.System.Newf("audit file %q changed while opening", path)
	}
	return file, nil
}
