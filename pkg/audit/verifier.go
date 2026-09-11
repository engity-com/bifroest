package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
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

type verifierDirectoryEntry struct {
	name string
	mode os.FileMode
	info os.FileInfo
}

func VerifyJournalIntegrity(ctx context.Context, sources []JournalSource) error {
	_, err := verifyJournals(ctx, sources, false)
	return err
}

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
	rootBefore, err := snapshotVerifierDirectory(source.Directory)
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	entries, err := os.ReadDir(source.Directory)
	if err != nil {
		return VerifiedJournal{}, nil, errors.System.Newf("cannot inspect audit journal %q: %w", source.Name, err)
	}
	journal := VerifiedJournal{Name: source.Name, Directory: source.Directory}
	var records []VerifiedRecord
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return VerifiedJournal{}, nil, errors.System.Newf("audit verification canceled: %w", err)
		}
		if entry.Name() == journalLockFileName {
			if !entry.Type().IsRegular() {
				return VerifiedJournal{}, nil, errors.Config.Newf("audit journal lock %q is not a regular file", filepath.Join(source.Directory, entry.Name()))
			}
			continue
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return VerifiedJournal{}, nil, errors.Config.Newf("audit journal %q contains unsupported entry %q", source.Name, entry.Name())
		}
		var producerId ProducerId
		if err := producerId.UnmarshalText([]byte(entry.Name())); err != nil {
			return VerifiedJournal{}, nil, errors.Config.Newf("audit journal %q contains illegal producer directory %q: %w", source.Name, entry.Name(), err)
		}
		if !source.ExpectedProducerId.IsZero() && producerId != source.ExpectedProducerId {
			return VerifiedJournal{}, nil, errors.System.Newf("audit journal %q contains producer %s instead of expected producer %s", source.Name, producerId, source.ExpectedProducerId)
		}
		beforeRecords := budget.records
		producerRecords, segmentCount, err := verifyProducer(ctx, source.Name, filepath.Join(source.Directory, entry.Name()), producerId, source.ExpectedEncryptionRecipient, source.DecryptionIdentities, collectRecords, budget)
		if err != nil {
			return VerifiedJournal{}, nil, err
		}
		journal.ProducerCount++
		journal.SegmentCount += segmentCount
		journal.RecordCount += budget.records - beforeRecords
		records = append(records, producerRecords...)
	}
	if journal.ProducerCount == 0 {
		return VerifiedJournal{}, nil, errors.System.Newf("audit journal %q contains no producers", source.Name)
	}
	if !source.ExpectedProducerId.IsZero() && journal.ProducerCount != 1 {
		return VerifiedJournal{}, nil, errors.System.Newf("audit journal %q does not contain exactly one expected producer", source.Name)
	}
	rootAfter, err := snapshotVerifierDirectory(source.Directory)
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	if !equalVerifierDirectorySnapshots(rootBefore, rootAfter) {
		return VerifiedJournal{}, nil, errors.System.Newf("audit journal %q changed during verification", source.Name)
	}
	return journal, records, nil
}

func verifyProducer(ctx context.Context, auditlogName, directory string, producerId ProducerId, expectedEncryptionRecipient string, decryptionIdentities []bfcrypto.PrivateKey, collectRecords bool, budget *verifierBudget) ([]VerifiedRecord, uint64, error) {
	decrypter, err := newJournalEventDecrypter(decryptionIdentities)
	if err != nil {
		return nil, 0, err
	}
	headPath := filepath.Join(directory, journalHeadFileName)
	headBefore, err := readVerifierFile(headPath, maxJournalRecordPayloadSize)
	if err != nil {
		return nil, 0, err
	}
	var unsignedHead journalHead
	if err := decodeCanonicalJournalPayload(headBefore, &unsignedHead); err != nil {
		return nil, 0, errors.System.Newf("cannot decode audit journal head %q: %w", headPath, err)
	}
	identity, err := newJournalPublicIdentity(unsignedHead.ProducerId, unsignedHead.PublicKey)
	if err != nil {
		return nil, 0, errors.System.Newf("cannot verify audit journal head %q: %w", headPath, err)
	}
	if identity.ProducerId() != producerId {
		return nil, 0, errors.System.Newf("audit producer directory %q does not match its signed identity", directory)
	}
	head, err := decodeJournalHead(headBefore, identity)
	if err != nil {
		return nil, 0, errors.System.Newf("cannot verify audit journal head %q: %w", headPath, err)
	}

	segmentsBefore, err := inspectVerifierSegments(ctx, directory)
	if err != nil {
		return nil, 0, err
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

	var active *verifierSegmentFile
	for index := range segmentsBefore {
		segment := &segmentsBefore[index]
		if segment.active {
			active = segment
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, 0, errors.System.Newf("audit verification canceled: %w", err)
		}
		if state.sequence == math.MaxUint64 || segment.sequence != state.sequence+1 {
			return nil, 0, errors.System.Newf("audit segment sequence does not continue after %d", state.sequence)
		}
		file, err := openVerifierFile(segment.path)
		if err != nil {
			return nil, 0, err
		}
		scanned, scanErr := scanJournalSegment(file, identity, segment.sequence, state.segmentHash, state.previousRecordHash, state.checkpointHash, state.checkpointSeen, false, expectedEncryptionRecipient, decrypter, emit(segment.sequence))
		closeErr := file.Close()
		if scanErr != nil {
			return nil, 0, errors.System.Newf("cannot verify audit segment %q: %w", segment.path, scanErr)
		}
		if closeErr != nil {
			return nil, 0, errors.System.Newf("cannot close audit segment %q: %w", segment.path, closeErr)
		}
		if !scanned.sealed || scanned.segmentHash != segment.hash {
			return nil, 0, errors.System.Newf("audit segment %q does not match its sealed file name", segment.path)
		}
		state = scanned
	}
	if active != nil {
		if state.sequence == math.MaxUint64 {
			return nil, 0, errors.System.Newf("audit segment sequence overflows after %d", state.sequence)
		}
		file, err := openVerifierFile(active.path)
		if err != nil {
			return nil, 0, err
		}
		scanned, scanErr := scanJournalSegment(file, identity, state.sequence+1, state.segmentHash, state.previousRecordHash, state.checkpointHash, state.checkpointSeen, false, expectedEncryptionRecipient, decrypter, emit(state.sequence+1))
		closeErr := file.Close()
		if scanErr != nil {
			return nil, 0, errors.System.Newf("cannot verify active audit segment %q: %w", active.path, scanErr)
		}
		if closeErr != nil {
			return nil, 0, errors.System.Newf("cannot close active audit segment %q: %w", active.path, closeErr)
		}
		state = scanned
	}
	if !state.checkpointSeen || state.previousRecordHash != head.LastRecordHash {
		return nil, 0, errors.System.Newf("audit producer %s does not end at its signed journal head", producerId)
	}
	headAfter, err := readVerifierFile(headPath, maxJournalRecordPayloadSize)
	if err != nil {
		return nil, 0, err
	}
	segmentsAfter, err := inspectVerifierSegments(ctx, directory)
	if err != nil {
		return nil, 0, err
	}
	if !bytes.Equal(headBefore, headAfter) || !equalVerifierSegments(segmentsBefore, segmentsAfter) {
		return nil, 0, errors.System.Newf("audit producer %s changed during verification", producerId)
	}
	return records, uint64(len(segmentsBefore)), nil
}

func inspectVerifierSegments(ctx context.Context, directory string) ([]verifierSegmentFile, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, errors.System.Newf("cannot inspect audit producer directory %q: %w", directory, err)
	}
	var segments []verifierSegmentFile
	activeIndex := -1
	for _, entry := range entries {
		if entry.Name() == journalHeadFileName {
			continue
		}
		if entry.Name() == journalHeadTempFileName {
			return nil, errors.System.Newf("audit producer directory %q contains an interrupted journal-head update", directory)
		}
		if !entry.Type().IsRegular() {
			return nil, errors.Config.Newf("audit producer directory %q contains unsupported entry %q", directory, entry.Name())
		}
		path := filepath.Join(directory, entry.Name())
		info, digest, err := digestVerifierFile(ctx, path)
		if err != nil {
			return nil, err
		}
		if entry.Name() == journalActiveFileName {
			segments = append(segments, verifierSegmentFile{name: entry.Name(), path: path, active: true, size: info.Size(), info: info, digest: digest})
			activeIndex = len(segments) - 1
			continue
		}
		sequence, hash, ok := parseSealedJournalFileName(entry.Name())
		if !ok {
			return nil, errors.Config.Newf("audit producer directory %q contains unsupported entry %q", directory, entry.Name())
		}
		segments = append(segments, verifierSegmentFile{name: entry.Name(), path: path, sequence: sequence, hash: hash, size: info.Size(), info: info, digest: digest})
	}
	if activeIndex >= 0 {
		activeInfo, err := os.Stat(segments[activeIndex].path)
		if err != nil {
			return nil, errors.System.Newf("cannot inspect active audit segment: %w", err)
		}
		for index := range segments {
			if index == activeIndex || segments[index].active {
				continue
			}
			sealedInfo, err := os.Stat(segments[index].path)
			if err != nil {
				return nil, errors.System.Newf("cannot inspect sealed audit segment: %w", err)
			}
			if os.SameFile(activeInfo, sealedInfo) {
				segments = append(segments[:activeIndex], segments[activeIndex+1:]...)
				break
			}
		}
	}
	sort.Slice(segments, func(left, right int) bool {
		if segments[left].active != segments[right].active {
			return !segments[left].active
		}
		return segments[left].sequence < segments[right].sequence
	})
	return segments, nil
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

func digestVerifierFile(ctx context.Context, path string) (os.FileInfo, [sha256.Size]byte, error) {
	file, err := openVerifierFile(path)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, [sha256.Size]byte{}, errors.System.Newf("cannot inspect audit file %q before hashing: %w", path, err)
	}
	maximum := int64(defaultJournalSegmentTargetSize + maxJournalRecordPayloadSize*2)
	if info.Size() > maximum {
		_ = file.Close()
		return nil, [sha256.Size]byte{}, errors.System.Newf("audit segment %q exceeds %d bytes", path, maximum)
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			_ = file.Close()
			return nil, [sha256.Size]byte{}, errors.System.Newf("audit verification canceled: %w", err)
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			total += int64(read)
			if total > maximum {
				_ = file.Close()
				return nil, [sha256.Size]byte{}, errors.System.Newf("audit segment %q exceeds %d bytes", path, maximum)
			}
			_, _ = hash.Write(buffer[:read])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = file.Close()
			return nil, [sha256.Size]byte{}, errors.System.Newf("cannot hash audit file %q: %w", path, readErr)
		}
	}
	infoAfter, err := file.Stat()
	closeErr := file.Close()
	if err != nil {
		return nil, [sha256.Size]byte{}, errors.System.Newf("cannot inspect audit file %q after hashing: %w", path, err)
	}
	if info.Size() != infoAfter.Size() || !os.SameFile(info, infoAfter) {
		return nil, [sha256.Size]byte{}, errors.System.Newf("audit file %q changed while hashing", path)
	}
	if closeErr != nil {
		return nil, [sha256.Size]byte{}, errors.System.Newf("cannot close audit file %q after hashing: %w", path, closeErr)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return infoAfter, digest, nil
}

func snapshotVerifierDirectory(directory string) ([]verifierDirectoryEntry, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, errors.System.Newf("cannot inspect audit directory %q: %w", directory, err)
	}
	result := make([]verifierDirectoryEntry, 0, len(entries))
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, errors.System.Newf("cannot inspect audit directory entry %q: %w", entry.Name(), err)
		}
		result = append(result, verifierDirectoryEntry{name: entry.Name(), mode: info.Mode(), info: info})
	}
	return result, nil
}

func equalVerifierDirectorySnapshots(left, right []verifierDirectoryEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].name != right[index].name || left[index].mode != right[index].mode || !os.SameFile(left[index].info, right[index].info) {
			return false
		}
	}
	return true
}

func readVerifierFile(path string, maximum int64) ([]byte, error) {
	file, err := openVerifierFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, errors.System.Newf("cannot read audit file %q: %w", path, err)
	}
	if int64(len(raw)) > maximum {
		return nil, errors.System.Newf("audit file %q exceeds %d bytes", path, maximum)
	}
	return raw, nil
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
