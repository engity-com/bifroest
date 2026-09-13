package audit

import (
	"context"
	"encoding/binary"
	"encoding/json"
	goerrors "errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	defaultJournalSegmentTargetSize = 16 << 20
	maxJournalSegmentFileSize       = defaultJournalSegmentTargetSize + maxJournalRecordPayloadSize*2
	journalSegmentFilePrefix        = "segment-"
	journalSegmentFileSuffix        = ".journal"
)

type journalSegmentState struct {
	sequence            uint64
	previousSegmentHash journalHash
	previousRecordHash  journalHash
	recordCount         uint64
	contentBytes        int64
	fileBytes           int64
	segmentHash         journalHash
	sealed              bool
	header              bool
	checkpointHash      journalHash
	checkpointSeen      bool
}

type journalSegmentScanOptions struct {
	identity                    journalIdentity
	sequence                    uint64
	previousSegmentHash         journalHash
	previousRecordHash          journalHash
	checkpointHash              journalHash
	checkpointSeen              bool
	recoverTail                 bool
	expectedEncryptionRecipient string
	decrypter                   *journalEventDecrypter
	emit                        func(journalRecord, journalHash, uint64, int64) error
	digest                      io.Writer
}

type journalSegmentScanner struct {
	file    *os.File
	options journalSegmentScanOptions
	state   journalSegmentState
	size    int64
	offset  int64
}

type journalSegmentFile struct {
	name     string
	path     string
	sequence uint64
	hash     journalHash
}

func recoverJournalSegments(producerDirectory, activePath string, identity *Identity, checkpointHash journalHash, expectedEncryptionRecipient string) (*os.File, journalSegmentState, error) {
	workspace, err := newRecorderJournalSegmentWorkspace(filepath.Dir(producerDirectory))
	if err != nil {
		return nil, journalSegmentState{}, err
	}
	file, state, recoverErr := recoverJournalSegmentsInWorkspace(producerDirectory, activePath, identity, checkpointHash, expectedEncryptionRecipient, workspace.path)
	if closeErr := workspace.Close(); closeErr != nil {
		if file != nil {
			_ = file.Close()
		}
		return nil, journalSegmentState{}, goerrors.Join(recoverErr, closeErr)
	}
	return file, state, recoverErr
}

func recoverJournalSegmentsInWorkspace(producerDirectory, activePath string, identity *Identity, checkpointHash journalHash, expectedEncryptionRecipient, workspace string) (*os.File, journalSegmentState, error) {
	inventory, err := newJournalSegmentInventory(context.Background(), producerDirectory, workspace)
	if err != nil {
		return nil, journalSegmentState{}, err
	}
	closeInventory := func(cause error) error {
		return goerrors.Join(cause, inventory.segments.Close())
	}
	state := journalSegmentState{checkpointHash: checkpointHash, checkpointSeen: checkpointHash.IsZero()}
	for {
		segment, found, err := inventory.segments.Next(context.Background())
		if err != nil {
			return nil, journalSegmentState{}, closeInventory(err)
		}
		if !found {
			break
		}
		if segment.sequence != state.sequence+1 {
			return nil, journalSegmentState{}, closeInventory(errors.System.Newf("audit segment sequence jumps from %d to %d", state.sequence, segment.sequence))
		}
		file, err := openSealedJournal(segment.path)
		if err != nil {
			return nil, journalSegmentState{}, closeInventory(err)
		}
		scanned, scanErr := scanJournalSegment(file, journalSegmentScanOptions{
			identity:                    identity,
			sequence:                    segment.sequence,
			previousSegmentHash:         state.segmentHash,
			previousRecordHash:          state.previousRecordHash,
			checkpointHash:              state.checkpointHash,
			checkpointSeen:              state.checkpointSeen,
			expectedEncryptionRecipient: expectedEncryptionRecipient,
		})
		closeErr := file.Close()
		if scanErr != nil {
			return nil, journalSegmentState{}, closeInventory(errors.System.Newf("cannot verify sealed audit segment %q: %w", segment.path, scanErr))
		}
		if closeErr != nil {
			return nil, journalSegmentState{}, closeInventory(errors.System.Newf("cannot close sealed audit segment %q: %w", segment.path, closeErr))
		}
		if !scanned.sealed || scanned.segmentHash != segment.hash {
			return nil, journalSegmentState{}, closeInventory(errors.System.Newf("sealed audit segment %q does not match its file name", segment.path))
		}
		state = scanned
	}
	if err := inventory.segments.Close(); err != nil {
		return nil, journalSegmentState{}, err
	}

	nextSequence := state.sequence + 1
	if !inventory.hasActive {
		if !state.checkpointSeen {
			return nil, journalSegmentState{}, errors.System.Newf("audit journal does not contain its committed head %s", checkpointHash)
		}
		return createActiveJournal(activePath, identity, nextSequence, state.segmentHash, state.previousRecordHash)
	}
	if err := makeActiveJournalWritable(activePath); err != nil {
		return nil, journalSegmentState{}, err
	}
	file, err := openActiveJournal(activePath)
	if err != nil {
		return nil, journalSegmentState{}, err
	}
	active, err := scanJournalSegment(file, journalSegmentScanOptions{
		identity:                    identity,
		sequence:                    nextSequence,
		previousSegmentHash:         state.segmentHash,
		previousRecordHash:          state.previousRecordHash,
		checkpointHash:              state.checkpointHash,
		checkpointSeen:              state.checkpointSeen,
		recoverTail:                 true,
		expectedEncryptionRecipient: expectedEncryptionRecipient,
	})
	if err != nil {
		_ = file.Close()
		return nil, journalSegmentState{}, errors.System.Newf("cannot recover active audit segment %q: %w", activePath, err)
	}
	if !active.checkpointSeen {
		_ = file.Close()
		return nil, journalSegmentState{}, errors.System.Newf("audit journal does not contain its committed head %s", checkpointHash)
	}
	if !active.header {
		_ = file.Close()
		if err := os.Remove(activePath); err != nil {
			return nil, journalSegmentState{}, errors.System.Newf("cannot remove empty interrupted audit segment %q: %w", activePath, err)
		}
		if err := syncJournalDirectory(producerDirectory); err != nil {
			return nil, journalSegmentState{}, errors.System.Newf("cannot flush removal of interrupted audit segment: %w", err)
		}
		return createActiveJournal(activePath, identity, nextSequence, state.segmentHash, state.previousRecordHash)
	}
	if active.sealed {
		if err := sealJournalFile(activePath, file); err != nil {
			_ = file.Close()
			return nil, journalSegmentState{}, err
		}
		if err := file.Close(); err != nil {
			return nil, journalSegmentState{}, errors.System.Newf("cannot close recovered sealed audit segment: %w", err)
		}
		if err := finishPublishingSegment(activePath, producerDirectory, active); err != nil {
			return nil, journalSegmentState{}, err
		}
		return createActiveJournal(activePath, identity, active.sequence+1, active.segmentHash, active.previousRecordHash)
	}
	if active.recordCount > 0 {
		sealed, err := sealActiveJournal(file, activePath, producerDirectory, identity, active, time.Now().UTC())
		if err != nil {
			return nil, journalSegmentState{}, err
		}
		return createActiveJournal(activePath, identity, sealed.sequence+1, sealed.segmentHash, sealed.previousRecordHash)
	}
	return file, active, nil
}

func createActiveJournal(path string, identity *Identity, sequence uint64, previousSegmentHash, previousRecordHash journalHash) (*os.File, journalSegmentState, error) {
	file, err := openActiveJournal(path)
	if err != nil {
		return nil, journalSegmentState{}, err
	}
	header, payload, err := newJournalSegmentHeader(identity, sequence, previousSegmentHash, previousRecordHash, time.Now().UTC())
	if err != nil {
		_ = file.Close()
		return nil, journalSegmentState{}, err
	}
	_ = header
	frame, err := encodeJournalFrame(payload)
	if err != nil {
		_ = file.Close()
		return nil, journalSegmentState{}, err
	}
	if err := writeCommittedJournalFrame(file, frame); err != nil {
		_ = file.Close()
		return nil, journalSegmentState{}, err
	}
	return file, journalSegmentState{
		sequence:            sequence,
		previousSegmentHash: previousSegmentHash,
		previousRecordHash:  previousRecordHash,
		contentBytes:        int64(len(frame)),
		fileBytes:           int64(len(frame)),
		header:              true,
		checkpointSeen:      true,
	}, nil
}

func sealActiveJournal(file *os.File, activePath, producerDirectory string, identity *Identity, state journalSegmentState, sealedAt time.Time) (journalSegmentState, error) {
	content, err := readJournalFilePrefix(file, state.contentBytes)
	if err != nil {
		return journalSegmentState{}, err
	}
	contentHash := hashJournalBytes(journalSegmentContentHashDomain, content)
	_, payload, err := newJournalSegmentSeal(identity, state.sequence, state.recordCount, uint64(state.contentBytes), contentHash, state.previousRecordHash, sealedAt)
	if err != nil {
		return journalSegmentState{}, err
	}
	frame, err := encodeJournalFrame(payload)
	if err != nil {
		return journalSegmentState{}, err
	}
	if err := writeCommittedJournalFrame(file, frame); err != nil {
		return journalSegmentState{}, err
	}
	state.fileBytes = state.contentBytes + int64(len(frame))
	full, err := readJournalFilePrefix(file, state.fileBytes)
	if err != nil {
		return journalSegmentState{}, err
	}
	state.segmentHash = hashJournalBytes(journalSegmentHashDomain, full)
	state.sealed = true
	if err := sealJournalFile(activePath, file); err != nil {
		return journalSegmentState{}, err
	}
	if err := file.Close(); err != nil {
		return journalSegmentState{}, errors.System.Newf("cannot close sealed audit segment: %w", err)
	}
	if err := finishPublishingSegment(activePath, producerDirectory, state); err != nil {
		return journalSegmentState{}, err
	}
	return state, nil
}

func finishPublishingSegment(activePath, producerDirectory string, state journalSegmentState) error {
	target := filepath.Join(producerDirectory, sealedJournalFileName(state.sequence, state.segmentHash))
	if err := publishJournalFile(activePath, target); err != nil {
		return errors.System.Newf("cannot publish sealed audit segment %q: %w", target, err)
	}
	if err := syncJournalDirectory(producerDirectory); err != nil {
		return errors.System.Newf("cannot flush published audit segment %q: %w", target, err)
	}
	return nil
}

func scanJournalSegment(file *os.File, options journalSegmentScanOptions) (journalSegmentState, error) {
	scanner, err := newJournalSegmentScanner(file, options)
	if err != nil {
		return journalSegmentState{}, err
	}
	if err := scanner.scan(); err != nil {
		return journalSegmentState{}, err
	}
	return scanner.state, nil
}

func newJournalSegmentScanner(file *os.File, options journalSegmentScanOptions) (*journalSegmentScanner, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, errors.System.Newf("cannot inspect audit segment: %w", err)
	}
	return &journalSegmentScanner{
		file:    file,
		options: options,
		size:    info.Size(),
		state: journalSegmentState{
			sequence:            options.sequence,
			previousSegmentHash: options.previousSegmentHash,
			previousRecordHash:  options.previousRecordHash,
			fileBytes:           info.Size(),
			checkpointHash:      options.checkpointHash,
			checkpointSeen:      options.checkpointSeen,
		},
	}, nil
}

func (this *journalSegmentScanner) scan() error {
	for this.offset < this.size {
		complete, err := this.scanNextFrame()
		if err != nil {
			return err
		}
		if !complete {
			return nil
		}
	}
	if !this.state.header && this.size > 0 {
		return errors.System.Newf("audit segment has no valid header")
	}
	return nil
}

func (this *journalSegmentScanner) scanNextFrame() (bool, error) {
	payload, frame, frameSize, incomplete, err := readJournalFrameBytes(this.file, this.offset, this.size)
	if err != nil {
		return false, err
	}
	if incomplete {
		return false, this.recoverIncompleteTail()
	}
	var envelope struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return false, errors.System.Newf("cannot identify audit frame at offset %d: %w", this.offset, err)
	}
	switch envelope.Schema {
	case journalSegmentHeaderSchema:
		err = this.scanHeader(payload, frameSize)
	case journalRecordSchema, journalEncryptedRecordSchema:
		err = this.scanRecord(payload, frameSize)
	case journalSegmentSealSchema:
		err = this.scanSeal(payload, frameSize)
	default:
		err = errors.System.Newf("unsupported audit frame schema %q at offset %d", envelope.Schema, this.offset)
	}
	if err != nil {
		return false, err
	}
	if err := this.writeDigest(frame); err != nil {
		return false, err
	}
	this.offset += frameSize
	return true, nil
}

func (this *journalSegmentScanner) recoverIncompleteTail() error {
	if !this.options.recoverTail {
		return errors.System.Newf("sealed audit segment has an incomplete frame at offset %d", this.offset)
	}
	if !this.state.checkpointSeen {
		return errors.System.Newf("audit journal cannot discard an incomplete frame before its committed head %s", this.options.checkpointHash)
	}
	if err := truncateJournalTail(this.file, this.offset); err != nil {
		return err
	}
	this.state.fileBytes = this.offset
	return nil
}

func (this *journalSegmentScanner) scanHeader(payload []byte, frameSize int64) error {
	if this.offset != 0 || this.state.header {
		return errors.System.Newf("unexpected audit segment header at offset %d", this.offset)
	}
	if _, err := decodeJournalSegmentHeader(payload, this.options.identity, this.options.sequence, this.options.previousSegmentHash, this.options.previousRecordHash); err != nil {
		return err
	}
	this.state.header = true
	this.state.contentBytes = frameSize
	return nil
}

func (this *journalSegmentScanner) scanRecord(payload []byte, frameSize int64) error {
	if !this.state.header || this.state.sealed {
		return errors.System.Newf("audit record outside an open segment at offset %d", this.offset)
	}
	record, recordHash, err := decodeJournalRecord(payload, this.options.identity, this.state.previousRecordHash, this.options.decrypter)
	if err != nil {
		return err
	}
	if record.encryptionRecipient != this.options.expectedEncryptionRecipient {
		return errors.Config.Newf("audit record encryption recipient %q does not match configured recipient %q", record.encryptionRecipient, this.options.expectedEncryptionRecipient)
	}
	this.state.previousRecordHash = recordHash
	if recordHash == this.state.checkpointHash {
		this.state.checkpointSeen = true
	}
	this.state.recordCount++
	if this.options.emit != nil {
		if err := this.options.emit(record, recordHash, this.state.recordCount, int64(len(payload))); err != nil {
			return err
		}
	}
	this.state.contentBytes = this.offset + frameSize
	return nil
}

func (this *journalSegmentScanner) scanSeal(payload []byte, frameSize int64) error {
	if !this.state.header || this.state.sealed || this.state.recordCount == 0 {
		return errors.System.Newf("unexpected audit segment seal at offset %d", this.offset)
	}
	content, err := readJournalFilePrefix(this.file, this.state.contentBytes)
	if err != nil {
		return err
	}
	if _, err := decodeJournalSegmentSeal(payload, this.options.identity, this.state, hashJournalBytes(journalSegmentContentHashDomain, content)); err != nil {
		return err
	}
	this.state.sealed = true
	this.state.fileBytes = this.offset + frameSize
	if this.state.fileBytes != this.size {
		return errors.System.Newf("audit segment contains data after its seal")
	}
	full, err := readJournalFilePrefix(this.file, this.state.fileBytes)
	if err != nil {
		return err
	}
	this.state.segmentHash = hashJournalBytes(journalSegmentHashDomain, full)
	return nil
}

func (this *journalSegmentScanner) writeDigest(frame []byte) error {
	if this.options.digest == nil {
		return nil
	}
	written, err := this.options.digest.Write(frame)
	if err == nil && written != len(frame) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return errors.System.Newf("cannot hash audit frame at offset %d: %w", this.offset, err)
	}
	return nil
}

func readJournalFrame(file *os.File, offset, size int64) ([]byte, int64, bool, error) {
	payload, _, frameSize, incomplete, err := readJournalFrameBytes(file, offset, size)
	return payload, frameSize, incomplete, err
}

func readJournalFrameBytes(file *os.File, offset, size int64) ([]byte, []byte, int64, bool, error) {
	remaining := size - offset
	if remaining < journalFrameLengthSize {
		return nil, nil, 0, true, nil
	}
	length := make([]byte, journalFrameLengthSize)
	if _, err := file.ReadAt(length, offset); err != nil {
		return nil, nil, 0, false, errors.System.Newf("cannot read audit frame length: %w", err)
	}
	payloadSize := int64(binary.BigEndian.Uint32(length))
	if payloadSize <= 0 || payloadSize > maxJournalRecordPayloadSize {
		committed, err := journalTailHasCommitMarker(file, offset, size)
		if err != nil {
			return nil, nil, 0, false, err
		}
		if !committed {
			return nil, nil, 0, true, nil
		}
		return nil, nil, 0, false, errors.System.Newf("illegal audit frame size %d at offset %d", payloadSize, offset)
	}
	frameSize := int64(journalFrameLengthSize+journalFrameChecksumSize+len(journalFrameCommitMarker)) + payloadSize
	if remaining < frameSize {
		committed, err := journalTailHasCommitMarker(file, offset, size)
		if err != nil {
			return nil, nil, 0, false, err
		}
		if committed {
			return nil, nil, 0, false, errors.System.Newf("audit frame at offset %d has a corrupted size", offset)
		}
		return nil, nil, frameSize, true, nil
	}
	frame := make([]byte, frameSize)
	if _, err := file.ReadAt(frame, offset); err != nil {
		return nil, nil, 0, false, errors.System.Newf("cannot read audit frame: %w", err)
	}
	payload := frame[journalFrameLengthSize : journalFrameLengthSize+payloadSize]
	checksumOffset := journalFrameLengthSize + payloadSize
	if string(frame[checksumOffset+journalFrameChecksumSize:]) != journalFrameCommitMarker {
		return nil, nil, 0, false, errors.System.Newf("audit frame commit marker mismatch at offset %d", offset)
	}
	if binary.BigEndian.Uint32(frame[checksumOffset:]) != crc32.Checksum(payload, journalChecksumTable) {
		return nil, nil, 0, false, errors.System.Newf("audit frame checksum mismatch at offset %d", offset)
	}
	return payload, frame, frameSize, false, nil
}

func journalTailHasCommitMarker(file *os.File, offset, size int64) (bool, error) {
	if size-offset < int64(len(journalFrameCommitMarker)) {
		return false, nil
	}
	marker := make([]byte, len(journalFrameCommitMarker))
	if _, err := file.ReadAt(marker, size-int64(len(marker))); err != nil {
		return false, errors.System.Newf("cannot inspect audit frame tail: %w", err)
	}
	return string(marker) == journalFrameCommitMarker, nil
}

func readJournalFilePrefix(file *os.File, size int64) ([]byte, error) {
	if size < 0 || size > maxJournalSegmentFileSize {
		return nil, errors.System.Newf("illegal audit segment size %d", size)
	}
	content := make([]byte, size)
	if _, err := io.ReadFull(io.NewSectionReader(file, 0, size), content); err != nil {
		return nil, errors.System.Newf("cannot read audit segment content: %w", err)
	}
	return content, nil
}

type journalSegmentInventory struct {
	segments  *sortedJournalSegmentIterator
	hasActive bool
}

func newJournalSegmentInventory(ctx context.Context, directory, tempDirectory string) (*journalSegmentInventory, error) {
	var activeInfo os.FileInfo
	activePath := filepath.Join(directory, journalActiveFileName)
	segments, err := newSortedJournalSegmentIterator(ctx, directory, tempDirectory, func(entry os.DirEntry) (*journalSegmentFile, error) {
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return nil, errors.System.Newf("cannot inspect audit producer entry %q: %w", path, err)
		}
		if entry.Name() == journalActiveFileName {
			if !info.Mode().IsRegular() || activeInfo != nil {
				return nil, errors.Config.Newf("illegal active audit segment in %q", directory)
			}
			activeInfo = info
			return nil, nil
		}
		if entry.Name() == journalHeadFileName {
			if !info.Mode().IsRegular() {
				return nil, errors.Config.Newf("illegal audit journal head in %q", directory)
			}
			return nil, nil
		}
		sequence, hash, ok := parseSealedJournalFileName(entry.Name())
		if !ok || !info.Mode().IsRegular() {
			return nil, errors.Config.Newf("audit producer directory %q contains unsupported entry %q", directory, entry.Name())
		}
		return &journalSegmentFile{name: entry.Name(), path: path, sequence: sequence, hash: hash}, nil
	})
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*journalSegmentInventory, error) {
		return nil, goerrors.Join(cause, segments.Close())
	}
	hasActive := activeInfo != nil
	activeAlias := false
	if hasActive {
		current, err := os.Lstat(activePath)
		if err != nil || !current.Mode().IsRegular() || !os.SameFile(activeInfo, current) {
			return fail(errors.System.Newf("active audit segment %q changed during inventory", activePath))
		}
		for {
			segment, found, err := segments.Next(ctx)
			if err != nil {
				return fail(err)
			}
			if !found {
				break
			}
			info, err := os.Lstat(segment.path)
			if err != nil {
				return fail(errors.System.Newf("cannot inspect sealed audit segment %q: %w", segment.path, err))
			}
			if os.SameFile(activeInfo, info) {
				activeAlias = true
				break
			}
		}
		if err := segments.Reset(); err != nil {
			return fail(err)
		}
	}
	if activeAlias {
		if err := os.Remove(activePath); err != nil {
			return fail(errors.System.Newf("cannot finish publishing active audit segment: %w", err))
		}
		if err := syncJournalDirectory(directory); err != nil {
			return fail(errors.System.Newf("cannot flush recovered audit segment publication: %w", err))
		}
		hasActive = false
	}
	return &journalSegmentInventory{segments: segments, hasActive: hasActive}, nil
}

func sealedJournalFileName(sequence uint64, hash journalHash) string {
	return journalSegmentFilePrefix + leftPadUint(sequence, 20) + "-" + hash.String() + journalSegmentFileSuffix
}

func parseSealedJournalFileName(name string) (uint64, journalHash, bool) {
	if !strings.HasPrefix(name, journalSegmentFilePrefix) || !strings.HasSuffix(name, journalSegmentFileSuffix) {
		return 0, journalHash{}, false
	}
	middle := strings.TrimSuffix(strings.TrimPrefix(name, journalSegmentFilePrefix), journalSegmentFileSuffix)
	if len(middle) != 20+1+64 || middle[20] != '-' {
		return 0, journalHash{}, false
	}
	sequence, err := strconv.ParseUint(middle[:20], 10, 64)
	if err != nil || sequence == 0 {
		return 0, journalHash{}, false
	}
	var hash journalHash
	if err := hash.UnmarshalText([]byte(middle[21:])); err != nil {
		return 0, journalHash{}, false
	}
	if sealedJournalFileName(sequence, hash) != name {
		return 0, journalHash{}, false
	}
	return sequence, hash, true
}

func leftPadUint(value uint64, width int) string {
	raw := strconv.FormatUint(value, 10)
	return strings.Repeat("0", width-len(raw)) + raw
}
