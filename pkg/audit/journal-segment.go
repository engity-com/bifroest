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
