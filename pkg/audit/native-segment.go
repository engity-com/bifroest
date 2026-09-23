package audit

import (
	"bytes"
	"context"
	"encoding/binary"
	goerrors "errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

const (
	nativeActiveClear           = "active.baudit"
	nativeActiveEncrypted       = "active.beaudit"
	nativeTargetSize      int64 = 16 << 20
	nativeMaxSize         int64 = 17 << 20
)

type nativeSegmentState struct {
	seq, count                           uint64
	prevSegment, lastRecord, segmentHash journalHash
	contentBytes, fileBytes              int64
	sealed, checkpointSeen               bool
}

type nativeSegmentEntry struct {
	path string
	seq  uint64
	hash journalHash
}

func nativeSegmentName(seq uint64, hash journalHash, encrypted bool) string {
	ext := ".baudit"
	if encrypted {
		ext = ".beaudit"
	}
	return "segment-" + leftPadUint(seq, 20) + "-" + hash.String() + ext
}

func parseNativeSegmentName(name string, encrypted bool) (uint64, journalHash, bool) {
	ext := ".baudit"
	if encrypted {
		ext = ".beaudit"
	}
	if !strings.HasPrefix(name, "segment-") || !strings.HasSuffix(name, ext) {
		return 0, journalHash{}, false
	}
	middle := strings.TrimSuffix(strings.TrimPrefix(name, "segment-"), ext)
	if len(middle) != 85 || middle[20] != '-' {
		return 0, journalHash{}, false
	}
	seq, err := strconv.ParseUint(middle[:20], 10, 64)
	if err != nil || seq == 0 {
		return 0, journalHash{}, false
	}
	var hash journalHash
	if hash.UnmarshalText([]byte(middle[21:])) != nil || nativeSegmentName(seq, hash, encrypted) != name {
		return 0, journalHash{}, false
	}
	return seq, hash, true
}

func nativeOpenRegular(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular native audit file: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = f.Close()
		return nil, fmt.Errorf("native audit file changed: %s: %v", path, err)
	}
	return f, nil
}

func nativeReadFile(f *os.File) ([]byte, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() < 0 || info.Size() > nativeMaxSize {
		return nil, fmt.Errorf("native audit segment exceeds size cap: %d", info.Size())
	}
	data := make([]byte, int(info.Size()))
	_, err = io.ReadFull(io.NewSectionReader(f, 0, info.Size()), data)
	return data, err
}

func nativeInventory(directory, activeName string, encrypted bool) ([]nativeSegmentEntry, bool, bool, error) {
	return nativeInventorySkippingTemps(directory, activeName, encrypted, nil)
}

// Keep the slice-based inventory for in-package test helpers. Production recovery
// and verification consume newNativeSegmentInventory directly without collecting it.
func nativeInventorySkippingTemps(directory, activeName string, encrypted bool, temps map[string]struct{}) ([]nativeSegmentEntry, bool, bool, error) {
	inventory, err := newNativeSegmentInventory(context.Background(), directory, activeName, encrypted, temps, func() (*journalSegmentWorkspace, error) {
		return newRecorderJournalSegmentWorkspace(filepath.Dir(directory))
	})
	if err != nil {
		return nil, false, false, err
	}
	var segments []nativeSegmentEntry
	for {
		segment, found, nextErr := inventory.segments.Next(context.Background())
		if nextErr != nil {
			return nil, false, false, goerrors.Join(nextErr, inventory.segments.Close())
		}
		if !found {
			if err := inventory.segments.Close(); err != nil {
				return nil, false, false, err
			}
			return segments, inventory.hasActive, inventory.hasHead, nil
		}
		segments = append(segments, nativeSegmentEntry{segment.path, segment.sequence, segment.hash})
	}
}

type nativeSegmentInventory struct {
	segments           *sortedJournalSegmentIterator
	hasActive, hasHead bool
}

func newNativeSegmentInventory(ctx context.Context, directory, activeName string, encrypted bool, temps map[string]struct{}, workspace func() (*journalSegmentWorkspace, error)) (*nativeSegmentInventory, error) {
	inventory := &nativeSegmentInventory{}
	segments, err := newSortedJournalSegmentIteratorWithWorkspace(ctx, directory, workspace, func(entry os.DirEntry) (*journalSegmentFile, error) {
		name := entry.Name()
		if _, ok := temps[name]; ok {
			return nil, nil
		}
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("unsupported native audit entry %q", name)
		}
		switch name {
		case activeName:
			inventory.hasActive = true
			return nil, nil
		case nativeHeadFileName:
			inventory.hasHead = true
			return nil, nil
		default:
			seq, hash, ok := parseNativeSegmentName(name, encrypted)
			if !ok {
				return nil, fmt.Errorf("unsupported native audit entry %q", name)
			}
			return &journalSegmentFile{name: name, path: path, sequence: seq, hash: hash}, nil
		}
	})
	if err != nil {
		return nil, err
	}
	inventory.segments = segments
	return inventory, nil
}

// Only a complete, signed state-0 header can be committed. A physically short
// header without a commit marker is discarded only after its checkpoint and
// all preceding segments have been verified by the caller.
func nativeRecoverActiveStart(f *os.File, directory string, identity *Identity, seq uint64, previousSegment, previousRecord journalHash, recipient string) error {
	data, err := nativeReadFile(f)
	if err != nil {
		return err
	}
	checkOpen := func() error {
		pathInfo, err := os.Lstat(f.Name())
		if err != nil {
			return err
		}
		openInfo, err := f.Stat()
		if err != nil {
			return err
		}
		if !pathInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openInfo) || openInfo.Size() != int64(len(data)) {
			return fmt.Errorf("native active changed during header recovery")
		}
		return nil
	}
	magic := []byte(nativeformat.AuditMagic)
	if len(data) <= len(magic) && bytes.Equal(data, magic[:len(data)]) {
		if len(data) < len(magic) {
			if err := checkOpen(); err != nil {
				return err
			}
			n, err := f.WriteAt(magic[len(data):], int64(len(data)))
			if err != nil {
				return err
			}
			if n != len(magic)-len(data) {
				return io.ErrShortWrite
			}
			if err := f.Sync(); err != nil {
				return err
			}
			return syncJournalDirectory(directory)
		}
		return nil
	}
	if !bytes.HasPrefix(data, magic) {
		return fmt.Errorf("invalid native active magic")
	}
	offset := int64(len(magic))
	fragment := data[len(magic):]
	if fragment[0] != byte(nativeformat.HeaderUnit) {
		return nil // The normal scanner rejects invalid committed headers.
	}
	if len(fragment) < 6 {
		var size [4]byte
		copy(size[:], fragment[1:])
		if binary.BigEndian.Uint32(size[:]) > nativeformat.MaxMetadataPayload || len(fragment) == 5 && binary.BigEndian.Uint32(size[:]) == 0 {
			return fmt.Errorf("invalid interrupted native header length")
		}
	} else {
		if fragment[5] != 0 {
			return nil // Committed (or invalid) state must be checked by the scanner.
		}
		length := binary.BigEndian.Uint32(fragment[1:5])
		if length == 0 || length > nativeformat.MaxMetadataPayload {
			return fmt.Errorf("invalid interrupted native header length")
		}
		declared := int64(6) + int64(length) + 4 + int64(len(nativeformat.CommitMarker))
		if int64(len(fragment)) >= declared {
			// A complete state-0 unit must verify as-is; extra bytes may be records.
			if int64(len(fragment)) > declared {
				return fmt.Errorf("data follows interrupted native header")
			}
			committed := bytes.Clone(data)
			committed[len(magic)+5] = 1
			unit, end, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(committed), offset, int64(len(committed)), nativeformat.MaxMetadataPayload)
			if err != nil || tail || end != int64(len(data)) || unit.Type != nativeformat.HeaderUnit {
				return fmt.Errorf("cannot verify interrupted native header: %v", err)
			}
			if _, err := decodeNativeAuditHeader(unit.Payload, identity, seq, previousSegment, previousRecord, recipient); err != nil {
				return err
			}
			if err := checkOpen(); err != nil {
				return err
			}
			n, err := f.WriteAt([]byte{1}, offset+5)
			if err != nil {
				return err
			}
			if n != 1 {
				return io.ErrShortWrite
			}
			if err := f.Sync(); err != nil {
				return err
			}
			return syncJournalDirectory(directory)
		}
	}
	// Even inside the declared size, a complete committed record would carry
	// this marker. Its presence makes the purported header fragment ambiguous.
	if bytes.Contains(fragment, []byte(nativeformat.CommitMarker)) {
		return fmt.Errorf("commit marker inside interrupted native header")
	}
	if err := checkOpen(); err != nil {
		return err
	}
	if err := f.Truncate(offset); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return syncJournalDirectory(directory)
}

func nativeScan(f *os.File, identity *Identity, seq uint64, previousSegment, previousRecord, checkpoint journalHash, checkpointSeen bool, recipient string, active bool) (nativeSegmentState, error) {
	var s nativeSegmentState
	s.seq, s.prevSegment, s.lastRecord, s.checkpointSeen = seq, previousSegment, previousRecord, checkpointSeen
	data, err := nativeReadFile(f)
	if err != nil {
		return s, err
	}
	if !bytes.HasPrefix(data, []byte(nativeformat.AuditMagic)) {
		return s, fmt.Errorf("invalid native audit magic")
	}
	offset := int64(len(nativeformat.AuditMagic))
	header := false
	for offset < int64(len(data)) {
		unit, next, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(data), offset, int64(len(data)), nativeformat.MaxAuditRecordPayload)
		if err != nil {
			return s, err
		}
		if tail {
			if !active || !s.checkpointSeen || !header || s.sealed {
				return s, fmt.Errorf("uncommitted native audit tail before checkpoint or in sealed segment")
			}
			if err := f.Truncate(offset); err != nil {
				return s, err
			}
			if err := f.Sync(); err != nil {
				return s, err
			}
			data = data[:offset]
			break
		}
		if next > nativeMaxSize {
			return s, fmt.Errorf("native audit segment exceeds size cap")
		}
		switch unit.Type {
		case nativeformat.HeaderUnit:
			if header || offset != int64(len(nativeformat.AuditMagic)) {
				return s, fmt.Errorf("unexpected native audit header")
			}
			if _, err := decodeNativeAuditHeader(unit.Payload, identity, seq, previousSegment, previousRecord, recipient); err != nil {
				return s, err
			}
			header = true
			s.contentBytes = next
		case nativeformat.ContentUnit:
			if !header || s.sealed || s.count == math.MaxUint64 {
				return s, fmt.Errorf("unexpected native audit record")
			}
			_, _, hash, err := decodeNativeAuditRecord(unit.Payload, identity, s.lastRecord, recipient, nil, false)
			if err != nil {
				return s, err
			}
			s.lastRecord = hash
			s.count++
			s.contentBytes = next
			if hash == checkpoint {
				s.checkpointSeen = true
			}
		case nativeformat.SealUnit:
			if !header || s.sealed || s.count == 0 || next != int64(len(data)) {
				return s, fmt.Errorf("unexpected native audit seal")
			}
			if _, err := decodeNativeAuditSeal(unit.Payload, identity, seq, s.count, uint64(offset), hashNativeAuditContent(data[:offset]), s.lastRecord); err != nil {
				return s, err
			}
			s.sealed = true
			s.segmentHash = hashNativeAuditSegment(data)
		default:
			return s, fmt.Errorf("unexpected native audit unit")
		}
		offset = next
	}
	if !header {
		if !active || !s.checkpointSeen || int64(len(data)) != int64(len(nativeformat.AuditMagic)) {
			return s, fmt.Errorf("missing native audit header")
		}
		_, payload, err := newNativeAuditHeader(identity, seq, previousSegment, previousRecord, time.Now().UTC(), recipient)
		if err != nil {
			return s, err
		}
		end, err := nativeWriteUnit(f, int64(len(data)), nativeformat.HeaderUnit, payload, nativeformat.MaxMetadataPayload)
		if err != nil {
			return s, err
		}
		s.contentBytes, s.fileBytes = end, end
		if err := syncJournalDirectory(filepath.Dir(f.Name())); err != nil {
			return s, err
		}
		return s, nil
	}
	if !active && !s.sealed {
		return s, fmt.Errorf("unsealed published native audit segment")
	}
	s.fileBytes = int64(len(data))
	return s, nil
}

func nativeWriteUnit(f *os.File, offset int64, kind nativeformat.UnitType, payload []byte, maximum int) (int64, error) {
	frame, err := nativeformat.EncodeUnit(kind, payload, maximum)
	if err != nil {
		return offset, err
	}
	if offset < 0 || offset > nativeMaxSize-int64(len(frame)) {
		return offset, fmt.Errorf("native audit segment size cap exceeded")
	}
	frame[5] = 0
	n, err := f.WriteAt(frame, offset)
	if err != nil {
		return offset, err
	}
	if n != len(frame) {
		return offset, io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		return offset, err
	}
	n, err = f.WriteAt([]byte{1}, offset+5)
	if err != nil {
		return offset, err
	}
	if n != 1 {
		return offset, io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		return offset, err
	}
	return offset + int64(len(frame)), nil
}

func nativeCreateActive(path string, identity *Identity, seq uint64, segment, record journalHash, recipient string) (*os.File, nativeSegmentState, error) {
	var s nativeSegmentState
	if seq == 0 {
		return nil, s, fmt.Errorf("native audit sequence overflow")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, journalFileMode)
	if err != nil {
		return nil, s, err
	}
	// Do not remove an interrupted new file: it may contain evidence.
	fail := func(err error) (*os.File, nativeSegmentState, error) { _ = f.Close(); return nil, s, err }
	if _, err := f.WriteAt([]byte(nativeformat.AuditMagic), 0); err != nil {
		return fail(err)
	}
	_, payload, err := newNativeAuditHeader(identity, seq, segment, record, time.Now().UTC(), recipient)
	if err != nil {
		return fail(err)
	}
	end, err := nativeWriteUnit(f, int64(len(nativeformat.AuditMagic)), nativeformat.HeaderUnit, payload, nativeformat.MaxMetadataPayload)
	if err != nil {
		return fail(err)
	}
	if err := syncJournalDirectory(filepath.Dir(path)); err != nil {
		return fail(err)
	}
	s = nativeSegmentState{seq: seq, prevSegment: segment, lastRecord: record, contentBytes: end, fileBytes: end, checkpointSeen: true}
	return f, s, nil
}

func nativePublishActive(f *os.File, path string, s nativeSegmentState, identity *Identity) (nativeSegmentState, error) {
	if !s.sealed {
		data, err := nativeReadFile(f)
		if err != nil {
			return s, err
		}
		if int64(len(data)) != s.contentBytes {
			return s, fmt.Errorf("native active file changed before seal")
		}
		_, payload, err := newNativeAuditSeal(identity, s.seq, s.count, uint64(s.contentBytes), hashNativeAuditContent(data), s.lastRecord, time.Now().UTC())
		if err != nil {
			return s, err
		}
		end, err := nativeWriteUnit(f, s.contentBytes, nativeformat.SealUnit, payload, nativeformat.MaxMetadataPayload)
		if err != nil {
			return s, err
		}
		s.fileBytes = end
		data, err = nativeReadFile(f)
		if err != nil {
			return s, err
		}
		if int64(len(data)) != end {
			return s, fmt.Errorf("native seal size changed")
		}
		s.segmentHash = hashNativeAuditSegment(data)
		s.sealed = true
	}
	if err := sealJournalFile(path, f); err != nil {
		return s, err
	}
	if err := f.Close(); err != nil {
		return s, err
	}
	target := filepath.Join(filepath.Dir(path), nativeSegmentName(s.seq, s.segmentHash, strings.HasSuffix(path, ".beaudit")))
	if err := publishJournalFile(path, target); err != nil {
		return s, err
	}
	return s, syncJournalDirectory(filepath.Dir(path))
}
