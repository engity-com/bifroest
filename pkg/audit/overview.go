package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
	"github.com/engity-com/bifroest/pkg/metadatacache"
	"github.com/engity-com/bifroest/pkg/nativeformat"
	"github.com/google/uuid"
)

// OverviewReader is an operational read model, NOT producer/journal evidence.
// It indexes public record headers without verifying/decrypting the archive.
// Only selected records are individually authenticated; full verification stays
// in the existing independent verifier. Index files contain no private payloads.
type OverviewReader struct{ cache *metadatacache.Cache }

func NewOverviewReader(roots ...string) *OverviewReader {
	return &OverviewReader{cache: metadatacache.New(128<<20, 128, roots...)}
}
func (r *OverviewReader) Close() error {
	if r == nil {
		return nil
	}
	return r.cache.Close()
}

type OverviewRecord struct {
	ID                    string
	RecordedAt            time.Time
	Name, Domain, Outcome string
	Sequence, Index       uint64
	offset, length        int64
	hash, previous        journalHash
	file                  *overviewFile
}
type overviewFile struct {
	mutex      sync.Mutex
	file       *os.File
	info       os.FileInfo
	size       int64
	references int
	identity   journalIdentity
	recipient  string
	active     bool
}

func (v OverviewRecord) Retain() error {
	if v.file == nil {
		return fmt.Errorf("missing audit record lease")
	}
	v.file.mutex.Lock()
	defer v.file.mutex.Unlock()
	if v.file.references < 1 {
		return fmt.Errorf("audit record lease ended")
	}
	v.file.references++
	return nil
}
func (v OverviewRecord) Release() error {
	if v.file == nil {
		return nil
	}
	return v.file.release()
}
func (f *overviewFile) release() error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.references < 1 {
		return fmt.Errorf("audit record lease already closed")
	}
	f.references--
	if f.references == 0 {
		return f.file.Close()
	}
	return nil
}

type overviewRecordIndex struct {
	ID                    string
	RecordedAt            time.Time
	Name, Domain, Outcome string
	Offset, Length        int64
	Previous, Hash        journalHash
}
type overviewIndexLine struct {
	Header *nativeAuditHeader   `json:"header,omitempty"`
	Record *overviewRecordIndex `json:"record,omitempty"`
	Seal   *nativeAuditSeal     `json:"seal,omitempty"`
}

// Walk visits provisional public metadata in chain order through one captured
// signed checkpoint. Retain only selected candidates, then authenticate them
// with ReadRecord. A lease permits rotation/append, never mutable record bytes.
func (r *OverviewReader) Walk(ctx context.Context, source JournalSource, visit func(OverviewRecord) error, progress func(int64) error) (resultErr error) {
	if r == nil || visit == nil || source.ExpectedProducerId.IsZero() || len(source.DecryptionIdentities) != 0 {
		return fmt.Errorf("invalid audit overview source")
	}
	root, err := filepath.EvalSymlinks(source.Directory)
	if err != nil {
		return err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	err = forEachJournalDirectoryEntry(ctx, root, func(entry os.DirEntry) error {
		name := entry.Name()
		if name == journalLockFileName && entry.Type().IsRegular() || (name == journalWorkDirectoryName || name == remoteDeliveryStateDirectoryName) && entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			return nil
		}
		if name != source.ExpectedProducerId.String() || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unexpected audit overview root entry")
		}
		return nil
	})
	if err != nil {
		return err
	}
	directory := filepath.Join(root, source.ExpectedProducerId.String())
	payload, _, err := readVerifierFile(filepath.Join(directory, nativeHeadFileName), nativeformat.MaxMetadataPayload)
	if err != nil {
		return err
	}
	unsigned, err := nativeformat.Unmarshal[nativeAuditHead](payload, nativeformat.MaxMetadataPayload)
	if err != nil {
		return err
	}
	identity, err := newJournalPublicIdentity(source.ExpectedProducerId, unsigned.PublicKey)
	if err != nil {
		return err
	}
	head, err := decodeNativeAuditHead(payload, identity)
	if err != nil {
		return err
	}
	checkpoint := journalHash(head.LastRecordHash)
	if checkpoint.IsZero() {
		return ctx.Err()
	}
	temps, err := nativeHeadTempsForInventory(directory)
	if err != nil {
		return err
	}
	activeName := nativeActiveClear
	if source.ExpectedEncryptionRecipient != "" {
		activeName = nativeActiveEncrypted
	}
	inventory, err := newNativeSegmentInventory(ctx, directory, activeName, source.ExpectedEncryptionRecipient != "", temps, func() (*journalSegmentWorkspace, error) { return newNativeVerifierWorkspace([]string{root}) })
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, inventory.segments.Close()) }()
	var sequence uint64
	var previousSegment, last journalHash
	reached := false
	var count int64
	consumeFile := func(path string, seq uint64, active bool) (fileErr error) {
		file, err := openVerifierFile(path)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return err
		}
		lease := &overviewFile{file: file, info: info, size: info.Size(), references: 1, identity: identity, recipient: source.ExpectedEncryptionRecipient, active: active}
		defer func() { fileErr = errors.Join(fileErr, lease.release()) }()
		if info.Size() < 0 || info.Size() > evidence.MaxAuditSegmentBytes {
			return fmt.Errorf("audit overview segment exceeds individual bound")
		}
		stamp, err := metadatacache.Fingerprint(file)
		if err != nil {
			return err
		}
		// Active indexes are checkpoint-specific even if an append completed
		// between capturing the head and the descriptor's size/change stamp.
		key := path
		if active {
			key += "/" + checkpoint.String()
		}
		err = r.cache.UseFile(ctx, key, stamp, 64<<20, func(output io.Writer) error { return buildOverviewIndex(ctx, lease, checkpoint, output) }, func(input io.Reader) error {
			scanner := bufio.NewScanner(input)
			scanner.Buffer(make([]byte, 4<<10), 8<<10)
			headerSeen := false
			var index uint64
			for scanner.Scan() {
				if err := ctx.Err(); err != nil {
					return err
				}
				var line overviewIndexLine
				if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
					return err
				}
				if line.Header != nil {
					if headerSeen || line.Record != nil || line.Seal != nil {
						return fmt.Errorf("invalid audit metadata header")
					}
					h := line.Header
					data, err := nativeformat.Marshal(*h, nativeformat.MaxMetadataPayload)
					if err != nil {
						return err
					}
					if _, err := decodeNativeAuditHeader(data, identity, seq, previousSegment, last, source.ExpectedEncryptionRecipient); err != nil {
						return err
					}
					headerSeen = true
					continue
				}
				if !headerSeen {
					return fmt.Errorf("audit metadata index has no header")
				}
				if line.Record != nil {
					row := line.Record
					if line.Seal != nil || row.Previous != last || row.Length < 1 || row.Length > nativeformat.MaxAuditRecordPayload+18 || row.Offset < int64(len(nativeformat.AuditMagic)) || row.Offset+row.Length > lease.size {
						return fmt.Errorf("audit metadata index continuity/bounds mismatch")
					}
					if !reached {
						value := OverviewRecord{ID: row.ID, RecordedAt: row.RecordedAt, Name: row.Name, Domain: row.Domain, Outcome: row.Outcome, Sequence: seq, Index: index, offset: row.Offset, length: row.Length, hash: row.Hash, previous: row.Previous, file: lease}
						if err := visit(value); err != nil {
							return err
						}
						count++
						if progress != nil && count%128 == 0 {
							if err := progress(count); err != nil {
								return err
							}
						}
					}
					last = row.Hash
					index++
					if last == checkpoint {
						reached = true
					}
					continue
				}
				if line.Seal == nil {
					return fmt.Errorf("invalid audit metadata index line")
				}
				// A signed seal is only metadata here. This does not rehash its
				// content or claim journal completeness/producer verification.
				seal := line.Seal
				data, err := nativeformat.Marshal(*seal, nativeformat.MaxMetadataPayload)
				if err != nil {
					return err
				}
				if _, err := decodeNativeAuditSeal(data, identity, seq, index, seal.ContentBytes, journalHash(seal.ContentHash), last); err != nil {
					return err
				}
			}
			return scanner.Err()
		})
		if err != nil {
			return err
		}
		current, err := file.Stat()
		if err != nil {
			return err
		}
		if !os.SameFile(info, current) || (!active && current.Size() != info.Size()) || active && current.Size() < info.Size() {
			return fmt.Errorf("audit overview source changed")
		}
		if !active {
			actual, err := metadatacache.Fingerprint(file)
			if err != nil || actual != stamp {
				return fmt.Errorf("sealed audit overview source changed: %v", err)
			}
		}
		return nil
	}
	for !reached {
		segment, found, err := inventory.segments.Next(ctx)
		if err != nil {
			return err
		}
		if !found {
			break
		}
		if segment.sequence != sequence+1 {
			return fmt.Errorf("audit overview segment sequence gap")
		}
		if err := consumeFile(segment.path, segment.sequence, false); err != nil {
			return err
		}
		sequence, previousSegment = segment.sequence, segment.hash
	}
	if !reached && inventory.hasActive {
		if err := consumeFile(filepath.Join(directory, activeName), sequence+1, true); err != nil {
			return err
		}
	}
	if !reached {
		return fmt.Errorf("captured audit checkpoint not in overview inventory")
	}
	if progress != nil {
		if err := progress(count); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func buildOverviewIndex(ctx context.Context, file *overviewFile, checkpoint journalHash, output io.Writer) error {
	source := io.NewSectionReader(file.file, 0, file.size)
	var magic [len(nativeformat.AuditMagic)]byte
	if _, err := source.ReadAt(magic[:], 0); err != nil || string(magic[:]) != nativeformat.AuditMagic {
		return fmt.Errorf("invalid audit overview magic")
	}
	encoder := json.NewEncoder(output)
	offset := int64(len(magic))
	headerSeen := false
	for offset < file.size {
		if err := ctx.Err(); err != nil {
			return err
		}
		unit, next, tail, err := nativeformat.ReadUnitAt(source, offset, file.size, nativeformat.MaxAuditRecordPayload)
		if tail && file.active {
			return fmt.Errorf("captured audit checkpoint not committed in active prefix")
		}
		if err != nil || tail {
			return fmt.Errorf("invalid audit overview unit: %v", err)
		}
		switch unit.Type {
		case nativeformat.HeaderUnit:
			if headerSeen || offset != int64(len(magic)) {
				return fmt.Errorf("unexpected audit metadata header")
			}
			var header nativeAuditHeader
			if err := decodeOverviewPayload(unit.Payload, &header, nativeformat.MaxMetadataPayload); err != nil {
				return err
			}
			headerSeen = true
			if err := encoder.Encode(overviewIndexLine{Header: &header}); err != nil {
				return err
			}
		case nativeformat.ContentUnit:
			if !headerSeen {
				return fmt.Errorf("audit record before header")
			}
			record, err := nativeformat.Unmarshal[nativeAuditRecord](unit.Payload, nativeformat.MaxAuditRecordPayload)
			if err != nil {
				return err
			}
			id := uuid.UUID(record.Id)
			at, err := record.RecordedAt.Time()
			if err != nil || at.IsZero() || id.Version() != 4 || id.Variant() != uuid.RFC4122 {
				return fmt.Errorf("invalid audit overview record metadata")
			}
			event := Event{Name: record.PublicEvent.Name, Domain: EventDomain(record.PublicEvent.Domain), Outcome: EventOutcome(record.PublicEvent.Outcome)}
			if err := validateAuditEvent(event); err != nil {
				return err
			}
			hash := hashJournalBytes(nativeAuditRecordHashDomain, unit.Payload)
			row := overviewRecordIndex{ID: id.String(), RecordedAt: at, Name: event.Name, Domain: string(event.Domain), Outcome: string(event.Outcome), Offset: offset, Length: next - offset, Previous: journalHash(record.PreviousRecordHash), Hash: hash}
			if err := encoder.Encode(overviewIndexLine{Record: &row}); err != nil {
				return err
			}
			if file.active && hash == checkpoint {
				return nil
			}
		case nativeformat.SealUnit:
			if next != file.size {
				return fmt.Errorf("audit overview has trailing sealed data")
			}
			seal, err := nativeformat.Unmarshal[nativeAuditSeal](unit.Payload, nativeformat.MaxMetadataPayload)
			if err != nil {
				return err
			}
			return encoder.Encode(overviewIndexLine{Seal: &seal})
		default:
			return fmt.Errorf("unknown audit overview unit")
		}
		offset = next
	}
	return fmt.Errorf("audit overview lacks committed end")
}

func decodeOverviewPayload(payload []byte, target *nativeAuditHeader, maximum int) error {
	value, err := nativeformat.Unmarshal[nativeAuditHeader](payload, maximum)
	if err == nil {
		*target = value
	}
	return err
}

func (v OverviewRecord) payload(ctx context.Context) ([]byte, error) {
	if v.file == nil {
		return nil, fmt.Errorf("missing audit record lease")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	unit, next, tail, err := nativeformat.ReadUnitAt(io.NewSectionReader(v.file.file, 0, v.file.size), v.offset, v.file.size, nativeformat.MaxAuditRecordPayload)
	if err != nil || tail || unit.Type != nativeformat.ContentUnit || next != v.offset+v.length || hashJournalBytes(nativeAuditRecordHashDomain, unit.Payload) != v.hash {
		return nil, fmt.Errorf("selected audit record changed: %v", err)
	}
	return unit.Payload, nil
}

// MetadataContext is for explicit metadata searches in clear journals. It does
// not authenticate a record or return decryption capability and never caches
// private fields. A selected result must still pass ReadRecord before release.
func (v OverviewRecord) MetadataContext(ctx context.Context) (Event, error) {
	if v.file == nil || v.file.recipient != "" {
		return Event{}, fmt.Errorf("private audit metadata requires local decryption")
	}
	v.file.mutex.Lock()
	defer v.file.mutex.Unlock()
	if v.file.references < 1 {
		return Event{}, fmt.Errorf("audit record lease ended")
	}
	payload, err := v.payload(ctx)
	if err != nil {
		return Event{}, err
	}
	record, err := nativeformat.Unmarshal[nativeAuditRecord](payload, nativeformat.MaxAuditRecordPayload)
	if err != nil {
		return Event{}, err
	}
	data, err := nativeformat.DecodeStoredPayload(record.PrivatePayload, nil, "", nativeAuditPayloadLimits)
	if err != nil {
		return Event{}, err
	}
	defer clear(data)
	private, err := nativeformat.Unmarshal[nativeAuditPrivateEvent](data, nativeformat.MaxAuditEventPayload)
	if err != nil {
		return Event{}, err
	}
	event, err := evidence.AuditEventFromPrivate(Event{Name: record.PublicEvent.Name, Domain: EventDomain(record.PublicEvent.Domain), Outcome: EventOutcome(record.PublicEvent.Outcome)}, private)
	if err != nil {
		return Event{}, err
	}
	if err := validateAuditEventForWrite(event); err != nil {
		return Event{}, err
	}
	return event, nil
}

// ReadRecord authenticates one selected record, not the producer's whole chain.
func (v OverviewRecord) ReadRecord(ctx context.Context, sensitive bool) (Event, error) {
	if v.file == nil {
		return Event{}, fmt.Errorf("missing audit record lease")
	}
	v.file.mutex.Lock()
	defer v.file.mutex.Unlock()
	if v.file.references < 1 {
		return Event{}, fmt.Errorf("audit record lease ended")
	}
	payload, err := v.payload(ctx)
	if err != nil {
		return Event{}, err
	}
	_, event, _, err := decodeNativeAuditRecord(payload, v.file.identity, v.previous, v.file.recipient, nil, sensitive && v.file.recipient == "")
	return event, err
}
