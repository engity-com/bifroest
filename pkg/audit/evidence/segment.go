package evidence

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/crypto/keydata"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

const MaxAuditSegmentBytes int64 = 17 << 20

// AuditSegmentImage owns one bounded immutable byte image. Construction copies
// the input; ReadAt never exposes its backing storage. It proves neither file
// identity nor producer trust, inventory completeness or checkpoint freshness.
type AuditSegmentImage struct {
	data []byte
}

func NewAuditSegmentImage(data []byte) (*AuditSegmentImage, error) {
	if int64(len(data)) > MaxAuditSegmentBytes {
		return nil, fmt.Errorf("native audit segment exceeds size cap: %d", len(data))
	}
	return &AuditSegmentImage{data: bytes.Clone(data)}, nil
}

func (this *AuditSegmentImage) Size() int64 {
	if this == nil {
		return 0
	}
	return int64(len(this.data))
}

func (this *AuditSegmentImage) ReadAt(output []byte, offset int64) (int, error) {
	if this == nil {
		return 0, io.EOF
	}
	return bytes.NewReader(this.data).ReadAt(output, offset)
}

type AuditSegmentOptions struct {
	Sequence                    uint64
	PreviousSegmentHash         Hash
	PreviousRecordHash          Hash
	ExpectedEncryptionRecipient string
	DecryptionIdentities        *keydata.AgeSshIdentities
	WithSensitive               bool
	// Checkpoint must come from an independently verified signed head.
	Checkpoint *Hash
	Published  bool
	// CheckpointReached is trusted continuation state from an earlier scan,
	// never an assertion accepted from untrusted input.
	CheckpointReached bool
}

type AuditScannedRecord struct {
	Id           uuid.UUID
	RecordedAt   time.Time
	Index        uint64
	Event        Event
	PreviousHash Hash
	Hash         Hash
	PayloadBytes int64
}

type AuditSegmentScan struct {
	SegmentHash       Hash
	LastRecordHash    Hash
	RecordCount       uint64
	Sealed            bool
	CheckpointReached bool
}

// ScanAuditSegment shares the native offline/live unit scanner. Visit receives
// provisional records only through the checkpoint, including the checkpoint
// record itself. The caller owns quota/selection and must not publish callbacks
// before the entire producer/journal, source revalidation and resource closes
// succeed. Any error returns a zero scan, not partial completion state.
//
// Active may stop at the checkpoint. Published consumes the complete suffix and
// validates its seal/hash without exporting or charging later records. The
// caller must still require Sealed and compare SegmentHash with its inventory.
// RecordCount includes a validated published suffix, not only visited records.
func ScanAuditSegment(ctx context.Context, image *AuditSegmentImage, identity JournalIdentity, options AuditSegmentOptions, visit func(AuditScannedRecord) error) (AuditSegmentScan, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return AuditSegmentScan{}, err
	}
	if image == nil || !bytes.HasPrefix(image.data, []byte(nativeformat.AuditMagic)) {
		return AuditSegmentScan{}, fmt.Errorf("invalid native audit magic")
	}
	if options.CheckpointReached && options.Checkpoint == nil {
		return AuditSegmentScan{}, fmt.Errorf("native audit checkpoint state requires a checkpoint")
	}
	var checkpoint Hash
	if options.Checkpoint != nil {
		checkpoint = *options.Checkpoint
	}
	data := image.data
	var count uint64
	var recipient string
	var sealed, header bool
	reached := options.CheckpointReached
	offset := int64(len(nativeformat.AuditMagic))
	contentEnd := offset
	last := options.PreviousRecordHash
	var segmentHash Hash
	completed := func() (AuditSegmentScan, error) {
		if err := ctx.Err(); err != nil {
			return AuditSegmentScan{}, err
		}
		return AuditSegmentScan{SegmentHash: segmentHash, LastRecordHash: last, RecordCount: count, Sealed: sealed, CheckpointReached: reached}, nil
	}
	for offset < int64(len(data)) {
		if err := ctx.Err(); err != nil {
			return AuditSegmentScan{}, err
		}
		unit, next, tail, err := nativeformat.ReadUnitAt(image, offset, int64(len(data)), nativeformat.MaxAuditRecordPayload)
		if err != nil || tail {
			return AuditSegmentScan{}, fmt.Errorf("invalid or uncommitted native audit unit: %v", err)
		}
		switch unit.Type {
		case nativeformat.HeaderUnit:
			if header || offset != int64(len(nativeformat.AuditMagic)) || len(unit.Payload) > nativeformat.MaxMetadataPayload {
				return AuditSegmentScan{}, fmt.Errorf("unexpected native audit header")
			}
			candidate, err := nativeformat.Unmarshal[nativeAuditHeader](unit.Payload, nativeformat.MaxMetadataPayload)
			if err != nil {
				return AuditSegmentScan{}, err
			}
			recipient = candidate.Recipient
			if recipient != options.ExpectedEncryptionRecipient {
				return AuditSegmentScan{}, fmt.Errorf("native audit encryption recipient differs from configured recipient")
			}
			if _, err := decodeNativeAuditHeader(unit.Payload, identity, options.Sequence, options.PreviousSegmentHash, options.PreviousRecordHash, recipient); err != nil {
				return AuditSegmentScan{}, err
			}
			if options.WithSensitive && recipient != "" && options.DecryptionIdentities == nil {
				return AuditSegmentScan{}, fmt.Errorf("encrypted audit records require a matching decryption identity")
			}
			header = true
			contentEnd = next
			if options.Checkpoint != nil && checkpoint.IsZero() && options.PreviousRecordHash.IsZero() && options.Sequence == 1 {
				reached = true
				if !options.Published {
					return completed()
				}
			}
		case nativeformat.ContentUnit:
			if !header || sealed || count == math.MaxUint64 {
				return AuditSegmentScan{}, fmt.Errorf("unexpected native audit record")
			}
			identities := options.DecryptionIdentities
			withSensitive := options.WithSensitive || identities != nil
			if reached {
				identities, withSensitive = nil, false
			}
			record, event, hash, err := decodeNativeAuditRecord(unit.Payload, identity, last, recipient, identities, withSensitive)
			if err != nil {
				return AuditSegmentScan{}, err
			}
			if !options.WithSensitive {
				event = Event{Name: event.Name, Domain: event.Domain, Outcome: event.Outcome}
			}
			if !reached && visit != nil {
				at, _ := record.RecordedAt.Time()
				if err := visit(AuditScannedRecord{Id: uuid.UUID(record.Id), RecordedAt: at.UTC(), Index: count, Event: event, PreviousHash: last, Hash: hash, PayloadBytes: int64(len(unit.Payload))}); err != nil {
					return AuditSegmentScan{}, err
				}
			}
			count++
			last = hash
			contentEnd = next
			if options.Checkpoint != nil && last == checkpoint {
				reached = true
				if !options.Published {
					return completed()
				}
			}
		case nativeformat.SealUnit:
			if !header || sealed || count == 0 || next != int64(len(data)) || len(unit.Payload) > nativeformat.MaxMetadataPayload || contentEnd != offset {
				return AuditSegmentScan{}, fmt.Errorf("unexpected native audit seal")
			}
			if _, err := decodeNativeAuditSeal(unit.Payload, identity, options.Sequence, count, uint64(offset), hashNativeAuditContent(data[:offset]), last); err != nil {
				return AuditSegmentScan{}, err
			}
			sealed = true
			segmentHash = hashNativeAuditSegment(data)
		default:
			return AuditSegmentScan{}, fmt.Errorf("unexpected native audit unit")
		}
		offset = next
	}
	if !header {
		return AuditSegmentScan{}, fmt.Errorf("missing native audit header")
	}
	return completed()
}
