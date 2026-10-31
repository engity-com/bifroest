package evidence

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/engity-com/bifroest/pkg/crypto/keydata"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

type AuditPublishedSegment struct {
	Sequence uint64
	Hash     Hash
	Image    *AuditSegmentImage
}

type AuditActiveSegment struct {
	Image *AuditSegmentImage
	// AliasOfPublished is zero for an independent active image. Otherwise the
	// source attests an alias and the verifier still requires exact last-segment
	// byte/hash equality. Native sources additionally require real file identity.
	AliasOfPublished uint64
}

// AuditProducerSegments is a single-owner capability, not a filesystem facade.
// NextPublished must exhaust an ordered, fixed inventory; images are immutable.
// Revalidate proves the source-specific capture/lease, never producer trust.
// Ownership transfers to the inspect/verify call, which always closes it once.
type AuditProducerSegments interface {
	NextPublished(context.Context) (AuditPublishedSegment, bool, error)
	Active(context.Context) (AuditActiveSegment, bool, error)
	Revalidate(context.Context) error
	Close() error
}

type AuditProducerSnapshot interface {
	AuditProducerSegments
	Head(context.Context) ([]byte, error)
}

type AuditProducerMode uint8

const (
	AuditProducerComplete AuditProducerMode = iota
	AuditProducerCapturedPrefix
)

type AuditProducerOptions struct {
	Auditlog                    string
	ExpectedProducerId          ProducerId
	AllowUntrusted              bool
	ExpectedEncryptionRecipient string
	DecryptionIdentities        *keydata.AgeSshIdentities
	WithSensitive               bool
	Mode                        AuditProducerMode
}

type AuditProducerSummary struct {
	ProducerId ProducerId
	// Trusted means the signing producer matches an independently supplied pin;
	// it is not filesystem provenance, freshness or private-key ownership proof.
	Trusted      bool
	Mode         AuditProducerMode
	Checkpoint   Hash
	SegmentCount uint64
	RecordCount  uint64
	// PrivateRecordCount counts validated private events in the selected proof
	// prefix, including events not retained by output selection. A zero count
	// does not prove a decryption-key match, even for a valid empty history.
	PrivateRecordCount uint64
}

// AuditProducerHead is an immutable proof of a successfully decoded signed head.
// Its fields cannot be populated from an unsigned caller-supplied checkpoint.
// Producer trust still comes independently from the verification options.
type AuditProducerHead struct {
	identity   *PublicIdentity
	checkpoint Hash
}

func CaptureAuditProducerHead(payload []byte, expected ProducerId, allowUntrusted bool) (*AuditProducerHead, error) {
	if expected.IsZero() && !allowUntrusted {
		return nil, fmt.Errorf("audit producer verification requires an independent expected producer ID or explicit untrusted opt-in")
	}
	if len(payload) == 0 || len(payload) > nativeformat.MaxMetadataPayload {
		return nil, fmt.Errorf("invalid native audit head size")
	}
	payload = bytes.Clone(payload)
	head, err := nativeformat.Unmarshal[NativeAuditHead](payload, nativeformat.MaxMetadataPayload)
	if err != nil {
		return nil, err
	}
	identity, err := NewPublicIdentity(ProducerId(head.ProducerId), head.PublicKey)
	if err != nil {
		return nil, err
	}
	if !expected.IsZero() && identity.ProducerId() != expected {
		return nil, fmt.Errorf("native audit producer differs from independently expected producer")
	}
	head, err = DecodeAuditHead(payload, identity)
	if err != nil {
		return nil, err
	}
	return &AuditProducerHead{identity: identity, checkpoint: Hash(head.LastRecordHash)}, nil
}

func (this *AuditProducerHead) ProducerId() ProducerId {
	if this == nil {
		return ProducerId{}
	}
	return this.identity.ProducerId()
}

func (this *AuditProducerHead) Checkpoint() Hash {
	if this == nil {
		return Hash{}
	}
	return this.checkpoint
}

type AuditProducerVerification struct {
	Summary       AuditProducerSummary
	records       []VerifiedRecord
	withSensitive bool
}

func (this *AuditProducerVerification) Records() []VerifiedRecord {
	if this == nil {
		return nil
	}
	return append([]VerifiedRecord(nil), this.records...)
}

func (this *AuditProducerVerification) ExportJSONLines(output io.Writer, order RecordOrder) error {
	if this == nil {
		return nil
	}
	return ExportVerifiedRecords(output, this.records, order, this.withSensitive)
}

func VerifyAuditProducerSnapshot(ctx context.Context, snapshot AuditProducerSnapshot, options AuditProducerOptions) (*AuditProducerVerification, error) {
	return verifyAuditProducerRecords(ctx, snapshot, options, nil)
}

func SelectAuditProducerRecords(ctx context.Context, snapshot AuditProducerSnapshot, options AuditProducerOptions, selection RecordSelection) (*AuditProducerVerification, error) {
	return verifyAuditProducerRecords(ctx, snapshot, options, NewSelectedRecords(selection))
}

func VerifyAuditProducerIntegrity(ctx context.Context, snapshot AuditProducerSnapshot, options AuditProducerOptions) (AuditProducerSummary, error) {
	return InspectAuditProducerSnapshot(ctx, snapshot, options, nil)
}

func verifyAuditProducerRecords(ctx context.Context, snapshot AuditProducerSnapshot, options AuditProducerOptions, selection *SelectedRecords) (*AuditProducerVerification, error) {
	var records []VerifiedRecord
	var count uint64
	var retained int64
	summary, err := InspectAuditProducerSnapshot(ctx, snapshot, options, func(record VerifiedRecord, payloadBytes int64) error {
		next, size, err := ConsumeRecordBudget(count, retained, payloadBytes, selection == nil)
		if err != nil {
			return err
		}
		count, retained = next, size
		if selection != nil {
			return selection.Add(record, payloadBytes)
		}
		records = append(records, record)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if selection != nil {
		records = selection.Records()
	}
	return &AuditProducerVerification{Summary: summary, records: records, withSensitive: options.WithSensitive}, nil
}

// InspectAuditProducerSnapshot validates the signed head before traversing the
// source. Visit is provisional and intended for native aggregate budgets; public
// materializing callers should use VerifyAuditProducerSnapshot/Select instead.
// No summary or materialized result is released on revalidation/close/cancel error.
func InspectAuditProducerSnapshot(ctx context.Context, snapshot AuditProducerSnapshot, options AuditProducerOptions, visit func(VerifiedRecord, int64) error) (AuditProducerSummary, error) {
	return inspectAuditProducer(ctx, snapshot, snapshot, options, nil, visit)
}

// InspectCapturedAuditProducer preserves native live-reader continuation: the
// caller supplies an opaque proof from CaptureAuditProducerHead. This entry
// does not manufacture a signed checkpoint or retry with a newer one. It owns
// and closes segments just like the full entry.
func InspectCapturedAuditProducer(ctx context.Context, segments AuditProducerSegments, head *AuditProducerHead, options AuditProducerOptions, visit func(VerifiedRecord, int64) error) (AuditProducerSummary, error) {
	return inspectAuditProducer(ctx, segments, nil, options, head, visit)
}

func inspectAuditProducer(ctx context.Context, source AuditProducerSegments, headSource AuditProducerSnapshot, options AuditProducerOptions, captured *AuditProducerHead, visit func(VerifiedRecord, int64) error) (result AuditProducerSummary, resultErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if source == nil {
		return result, fmt.Errorf("missing native audit producer snapshot")
	}
	defer func() {
		resultErr = errors.Join(resultErr, source.Close())
		if err := ctx.Err(); err != nil && !errors.Is(resultErr, err) {
			resultErr = errors.Join(resultErr, err)
		}
		if resultErr != nil {
			result = AuditProducerSummary{}
		}
	}()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if options.Auditlog == "" || options.Mode != AuditProducerComplete && options.Mode != AuditProducerCapturedPrefix {
		return result, fmt.Errorf("invalid audit producer verification options")
	}
	if options.ExpectedProducerId.IsZero() && !options.AllowUntrusted {
		return result, fmt.Errorf("audit producer verification requires an independent expected producer ID or explicit untrusted opt-in")
	}
	if headSource != nil {
		payload, err := headSource.Head(ctx)
		if err != nil {
			return result, err
		}
		captured, err = CaptureAuditProducerHead(payload, options.ExpectedProducerId, options.AllowUntrusted)
		if err != nil {
			return result, err
		}
	} else {
		if options.Mode != AuditProducerCapturedPrefix {
			return result, fmt.Errorf("captured audit traversal requires a verified prefix checkpoint")
		}
	}
	if captured == nil || captured.identity == nil || captured.ProducerId().IsZero() {
		return result, fmt.Errorf("missing verified captured audit head")
	}
	identity, checkpoint := captured.identity, captured.checkpoint
	if !options.ExpectedProducerId.IsZero() && identity.ProducerId() != options.ExpectedProducerId {
		return result, fmt.Errorf("native audit producer differs from independently expected producer")
	}
	result = AuditProducerSummary{ProducerId: identity.ProducerId(), Trusted: !options.ExpectedProducerId.IsZero(), Mode: options.Mode, Checkpoint: checkpoint}
	var sequence uint64
	var segmentHash, last Hash
	reached := false
	scanImage := func(image *AuditSegmentImage, seq uint64, published bool) (AuditSegmentScan, error) {
		scanOptions := AuditSegmentOptions{
			Sequence: seq, PreviousSegmentHash: segmentHash, PreviousRecordHash: last,
			ExpectedEncryptionRecipient: options.ExpectedEncryptionRecipient, DecryptionIdentities: options.DecryptionIdentities,
			WithSensitive: options.WithSensitive, Published: published,
		}
		if options.Mode == AuditProducerCapturedPrefix {
			scanOptions.Checkpoint, scanOptions.CheckpointReached = &checkpoint, reached
		}
		return ScanAuditSegment(ctx, image, identity, scanOptions, func(scanned AuditScannedRecord) error {
			if result.RecordCount == math.MaxUint64 {
				return fmt.Errorf("native audit record counters overflow")
			}
			result.RecordCount++
			if options.ExpectedEncryptionRecipient == "" || options.DecryptionIdentities != nil {
				result.PrivateRecordCount++
			}
			if visit == nil {
				return nil
			}
			return visit(VerifiedRecord{
				Auditlog: options.Auditlog, ProducerId: identity.ProducerId(), SegmentSequence: seq, SegmentRecordIndex: scanned.Index,
				Id: scanned.Id, RecordedAt: scanned.RecordedAt, Event: scanned.Event, PreviousHash: scanned.PreviousHash.String(), Hash: scanned.Hash.String(),
			}, scanned.PayloadBytes)
		})
	}
	for {
		if err := ctx.Err(); err != nil {
			return AuditProducerSummary{}, err
		}
		entry, found, err := source.NextPublished(ctx)
		if err != nil {
			return AuditProducerSummary{}, err
		}
		if !found {
			break
		}
		if sequence == math.MaxUint64 || entry.Sequence != sequence+1 {
			return AuditProducerSummary{}, fmt.Errorf("native audit segment sequence gap or duplicate")
		}
		scan, err := scanImage(entry.Image, entry.Sequence, true)
		if err != nil {
			return AuditProducerSummary{}, err
		}
		if !scan.Sealed || scan.SegmentHash != entry.Hash {
			return AuditProducerSummary{}, fmt.Errorf("native audit published segment seal or physical hash mismatch")
		}
		sequence, segmentHash, last, reached = entry.Sequence, scan.SegmentHash, scan.LastRecordHash, scan.CheckpointReached
		result.SegmentCount++
	}
	if options.Mode == AuditProducerComplete || !reached {
		active, found, err := source.Active(ctx)
		if err != nil {
			return AuditProducerSummary{}, err
		}
		if found {
			if active.AliasOfPublished != 0 {
				if sequence == 0 || active.AliasOfPublished != sequence {
					return AuditProducerSummary{}, fmt.Errorf("native active aliases an earlier published segment")
				}
				if active.Image == nil || HashAuditSegment(active.Image.data) != segmentHash {
					return AuditProducerSummary{}, fmt.Errorf("native active alias changed during verification")
				}
			} else {
				if sequence == math.MaxUint64 {
					return AuditProducerSummary{}, fmt.Errorf("native audit sequence overflow")
				}
				scan, err := scanImage(active.Image, sequence+1, false)
				if err != nil {
					return AuditProducerSummary{}, err
				}
				last, reached = scan.LastRecordHash, scan.CheckpointReached
				result.SegmentCount++
			}
		}
	}
	if options.Mode == AuditProducerComplete && checkpoint != last {
		return AuditProducerSummary{}, fmt.Errorf("native audit producer does not end at its signed head")
	}
	if options.Mode == AuditProducerCapturedPrefix && !reached {
		return AuditProducerSummary{}, fmt.Errorf("signed native audit checkpoint not in available chain")
	}
	if err := source.Revalidate(ctx); err != nil {
		return AuditProducerSummary{}, err
	}
	return result, nil
}
