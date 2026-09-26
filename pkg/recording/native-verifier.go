package recording

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

type NativeRecordingVerifyOptions struct {
	ExpectedProducerId    audit.ProducerId
	AllowUntrusted        bool
	MaximumContainerBytes int64
	MaximumCastBytes      int64
	MaximumChunks         uint64
	Context               context.Context
}

type NativeRecordingVerification struct {
	Header  NativeRecordingHeader
	Seal    NativeRecordingSeal
	Trusted bool
}

const (
	nativeRecordingAgePrefix            = "age-encryption.org/v1\n"
	DefaultMaximumNativeRecordingBytes  = int64(32 << 30)
	DefaultMaximumNativeRecordingChunks = 1 << 18
)

func effectiveMaximumNativeRecordingChunks(value uint64) uint64 {
	if value == 0 {
		return DefaultMaximumNativeRecordingChunks
	}
	return value
}

func castStatusFromNativeRecording(value uint8) (CastStatus, error) {
	switch value {
	case 1:
		return CastStatusCompleted, nil
	case 2:
		return CastStatusFailed, nil
	case 3:
		return CastStatusIncomplete, nil
	default:
		return "", fmt.Errorf("illegal native recording status %d", value)
	}
}

func validateNativeRecordingSeal(s nativeRecordingSeal, h nativeRecordingHeader) error {
	status, err := castStatusFromNativeRecording(s.Status)
	if err != nil || status == "" || s.ChunkCount == 0 || s.CastBytes == 0 {
		return fmt.Errorf("invalid native recording seal status or counts")
	}
	end, err := s.EndedAt.Time()
	if err != nil || end.IsZero() {
		return fmt.Errorf("invalid native recording end time")
	}
	start, err := h.StartedAt.Time()
	if err != nil || end.Before(start) {
		return fmt.Errorf("native recording ends before it starts")
	}
	var digest CastDigest
	copy(digest[:], s.CastDigest[:])
	castKey, err := audit.VerifySessionRecordingCastSignature(audit.SessionRecordingCastSignature{
		Schema: audit.SessionRecordingCastSignatureSchema, RecordingId: Id(h.RecordingId).String(),
		ProducerId: audit.ProducerId(h.ProducerId), Digest: digest.String(), PublicKey: h.PublicKey, Signature: s.CastSignature,
	})
	if err != nil || castKey == nil || !bytes.Equal(castKey.Marshal(), h.PublicKey) {
		return fmt.Errorf("invalid native recording Cast signature: %v", err)
	}
	return nil
}

// VerifyNativeRecordingOuter authenticates the entire committed envelope but
// does not claim semantic validity for the inner CBOR event maps. No export
// should consume its result as proof of full verification.
// The ReaderAt must remain an immutable snapshot throughout verification.
func VerifyNativeRecordingOuter(source io.ReaderAt, size int64, options NativeRecordingVerifyOptions) (*NativeRecordingVerification, error) {
	if source == nil || size < int64(len(nativeformat.RecordingMagic))+18 {
		return nil, fmt.Errorf("missing native recording input")
	}
	maximum := options.MaximumContainerBytes
	if maximum == 0 {
		maximum = DefaultMaximumNativeRecordingBytes
	}
	castMaximum := effectiveMaximumCastBytes(options.MaximumCastBytes)
	if maximum < 1 || castMaximum < 1 || size > maximum {
		return nil, fmt.Errorf("native recording exceeds configured limits")
	}
	if options.ExpectedProducerId.IsZero() && !options.AllowUntrusted {
		return nil, fmt.Errorf("native recording requires a trusted expected producer")
	}
	maxChunks := effectiveMaximumNativeRecordingChunks(options.MaximumChunks)
	var magic [len(nativeformat.RecordingMagic)]byte
	if _, err := source.ReadAt(magic[:], 0); err != nil || string(magic[:]) != nativeformat.RecordingMagic {
		return nil, fmt.Errorf("invalid native recording magic: %v", err)
	}
	offset := int64(len(magic))
	unit, next, tail, err := nativeformat.ReadUnitAt(source, offset, size, nativeformat.MaxMetadataPayload)
	if err != nil || tail || unit.Type != nativeformat.HeaderUnit {
		return nil, fmt.Errorf("invalid native recording header: %v", err)
	}
	header, key, err := verifyNativeRecordingHeader(unit.Payload)
	if err != nil {
		return nil, err
	}
	if !options.ExpectedProducerId.IsZero() && header.ProducerId != [32]byte(options.ExpectedProducerId) {
		return nil, fmt.Errorf("native recording producer mismatch")
	}
	previous, err := hashNativeRecordingUnit(source, offset, next)
	if err != nil {
		return nil, err
	}
	count := uint64(0)
	finalSeen := false
	var finalChunk nativeRecordingChunk
	var previousCastHashBytes uint64
	var previousElapsed uint64
	for offset = next; offset < size; offset = next {
		if options.Context != nil && options.Context.Err() != nil {
			return nil, options.Context.Err()
		}
		// The per-unit bound is enforced before allocation by ReadUnitAt.
		unit, next, tail, err = nativeformat.ReadUnitAt(source, offset, size, nativeformat.MaxRecordingChunkPayload)
		if err != nil || tail {
			return nil, fmt.Errorf("invalid committed native recording unit: %v", err)
		}
		switch unit.Type {
		case nativeformat.ContentUnit:
			if count >= maxChunks || finalSeen {
				return nil, fmt.Errorf("native recording exceeds chunk limit")
			}
			chunk, err := nativeformat.Unmarshal[nativeRecordingChunk](unit.Payload, nativeformat.MaxRecordingChunkPayload)
			if err != nil {
				return nil, err
			}
			if chunk.Sequence != count+1 || chunk.PreviousUnitHash != previous || len(chunk.StoredPayload) == 0 || chunk.StoredHash != sha256.Sum256(chunk.StoredPayload) || len(chunk.StoredPayload) > nativeformat.MaxRecordingChunkPayload-256 {
				return nil, fmt.Errorf("invalid native recording chunk chain or stored payload")
			}
			if chunk.CastHashBytes == 0 {
				finalSeen, finalChunk = true, chunk
			} else {
				if chunk.CastHashBytes <= previousCastHashBytes || chunk.CastHashBytes > uint64(castMaximum)+uint64(len(castContentHashDomain)) {
					return nil, fmt.Errorf("invalid native recording Cast hash continuation")
				}
				if *chunk.LastElapsedNanos < previousElapsed {
					return nil, fmt.Errorf("native recording event time moved backwards")
				}
				previousElapsed = *chunk.LastElapsedNanos
				previousCastHashBytes = chunk.CastHashBytes
			}
			if err := nativeRecordingVerify(key, nativeRecordingChunkDomain, nativeRecordingChunkFields(chunk), chunk.Signature, nativeformat.MaxRecordingChunkPayload); err != nil {
				return nil, err
			}
			if header.Encryption == 1 && !bytes.HasPrefix(chunk.StoredPayload, []byte(nativeRecordingAgePrefix)) {
				return nil, fmt.Errorf("encrypted native recording chunk has no age message")
			}
			if header.Encryption == 0 {
				decoded, err := nativeformat.DecodeStoredPayload(chunk.StoredPayload, nil, "", nativeformat.PayloadLimits{MaxDecoded: nativeformat.MaxRecordingDecodedChunk, MaxStored: nativeformat.MaxRecordingChunkPayload})
				if err != nil || len(decoded) != int(chunk.DecodedLength) {
					return nil, fmt.Errorf("invalid native recording compressed chunk: %v", err)
				}
				if _, err := nativeformat.Unmarshal[map[uint64]any](decoded, nativeformat.MaxRecordingDecodedChunk); err != nil {
					return nil, fmt.Errorf("invalid native recording CBOR event group: %w", err)
				}
			}
			previous, err = hashNativeRecordingUnit(source, offset, next)
			if err != nil {
				return nil, err
			}
			count++
		case nativeformat.SealUnit:
			if !finalSeen || next != size || len(unit.Payload) > nativeformat.MaxMetadataPayload {
				return nil, fmt.Errorf("native recording has trailing data or oversized seal")
			}
			seal, err := nativeformat.Unmarshal[nativeRecordingSeal](unit.Payload, nativeformat.MaxMetadataPayload)
			if err != nil {
				return nil, err
			}
			contentHash, hashErr := hashNativeRecordingContent(source, offset)
			if hashErr != nil || seal.ChunkCount != count || seal.LastUnitHash != previous || seal.CastBytes > uint64(castMaximum) || seal.ContentHash != contentHash || seal.Status != finalChunk.FinalStatus || seal.CastDigest != *finalChunk.CastDigest || !bytes.Equal(seal.CastSignature, finalChunk.CastSignature) || seal.CastBytes != *finalChunk.CastBytes || seal.EndedAt != *finalChunk.EndedAt {
				return nil, fmt.Errorf("native recording seal does not match its content")
			}
			if err := validateNativeRecordingSeal(seal, header); err != nil {
				return nil, err
			}
			if err := nativeRecordingVerify(key, nativeRecordingSealDomain, nativeRecordingSealFields(seal), seal.Signature, nativeformat.MaxMetadataPayload); err != nil {
				return nil, err
			}
			return &NativeRecordingVerification{Header: header, Seal: seal, Trusted: !options.ExpectedProducerId.IsZero()}, nil
		default:
			return nil, fmt.Errorf("unexpected native recording unit type %d", unit.Type)
		}
	}
	return nil, fmt.Errorf("native recording has no seal")
}

func hashNativeRecordingUnit(source io.ReaderAt, start, end int64) ([32]byte, error) {
	h := sha256.New()
	_, _ = h.Write([]byte(nativeRecordingUnitDomain))
	if _, err := io.Copy(h, io.NewSectionReader(source, start, end-start)); err != nil {
		return [32]byte{}, err
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

func hashNativeRecordingContent(source io.ReaderAt, end int64) ([32]byte, error) {
	h := sha256.New()
	_, _ = h.Write([]byte(nativeRecordingContentDomain))
	if _, err := io.Copy(h, io.NewSectionReader(source, 0, end)); err != nil {
		return [32]byte{}, err
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

// VerifyNativeRecordingHead checks head.cbor against an authenticated header.
// The adapter must additionally match every head field to its exact durable
// prefix before treating it as a recovery checkpoint.
func VerifyNativeRecordingHead(payload, headerPayload []byte) (NativeRecordingHead, error) {
	header, key, err := verifyNativeRecordingHeader(headerPayload)
	if err != nil {
		return NativeRecordingHead{}, err
	}
	head, err := nativeformat.Unmarshal[NativeRecordingHead](payload, nativeformat.MaxMetadataPayload)
	if err != nil {
		return NativeRecordingHead{}, err
	}
	if head.Version != 1 || head.RecordingId != header.RecordingId || head.ProducerId != header.ProducerId || head.ChunkCount == 0 || head.PrefixBytes <= uint64(len(nativeformat.RecordingMagic)) || head.CastHashBytes == 0 || head.CastHashBytes%sha256.BlockSize != 0 {
		return NativeRecordingHead{}, fmt.Errorf("invalid native recording head state")
	}
	if err := nativeRecordingVerify(ed25519.PublicKey(key), nativeRecordingHeadDomain, nativeRecordingHeadFields(head), head.Signature, nativeformat.MaxMetadataPayload); err != nil {
		return NativeRecordingHead{}, err
	}
	return head, nil
}

// VerifyNativeRecordingCheckpoint authenticates an exact committed prefix of
// an already sealed recording without requiring its encryption recipient or
// any mutation capability. The caller must verify the complete seal as well.
func VerifyNativeRecordingCheckpoint(source io.ReaderAt, size int64, headPayload []byte, identity *audit.Identity, options NativeRecordingVerifyOptions) error {
	maximum := options.MaximumContainerBytes
	if maximum == 0 {
		maximum = DefaultMaximumNativeRecordingBytes
	}
	castMaximum := effectiveMaximumCastBytes(options.MaximumCastBytes)
	if source == nil || identity == nil || identity.PublicKey() == nil || size < int64(len(nativeformat.RecordingMagic))+18 || size > maximum || maximum < 1 || castMaximum < 1 {
		return fmt.Errorf("invalid native checkpoint input or limits")
	}
	var magic [len(nativeformat.RecordingMagic)]byte
	if _, err := source.ReadAt(magic[:], 0); err != nil || string(magic[:]) != nativeformat.RecordingMagic {
		return fmt.Errorf("invalid native checkpoint magic: %v", err)
	}
	offset := int64(len(magic))
	unit, next, tail, err := nativeformat.ReadUnitAt(source, offset, size, nativeformat.MaxMetadataPayload)
	if err != nil || tail || unit.Type != nativeformat.HeaderUnit {
		return fmt.Errorf("invalid native checkpoint header: %v", err)
	}
	header, key, err := verifyNativeRecordingHeader(unit.Payload)
	if err != nil || header.ProducerId != [32]byte(identity.ProducerId()) || !bytes.Equal(header.PublicKey, identity.PublicKey().Marshal()) {
		return fmt.Errorf("native checkpoint identity mismatch: %v", err)
	}
	head, err := VerifyNativeRecordingHead(headPayload, unit.Payload)
	if err != nil {
		return err
	}
	if head.PrefixBytes > uint64(size) || head.PrefixBytes <= uint64(next) || head.ChunkCount > effectiveMaximumNativeRecordingChunks(options.MaximumChunks) {
		return fmt.Errorf("native checkpoint prefix or chunk count exceeds limits")
	}
	previous, err := hashNativeRecordingUnit(source, offset, next)
	if err != nil {
		return err
	}
	var count, castHashBytes, lastElapsed uint64
	var castState [32]byte
	for offset = next; uint64(offset) < head.PrefixBytes; offset = next {
		if options.Context != nil && options.Context.Err() != nil {
			return options.Context.Err()
		}
		unit, next, tail, err = nativeformat.ReadUnitAt(source, offset, int64(head.PrefixBytes), nativeformat.MaxRecordingChunkPayload)
		if err != nil || tail || unit.Type != nativeformat.ContentUnit || count >= head.ChunkCount {
			return fmt.Errorf("invalid committed native checkpoint chunk: %v", err)
		}
		chunk, err := nativeformat.Unmarshal[nativeRecordingChunk](unit.Payload, nativeformat.MaxRecordingChunkPayload)
		if err != nil {
			return err
		}
		if err := chunk.ValidateNativeWire(); err != nil {
			return err
		}
		if chunk.Sequence != count+1 || chunk.PreviousUnitHash != previous || chunk.CastHashBytes == 0 || chunk.CastHashBytes <= castHashBytes || chunk.CastHashBytes > uint64(castMaximum)+uint64(len(castContentHashDomain)) || *chunk.LastElapsedNanos < lastElapsed || len(chunk.StoredPayload) == 0 || len(chunk.StoredPayload) > nativeformat.MaxRecordingChunkPayload-256 || chunk.StoredHash != sha256.Sum256(chunk.StoredPayload) {
			return fmt.Errorf("native checkpoint chunk chain or stored hash mismatch")
		}
		if err := nativeRecordingVerify(key, nativeRecordingChunkDomain, nativeRecordingChunkFields(chunk), chunk.Signature, nativeformat.MaxRecordingChunkPayload); err != nil {
			return err
		}
		if header.Encryption == 1 {
			if !bytes.HasPrefix(chunk.StoredPayload, []byte(nativeRecordingAgePrefix)) {
				return fmt.Errorf("native checkpoint chunk lacks age ciphertext")
			}
		} else {
			decoded, err := nativeformat.DecodeStoredPayload(chunk.StoredPayload, nil, "", nativeRecordingPayloadLimits)
			if err != nil || len(decoded) != int(chunk.DecodedLength) {
				return fmt.Errorf("invalid clear native checkpoint chunk: %v", err)
			}
			if _, err := decodeNativeRecordingEvents(decoded); err != nil {
				return err
			}
		}
		if _, err := resumeCastSha256(castSha256Checkpoint{State: chunk.CastHashState, Bytes: chunk.CastHashBytes}); err != nil {
			return err
		}
		previous, err = hashNativeRecordingUnit(source, offset, next)
		if err != nil {
			return err
		}
		count++
		castHashBytes, castState, lastElapsed = chunk.CastHashBytes, chunk.CastHashState, *chunk.LastElapsedNanos
	}
	if uint64(offset) != head.PrefixBytes || count != head.ChunkCount || previous != head.LastUnitHash || castHashBytes != head.CastHashBytes || castState != head.CastHashState {
		return fmt.Errorf("native recording does not contain its exact signed checkpoint")
	}
	return nil
}
