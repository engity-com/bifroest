package cast

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

// NativeRecordingMetadata authenticates only the signed header, seal and (for
// clear recordings) setup chunk. It is NOT whole-envelope/inner verification.
// It is suitable for selection hints; selected content must still be verified.
type NativeRecordingMetadata struct {
	Header   NativeRecordingHeader
	Seal     NativeRecordingSeal
	Metadata *CastMetadata
}

func ReadNativeRecordingMetadata(source io.ReaderAt, size int64, options NativeRecordingVerifyOptions) (*NativeRecordingMetadata, error) {
	if options.Context != nil && options.Context.Err() != nil {
		return nil, options.Context.Err()
	}
	if source == nil || size < int64(len(nativeformat.RecordingMagic))+18 {
		return nil, fmt.Errorf("missing native recording metadata")
	}
	var magic [len(nativeformat.RecordingMagic)]byte
	if _, err := source.ReadAt(magic[:], 0); err != nil || string(magic[:]) != nativeformat.RecordingMagic {
		return nil, fmt.Errorf("invalid native recording magic")
	}
	unit, next, tail, err := nativeformat.ReadUnitAt(source, int64(len(magic)), size, nativeformat.MaxMetadataPayload)
	if err != nil || tail || unit.Type != nativeformat.HeaderUnit {
		return nil, fmt.Errorf("invalid recording metadata header: %v", err)
	}
	header, key, err := verifyNativeRecordingHeader(unit.Payload)
	if err != nil {
		return nil, err
	}
	if options.ExpectedProducerId.IsZero() && !options.AllowUntrusted || !options.ExpectedProducerId.IsZero() && header.ProducerId != [32]byte(options.ExpectedProducerId) {
		return nil, fmt.Errorf("recording metadata producer mismatch")
	}
	sealUnit, _, err := nativeformat.ReadFinalMetadataUnit(source, size, nativeformat.SealUnit)
	if err != nil {
		return nil, err
	}
	seal, err := nativeformat.Unmarshal[nativeRecordingSeal](sealUnit.Payload, nativeformat.MaxMetadataPayload)
	if err != nil {
		return nil, err
	}
	if err := validateNativeRecordingSeal(seal, header); err != nil {
		return nil, err
	}
	if err := nativeRecordingVerify(key, nativeRecordingSealDomain, nativeRecordingSealFields(seal), seal.Signature, nativeformat.MaxMetadataPayload); err != nil {
		return nil, err
	}
	result := &NativeRecordingMetadata{Header: header, Seal: seal}
	if header.Encryption == 0 {
		previous, err := hashNativeRecordingUnit(source, int64(len(magic)), next)
		if err != nil {
			return nil, err
		}
		unit, _, tail, err = nativeformat.ReadUnitAt(source, next, size, nativeformat.MaxRecordingChunkPayload)
		if err != nil || tail || unit.Type != nativeformat.ContentUnit {
			return nil, fmt.Errorf("invalid recording setup chunk: %v", err)
		}
		chunk, err := nativeformat.Unmarshal[nativeRecordingChunk](unit.Payload, nativeformat.MaxRecordingChunkPayload)
		if err != nil {
			return nil, err
		}
		if chunk.Sequence != 1 || chunk.PreviousUnitHash != previous || chunk.StoredHash != sha256.Sum256(chunk.StoredPayload) {
			return nil, fmt.Errorf("invalid recording setup commitment")
		}
		if err := nativeRecordingVerify(key, nativeRecordingChunkDomain, nativeRecordingChunkFields(chunk), chunk.Signature, nativeformat.MaxRecordingChunkPayload); err != nil {
			return nil, err
		}
		decoded, err := nativeformat.DecodeStoredPayload(chunk.StoredPayload, nil, "", nativeRecordingPayloadLimits)
		if err != nil {
			return nil, err
		}
		defer clear(decoded)
		if len(decoded) != int(chunk.DecodedLength) {
			return nil, fmt.Errorf("invalid recording setup length")
		}
		events, err := decodeNativeRecordingEvents(decoded)
		if err != nil || len(events) == 0 || events[0].Kind != NativeEventSetup {
			return nil, fmt.Errorf("missing recording setup metadata: %v", err)
		}
		metadata := events[0].Metadata
		if [16]byte(metadata.RecordingId) != header.RecordingId || [32]byte(metadata.ProducerId) != header.ProducerId || nativeformat.TimestampOf(metadata.StartedAt) != header.StartedAt {
			return nil, fmt.Errorf("recording setup identity mismatch")
		}
		result.Metadata = &metadata
	}
	if options.Context != nil && options.Context.Err() != nil {
		return nil, options.Context.Err()
	}
	return result, nil
}
