package cast

import (
	"context"
	"fmt"
	"io"
	"time"

	audit "github.com/engity-com/bifroest/pkg/audit/evidence"
	"github.com/engity-com/bifroest/pkg/crypto/keydata"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

// ReadNativeRecordingHeader decodes public format hints without authenticating
// them. It performs no signature, content hash, chain or producer-trust check.
func ReadNativeRecordingHeader(source io.ReaderAt, size int64) (NativeRecordingHeader, error) {
	var header NativeRecordingHeader
	if source == nil || size < int64(len(nativeformat.RecordingMagic))+18 {
		return header, fmt.Errorf("missing native recording input")
	}
	magic := make([]byte, len(nativeformat.RecordingMagic))
	if _, err := source.ReadAt(magic, 0); err != nil || string(magic) != nativeformat.RecordingMagic {
		return header, fmt.Errorf("invalid recording magic")
	}
	unit, _, tail, err := nativeformat.ReadUnitAt(source, int64(len(magic)), size, nativeformat.MaxMetadataPayload)
	if err != nil || tail || unit.Type != nativeformat.HeaderUnit {
		return header, fmt.Errorf("invalid recording header")
	}
	header, err = nativeformat.Unmarshal[NativeRecordingHeader](unit.Payload, nativeformat.MaxMetadataPayload)
	if err != nil {
		return header, err
	}
	if (header.Version != 1 && header.Version != 2) || header.Encryption > 1 || validateId(Id(header.RecordingId)) != nil || (header.Encryption == 1) != (header.Recipient != "") || header.Recipient != "" && !nativeRecordingRecipientValid(header.Recipient) {
		return header, fmt.Errorf("invalid recording header fields")
	}
	return header, nil
}

// ReadNativeRecordingContents is a bounded playback decoder, not a verifier.
// age authentication is mandatory when decrypting; invalid ciphertext is never
// released. Callers stage all events until decoding reaches physical EOF.
func ReadNativeRecordingContents(ctx context.Context, source io.ReaderAt, size, maximum int64, identities *keydata.AgeSshIdentities, visit func(CastEvent) error) (*CastContents, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if maximum < 1 || size > maximum {
		return nil, fmt.Errorf("recording input exceeds playback limit")
	}
	header, err := ReadNativeRecordingHeader(source, size)
	if err != nil {
		return nil, err
	}
	if header.Encryption == 1 && identities == nil {
		return nil, fmt.Errorf("recording requires decryption key")
	}
	_, offset, _, err := nativeformat.ReadUnitAt(source, int64(len(nativeformat.RecordingMagic)), size, nativeformat.MaxMetadataPayload)
	if err != nil {
		return nil, err
	}
	result := &CastContents{}
	var groups uint64
	var decodedTotal int64
	var setup, ended bool
	var elapsed time.Duration
	for offset < size {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		unit, next, tail, err := nativeformat.ReadUnitAt(source, offset, size, nativeformat.MaxRecordingChunkPayload)
		if err != nil || tail {
			return nil, fmt.Errorf("invalid recording unit")
		}
		if unit.Type == nativeformat.SealUnit {
			seal, err := nativeformat.Unmarshal[NativeRecordingSeal](unit.Payload, nativeformat.MaxMetadataPayload)
			if err != nil || !setup || !ended || next != size || seal.ChunkCount != groups {
				return nil, fmt.Errorf("invalid recording termination")
			}
			return result, nil
		}
		if unit.Type != nativeformat.ContentUnit || ended || groups >= DefaultMaximumNativeRecordingChunks {
			return nil, fmt.Errorf("invalid recording event sequence")
		}
		chunk, err := nativeformat.Unmarshal[NativeRecordingChunk](unit.Payload, nativeformat.MaxRecordingChunkPayload)
		if err != nil || chunk.Sequence != groups+1 || int64(chunk.DecodedLength) > maximum-decodedTotal {
			return nil, fmt.Errorf("invalid recording chunk or decoded budget")
		}
		decoded, err := nativeformat.DecodeStoredPayload(chunk.StoredPayload, identities, header.Recipient, nativeRecordingPayloadLimits)
		if err != nil {
			return nil, fmt.Errorf("recording payload authentication/decoding failed: %w", err)
		}
		if len(decoded) != int(chunk.DecodedLength) {
			clear(decoded)
			return nil, fmt.Errorf("recording decoded length mismatch")
		}
		decodedTotal += int64(len(decoded))
		events, err := decodeNativeRecordingEvents(decoded)
		clear(decoded)
		if err != nil {
			return nil, err
		}
		for _, event := range events {
			if ended {
				clear(event.Data)
				return nil, fmt.Errorf("recording event after result")
			}
			if event.Kind == NativeEventSetup {
				if setup || groups != 0 || event.Metadata.RecordingId != Id(header.RecordingId) || event.Metadata.ProducerId != audit.ProducerId(header.ProducerId) {
					return nil, fmt.Errorf("invalid recording setup")
				}
				result.Header, result.Metadata, setup = event.Header, event.Metadata, true
				continue
			}
			if !setup {
				return nil, fmt.Errorf("missing recording setup")
			}
			if event.Kind == NativeEventPaddingCheckpoint {
				continue
			}
			if event.Elapsed < elapsed {
				clear(event.Data)
				return nil, fmt.Errorf("recording time moved backwards")
			}
			elapsed = event.Elapsed
			decodedEvent := CastEvent{Elapsed: elapsed, Stream: event.Stream, Data: event.Data, Columns: event.Columns, Rows: event.Rows}
			switch event.Kind {
			case NativeEventOutput:
				if result.Metadata.Pty != (event.Stream == OutputStreamTerminal) {
					clear(event.Data)
					return nil, fmt.Errorf("recording stream does not match terminal mode")
				}
				decodedEvent.Code = "o"
			case NativeEventResize:
				if !result.Metadata.Pty {
					return nil, fmt.Errorf("resize in non-PTY recording")
				}
				decodedEvent.Code = "r"
			case NativeEventMarker:
				decodedEvent.Code = "m"
			case NativeEventResult:
				result.Result, result.ExitStatus, ended = event.Result, event.ExitStatus, true
				decodedEvent.Code = "x"
			default:
				return nil, fmt.Errorf("unsupported recording event")
			}
			if visit != nil {
				err = visit(decodedEvent)
			}
			clear(event.Data)
			if err != nil {
				return nil, err
			}
		}
		groups++
		offset = next
	}
	return nil, fmt.Errorf("recording has no complete termination")
}
