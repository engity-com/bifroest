package recording

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

// VerifyNativeRecordingFull checks the outer container before independently
// decoding every chunk and verifying the reconstructed Cast through a pipe.
// The source must remain an immutable ReaderAt snapshot for all passes.
func VerifyNativeRecordingFull(source io.ReaderAt, size int64, identities *bfcrypto.AgeSshIdentities, options NativeRecordingVerifyOptions) (*NativeRecordingVerification, error) {
	return verifyNativeRecordingFull(source, size, identities, options)
}

// ExportNativeRecordingCast emits nothing until the entire Cast passes full
// verification. The second pass requires the *same immutable input*. A failing
// output writer may still leave a partial, already verified export; callers
// publishing to a file must use their own atomic temporary-file protocol.
func ExportNativeRecordingCast(source io.ReaderAt, size int64, identities *bfcrypto.AgeSshIdentities, output io.Writer, options NativeRecordingVerifyOptions) (*NativeRecordingVerification, error) {
	if output == nil {
		return nil, fmt.Errorf("missing native Cast export output")
	}
	verification, err := verifyNativeRecordingFull(source, size, identities, options)
	if err != nil {
		return nil, err
	}
	renderer, err := newNativeCastRenderer(output, verification.Header, verification.Seal, int64(verification.Seal.CastBytes))
	if err != nil {
		return nil, err
	}
	if err := walkNativeRecordingGroups(source, size, identities, verification, options, renderer); err != nil {
		return nil, err
	}
	return verification, nil
}

func verifyNativeRecordingFull(source io.ReaderAt, size int64, identities *bfcrypto.AgeSshIdentities, options NativeRecordingVerifyOptions) (*NativeRecordingVerification, error) {
	verification, err := VerifyNativeRecordingOuter(source, size, options)
	if err != nil {
		return nil, err
	}
	if verification.Header.Encryption == 1 && identities == nil {
		return nil, fmt.Errorf("encrypted native recording requires an offline decryption identity")
	}
	reader, writer := io.Pipe()
	type castResult struct {
		verification *CastVerification
		err          error
	}
	result := make(chan castResult, 1)
	go func() {
		cast, err := VerifyCast(reader, CastVerifyOptions{
			Context: options.Context, MaximumBytes: int64(verification.Seal.CastBytes),
			ExpectedProducerId: options.ExpectedProducerId, AllowUntrusted: options.AllowUntrusted,
		})
		_ = reader.CloseWithError(err)
		result <- castResult{cast, err}
	}()
	renderer, err := newNativeCastRenderer(writer, verification.Header, verification.Seal, int64(verification.Seal.CastBytes))
	if err == nil {
		err = walkNativeRecordingGroups(source, size, identities, verification, options, renderer)
	}
	_ = writer.CloseWithError(err)
	cast := <-result
	if err != nil {
		return nil, err
	}
	if cast.err != nil {
		return nil, fmt.Errorf("reconstructed native Cast failed full verification: %w", cast.err)
	}
	if cast.verification == nil || cast.verification.Digest != CastDigest(verification.Seal.CastDigest) {
		return nil, fmt.Errorf("reconstructed native Cast digest differs from seal")
	}
	return verification, nil
}

// walkNativeRecordingGroups keeps at most one framed unit and one 2 MiB
// decoded group resident. It rechecks the chain and exact physical content
// digest so a changed input between the outer and inner passes fails closed.
func walkNativeRecordingGroups(source io.ReaderAt, size int64, identities *bfcrypto.AgeSshIdentities, verification *NativeRecordingVerification, options NativeRecordingVerifyOptions, renderer *nativeCastRenderer) error {
	offset := int64(len(nativeformat.RecordingMagic))
	unit, next, tail, err := nativeformat.ReadUnitAt(source, offset, size, nativeformat.MaxMetadataPayload)
	if err != nil || tail || unit.Type != nativeformat.HeaderUnit {
		return fmt.Errorf("native header changed after outer verification: %v", err)
	}
	headerPayload, err := nativeformat.Marshal(verification.Header, nativeformat.MaxMetadataPayload)
	if err != nil || !bytes.Equal(headerPayload, unit.Payload) {
		return fmt.Errorf("native header changed after outer verification")
	}
	_, publicKey, err := verifyNativeRecordingHeader(unit.Payload)
	if err != nil {
		return err
	}
	previous, err := hashNativeRecordingUnit(source, offset, next)
	if err != nil {
		return err
	}
	offset = next
	for sequence := uint64(1); sequence <= verification.Seal.ChunkCount; sequence++ {
		if options.Context != nil && options.Context.Err() != nil {
			return options.Context.Err()
		}
		unit, next, tail, err = nativeformat.ReadUnitAt(source, offset, size, nativeformat.MaxRecordingChunkPayload)
		if err != nil || tail || unit.Type != nativeformat.ContentUnit {
			return fmt.Errorf("native chunk changed after outer verification: %v", err)
		}
		chunk, err := nativeformat.Unmarshal[nativeRecordingChunk](unit.Payload, nativeformat.MaxRecordingChunkPayload)
		if err != nil {
			return err
		}
		if chunk.Sequence != sequence || chunk.PreviousUnitHash != previous || chunk.StoredHash != sha256.Sum256(chunk.StoredPayload) {
			return fmt.Errorf("native chunk chain changed after outer verification")
		}
		if err := nativeRecordingVerify(publicKey, nativeRecordingChunkDomain, nativeRecordingChunkFields(chunk), chunk.Signature, nativeformat.MaxRecordingChunkPayload); err != nil {
			return err
		}
		decoded, err := nativeformat.DecodeStoredPayload(chunk.StoredPayload, identities, verification.Header.Recipient, nativeRecordingPayloadLimits)
		if err != nil || len(decoded) != int(chunk.DecodedLength) {
			return fmt.Errorf("cannot fully decode native chunk %d: %v", sequence, err)
		}
		events, err := decodeNativeRecordingEvents(decoded)
		if err != nil {
			return fmt.Errorf("invalid native recording events in chunk %d: %w", sequence, err)
		}
		if err := renderer.consumeGroup(events); err != nil {
			return err
		}
		if chunk.CastHashBytes != 0 {
			if uint64(renderer.writer.lastElapsed) != *chunk.LastElapsedNanos {
				return fmt.Errorf("native chunk %d signed elapsed time mismatch", sequence)
			}
			checkpoint, err := checkpointCastSha256(renderer.writer.digest)
			if err != nil || checkpoint.State != chunk.CastHashState || checkpoint.Bytes != chunk.CastHashBytes {
				return fmt.Errorf("native chunk %d Cast hash continuation mismatch: %v", sequence, err)
			}
		} else if !renderer.finished || CastDigest(chunk.CastHashState) != CastDigest(verification.Seal.CastDigest) {
			return fmt.Errorf("native final chunk has no matching Cast result")
		}
		previous, err = hashNativeRecordingUnit(source, offset, next)
		if err != nil {
			return err
		}
		offset = next
	}
	if err := renderer.finish(); err != nil {
		return err
	}
	if previous != verification.Seal.LastUnitHash {
		return fmt.Errorf("native recording chain changed after outer verification")
	}
	contentHash, err := hashNativeRecordingContent(source, offset)
	if err != nil || contentHash != verification.Seal.ContentHash {
		return fmt.Errorf("native recording content changed after outer verification: %v", err)
	}
	unit, next, tail, err = nativeformat.ReadUnitAt(source, offset, size, nativeformat.MaxMetadataPayload)
	if err != nil || tail || unit.Type != nativeformat.SealUnit || next != size {
		return fmt.Errorf("native seal changed after outer verification: %v", err)
	}
	sealPayload, err := nativeformat.Marshal(verification.Seal, nativeformat.MaxMetadataPayload)
	if err != nil || !bytes.Equal(sealPayload, unit.Payload) {
		return fmt.Errorf("native seal changed after outer verification")
	}
	return nil
}
