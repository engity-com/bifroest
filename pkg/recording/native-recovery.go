package recording

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

// NativeRecoveryFile must be exclusively locked by its owner. The writer uses
// WriteAt rather than append mode to commit a complete frame only after Sync.
type NativeRecoveryFile interface {
	RecoveryFile
	io.WriterAt
}

type NativeRecordingRecoveryResult struct {
	Verification  *NativeRecordingVerification
	AlreadySealed bool
	Truncated     bool
	Finalized     bool
}

// RecoverNativeRecording verifies every committed unit and the exact signed
// head checkpoint before changing the file. It never decrypts stored chunks.
// The caller must hold an exclusive lock throughout, then sync the parent
// directory and publish only after the returned sealed file is verified.
func RecoverNativeRecording(file NativeRecoveryFile, identity *audit.Identity, recipient *bfcrypto.AgeSshRecipient, headPayload []byte, recoveredAt time.Time, options NativeRecordingVerifyOptions) (*NativeRecordingRecoveryResult, error) {
	if file == nil || identity == nil || identity.PublicKey() == nil || recoveredAt.IsZero() || recoveredAt.Location() != time.UTC {
		return nil, fmt.Errorf("invalid native recording recovery arguments")
	}
	if !options.ExpectedProducerId.IsZero() && options.ExpectedProducerId != identity.ProducerId() {
		return nil, fmt.Errorf("native recovery producer does not match identity")
	}
	options.ExpectedProducerId = identity.ProducerId()
	options.AllowUntrusted = false
	maximum := options.MaximumContainerBytes
	if maximum == 0 {
		maximum = DefaultMaximumBECastBytes
	}
	castMaximum := effectiveMaximumCastBytes(options.MaximumCastBytes)
	if maximum < 1 || castMaximum < 1 {
		return nil, fmt.Errorf("invalid native recovery limits")
	}
	maxChunks := effectiveMaximumBECastChunks(options.MaximumChunks)
	size, err := file.Seek(0, io.SeekEnd)
	if err != nil || size < int64(len(nativeformat.RecordingMagic))+18 || size > maximum {
		return nil, fmt.Errorf("invalid native recovery file size: %v", err)
	}
	var magic [len(nativeformat.RecordingMagic)]byte
	if _, err := file.ReadAt(magic[:], 0); err != nil || string(magic[:]) != nativeformat.RecordingMagic {
		return nil, fmt.Errorf("invalid native recording recovery magic: %v", err)
	}
	offset := int64(len(magic))
	unit, next, tail, err := nativeformat.ReadUnitAt(file, offset, size, nativeformat.MaxMetadataPayload)
	if err != nil || tail || unit.Type != nativeformat.HeaderUnit {
		return nil, fmt.Errorf("invalid native recording recovery header: %v", err)
	}
	header, key, err := verifyNativeRecordingHeader(unit.Payload)
	if err != nil || header.ProducerId != [32]byte(identity.ProducerId()) || !bytes.Equal(header.PublicKey, identity.PublicKey().Marshal()) {
		return nil, fmt.Errorf("native recording recovery identity mismatch: %v", err)
	}
	if header.Encryption == 1 {
		if recipient == nil || header.Recipient != recipient.Fingerprint() || recipient.Fingerprint() == identity.Fingerprint() {
			return nil, fmt.Errorf("native recovery recipient does not match signed header")
		}
	} else if recipient != nil {
		return nil, fmt.Errorf("clear native recording cannot recover with a recipient")
	}
	hasHead := len(headPayload) != 0
	var head NativeRecordingHead
	if hasHead {
		head, err = VerifyNativeRecordingHead(headPayload, unit.Payload)
		if err != nil {
			return nil, fmt.Errorf("invalid signed native recovery head: %w", err)
		}
		if head.PrefixBytes > uint64(size) {
			return nil, fmt.Errorf("native recording lost data behind signed head")
		}
	}
	previous, err := hashNativeRecordingUnit(file, offset, next)
	if err != nil {
		return nil, err
	}
	offset = next
	var count, castHashBytes, lastElapsed uint64
	var castState [32]byte
	var final *nativeRecordingChunk
	checkpointSeen := !hasHead
	validEnd := offset
	incompleteTail := false
	for offset < size {
		if options.Context != nil && options.Context.Err() != nil {
			return nil, options.Context.Err()
		}
		unit, next, tail, err = nativeformat.ReadUnitAt(file, offset, size, nativeformat.MaxRecordingChunkPayload)
		if err != nil {
			return nil, fmt.Errorf("invalid committed native recovery unit: %w", err)
		}
		if tail {
			if !hasHead || !checkpointSeen || uint64(offset) < head.PrefixBytes {
				return nil, fmt.Errorf("uncommitted native tail precedes the signed checkpoint")
			}
			incompleteTail = true
			break
		}
		switch unit.Type {
		case nativeformat.ContentUnit:
			if final != nil || count >= maxChunks {
				return nil, fmt.Errorf("unexpected native recovery chunk after final chunk or chunk limit")
			}
			chunk, err := nativeformat.Unmarshal[nativeRecordingChunk](unit.Payload, nativeformat.MaxRecordingChunkPayload)
			if err != nil {
				return nil, err
			}
			if chunk.Sequence != count+1 || chunk.PreviousUnitHash != previous || len(chunk.StoredPayload) == 0 || len(chunk.StoredPayload) > nativeformat.MaxRecordingChunkPayload-256 || chunk.StoredHash != sha256.Sum256(chunk.StoredPayload) {
				return nil, fmt.Errorf("native recovery chunk chain or stored hash mismatch")
			}
			if err := nativeRecordingVerify(key, nativeRecordingChunkDomain, nativeRecordingChunkFields(chunk), chunk.Signature, nativeformat.MaxRecordingChunkPayload); err != nil {
				return nil, err
			}
			if header.Encryption == 1 {
				if !bytes.HasPrefix(chunk.StoredPayload, []byte(nativeRecordingAgePrefix)) {
					return nil, fmt.Errorf("native recovery chunk lacks age ciphertext")
				}
			} else {
				decoded, err := nativeformat.DecodeStoredPayload(chunk.StoredPayload, nil, "", nativeRecordingPayloadLimits)
				if err != nil || len(decoded) != int(chunk.DecodedLength) {
					return nil, fmt.Errorf("invalid clear native recovery chunk: %v", err)
				}
				if _, err := decodeNativeRecordingEvents(decoded); err != nil {
					return nil, err
				}
			}
			if chunk.CastHashBytes == 0 {
				final = &chunk
				if *chunk.CastBytes > uint64(castMaximum) {
					return nil, fmt.Errorf("native recovery final Cast exceeds configured limit")
				}
			} else {
				if chunk.CastHashBytes <= castHashBytes || chunk.CastHashBytes > uint64(castMaximum)+uint64(len(castContentHashDomain)) {
					return nil, fmt.Errorf("native recovery Cast continuation is invalid")
				}
				if *chunk.LastElapsedNanos < lastElapsed {
					return nil, fmt.Errorf("native recovery event time moved backwards")
				}
				if _, err := resumeCastSha256(castSha256Checkpoint{State: chunk.CastHashState, Bytes: chunk.CastHashBytes}); err != nil {
					return nil, err
				}
				castHashBytes, castState = chunk.CastHashBytes, chunk.CastHashState
				lastElapsed = *chunk.LastElapsedNanos
			}
			previous, err = hashNativeRecordingUnit(file, offset, next)
			if err != nil {
				return nil, err
			}
			count++
			if count == head.ChunkCount {
				if chunk.CastHashBytes == 0 || uint64(next) != head.PrefixBytes || previous != head.LastUnitHash || castHashBytes != head.CastHashBytes || castState != head.CastHashState {
					return nil, fmt.Errorf("native recovery file does not contain its exact signed checkpoint")
				}
				checkpointSeen = true
			}
		case nativeformat.SealUnit:
			if !checkpointSeen || final == nil || next != size {
				return nil, fmt.Errorf("unexpected native recovery seal")
			}
			verified, err := VerifyNativeRecordingOuter(file, size, options)
			if err != nil {
				return nil, err
			}
			if err := file.Sync(); err != nil {
				return nil, err
			}
			return &NativeRecordingRecoveryResult{Verification: verified, AlreadySealed: true}, nil
		default:
			return nil, fmt.Errorf("unexpected native recovery unit type %d", unit.Type)
		}
		validEnd, offset = next, next
	}
	if !checkpointSeen || count < head.ChunkCount || validEnd < int64(head.PrefixBytes) {
		return nil, fmt.Errorf("native recording lost its signed checkpoint")
	}
	if !hasHead && final == nil {
		return nil, fmt.Errorf("native recording without head has no committed final chunk; refusing to discard possible events")
	}
	start, err := header.StartedAt.Time()
	if err != nil {
		return nil, err
	}
	if recoveredAt.Before(start) {
		recoveredAt = start
	}
	if final == nil && recoveredAt.Before(start.Add(time.Duration(lastElapsed))) {
		recoveredAt = start.Add(time.Duration(lastElapsed))
	}
	signer, err := NewNativeRecordingSigner(identity)
	if err != nil {
		return nil, err
	}
	var pendingFrame []byte
	var status uint8
	var digest [32]byte
	var castSignature []byte
	var castBytes uint64
	var endedAt nativeformat.Timestamp
	if final != nil {
		status, digest, castSignature, castBytes, endedAt = final.FinalStatus, *final.CastDigest, final.CastSignature, *final.CastBytes, *final.EndedAt
	} else {
		if count >= maxChunks || recoveredAt.After(start.Add(maximumEventElapsed)) {
			return nil, fmt.Errorf("native recovery cannot add an incomplete final chunk within configured limits")
		}
		result := CastResult{Status: CastStatusIncomplete, EndedAt: recoveredAt, Reason: startupRecoveryReason}
		if err := validateCastResult(CastMetadata{StartedAt: start}, result, false); err != nil {
			return nil, err
		}
		resultLine, err := encodeCastRecoveryResultLine(result)
		if err != nil {
			return nil, err
		}
		continuation, err := resumeCastSha256(castSha256Checkpoint{State: castState, Bytes: castHashBytes})
		if err != nil {
			return nil, err
		}
		_, _ = continuation.Write(resultLine)
		copy(digest[:], continuation.Sum(nil))
		castSignatureValue, err := identity.NewSessionRecordingCastSignature(Id(header.RecordingId).String(), CastDigest(digest).String())
		if err != nil {
			return nil, err
		}
		castSignature = castSignatureValue.Signature
		signatureJSON, err := json.Marshal(castSignatureValue)
		if err != nil {
			return nil, err
		}
		castBytes = castHashBytes - uint64(len(castContentHashDomain)) + uint64(len(resultLine)+len(castSignatureCommentPrefix)+len(signatureJSON)+1)
		if castBytes > uint64(castMaximum) {
			return nil, fmt.Errorf("recovered native Cast exceeds configured limit")
		}
		status, endedAt = 3, nativeformat.TimestampOf(recoveredAt)
		decoded, err := EncodeNativeRecordingEvents([]NativeCastEvent{{Kind: NativeEventResult, Elapsed: time.Duration(lastElapsed), Result: result}})
		if err != nil {
			return nil, err
		}
		stored, err := nativeformat.EncodeStoredPayload(decoded, recipient, nativeRecordingPayloadLimits)
		if err != nil {
			return nil, err
		}
		chunk := nativeRecordingChunk{
			Sequence: count + 1, PreviousUnitHash: previous, DecodedLength: uint32(len(decoded)),
			StoredPayload: stored, StoredHash: sha256.Sum256(stored), CastHashState: digest,
			FinalStatus: status, CastDigest: &digest, CastSignature: castSignature,
			CastBytes: &castBytes, EndedAt: &endedAt,
		}
		payload, err := signer.Chunk(chunk)
		if err != nil {
			return nil, err
		}
		pendingFrame, err = nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxRecordingChunkPayload)
		if err != nil {
			return nil, err
		}
		previous = nativeRecordingHash(nativeRecordingUnitDomain, pendingFrame)
		count++
	}
	// Hash the exact committed file prefix, not the uncommitted physical tail.
	contentHash, err := hashNativeRecordingContent(file, validEnd)
	if err != nil {
		return nil, err
	}
	if len(pendingFrame) > 0 {
		h := sha256.New()
		_, _ = h.Write([]byte(nativeRecordingContentDomain))
		if _, err := io.Copy(h, io.NewSectionReader(file, 0, validEnd)); err != nil {
			return nil, err
		}
		_, _ = h.Write(pendingFrame)
		copy(contentHash[:], h.Sum(nil))
	}
	seal := nativeRecordingSeal{Status: status, ChunkCount: count, LastUnitHash: previous, ContentHash: contentHash, CastDigest: digest, CastSignature: castSignature, CastBytes: castBytes, EndedAt: endedAt}
	sealPayload, err := signer.Seal(seal, Id(header.RecordingId))
	if err != nil {
		return nil, err
	}
	sealFrame, err := nativeformat.EncodeUnit(nativeformat.SealUnit, sealPayload, nativeformat.MaxMetadataPayload)
	if err != nil || int64(len(pendingFrame))+int64(len(sealFrame)) > maximum-validEnd {
		return nil, fmt.Errorf("recovered native container exceeds its limit: %v", err)
	}
	currentSize, err := file.Seek(0, io.SeekEnd)
	if err != nil || currentSize != size {
		return nil, fmt.Errorf("native recovery file changed before mutation: %v", err)
	}
	if incompleteTail {
		if err := file.Truncate(validEnd); err != nil {
			return nil, err
		}
		if err := file.Sync(); err != nil {
			return nil, err
		}
	}
	if len(pendingFrame) > 0 {
		if err := commitNativeRecoveryUnit(file, validEnd, pendingFrame); err != nil {
			return nil, err
		}
		validEnd += int64(len(pendingFrame))
	}
	if err := commitNativeRecoveryUnit(file, validEnd, sealFrame); err != nil {
		return nil, err
	}
	finalSize := validEnd + int64(len(sealFrame))
	verified, err := VerifyNativeRecordingOuter(file, finalSize, options)
	if err != nil {
		return nil, fmt.Errorf("recovered native recording failed final verification: %w", err)
	}
	return &NativeRecordingRecoveryResult{Verification: verified, Truncated: incompleteTail, Finalized: true}, nil
}

func commitNativeRecoveryUnit(file NativeRecoveryFile, offset int64, committed []byte) error {
	unit := bytes.Clone(committed)
	unit[5] = 0
	n, err := file.WriteAt(unit, offset)
	if err != nil {
		return err
	}
	if n != len(unit) {
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return err
	}
	n, err = file.WriteAt([]byte{1}, offset+5)
	if err != nil {
		return err
	}
	if n != 1 {
		return io.ErrShortWrite
	}
	return file.Sync()
}
