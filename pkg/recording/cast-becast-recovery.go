package recording

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

type BECastRecoveryResult struct {
	Verification  *BECastVerification
	AlreadySealed bool
	Truncated     bool
	Finalized     bool
}

type beCastRecoveryScan struct {
	scanner          *beCastScanner
	validEnd         int64
	incompleteTail   bool
	seal             *audit.SessionRecordingBECastSeal
	latestCheckpoint castSha256Checkpoint
}

type beCastRecoveryPlan struct {
	chunk []byte
	seal  []byte
}

// RecoverBECast repairs an active container and seals it without decrypting
// existing chunks. The caller must hold an exclusive lock for file throughout
// the call. The signed head establishes a minimum durable prefix; rollback
// protection requires an external monotonic or append-only anchor for heads.
func RecoverBECast(file RecoveryFile, identity *audit.Identity, recipient *crypto.AgeSshRecipient, checkpoint audit.SessionRecordingBECastHead, recoveredAt time.Time, options BECastVerifyOptions) (*BECastRecoveryResult, error) {
	if file == nil {
		return nil, errors.System.Newf("nil BECast recovery file")
	}
	if identity == nil || identity.PublicKey() == nil {
		return nil, errors.System.Newf("nil BECast recovery identity")
	}
	if recipient == nil || recipient.Fingerprint() == "" {
		return nil, errors.System.Newf("nil BECast recovery age SSH recipient")
	}
	if recipient.Fingerprint() == ssh.FingerprintSHA256(identity.PublicKey().ToSsh()) {
		return nil, errors.Config.Newf("BECast recovery encryption recipient must differ from the signing identity")
	}
	if options.ExpectedProducerId != (audit.ProducerId{}) && options.ExpectedProducerId != identity.ProducerId() {
		return nil, errors.Config.Newf("BECast recovery identity does not match the expected producer")
	}
	options.ExpectedProducerId = identity.ProducerId()
	options.AllowUntrusted = false
	if options.MaximumContainerBytes == 0 {
		options.MaximumContainerBytes = DefaultMaximumBECastBytes
	}
	if options.MaximumContainerBytes < 1 {
		return nil, errors.Config.Newf("maximum BECast recovery container size must be positive")
	}
	if effectiveMaximumCastBytes(options.MaximumCastBytes) < 1 {
		return nil, errors.Config.Newf("maximum Cast size must be positive")
	}

	size, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, errors.System.Newf("cannot determine BECast recovery size: %w", err)
	}
	scan, err := scanActiveBECast(file, size, options, checkpoint)
	if err != nil {
		return nil, err
	}
	if scan.scanner.header.ProducerId != identity.ProducerId() || !bytes.Equal(scan.scanner.header.PublicKey, identity.PublicKey().Marshal()) {
		return nil, errors.System.Newf("BECast recovery identity does not match its container")
	}
	if scan.scanner.header.RecipientFingerprint != recipient.Fingerprint() {
		return nil, errors.Config.Newf("BECast recovery recipient does not match its container")
	}
	if scan.seal != nil {
		verification, err := VerifyBECast(file, size, options)
		if err != nil {
			return nil, errors.System.Newf("cannot verify sealed BECast recovery container: %w", err)
		}
		if err := file.Sync(); err != nil {
			return nil, errors.System.Newf("cannot synchronize sealed BECast container: %w", err)
		}
		return &BECastRecoveryResult{Verification: verification, AlreadySealed: true}, nil
	}

	plan, err := planRecoveredBECast(identity, recipient, scan, checkpoint, recoveredAt, options)
	if err != nil {
		return nil, err
	}
	currentSize, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, errors.System.Newf("cannot recheck BECast recovery size: %w", err)
	}
	if currentSize != size {
		return nil, errors.System.Newf("BECast recovery file changed while being verified")
	}

	if scan.validEnd != size {
		if !scan.incompleteTail {
			return nil, errors.System.Newf("refusing to truncate a complete BECast unit")
		}
		if err := file.Truncate(scan.validEnd); err != nil {
			return nil, errors.System.Newf("cannot truncate incomplete BECast tail: %w", err)
		}
	}
	if err := file.Sync(); err != nil {
		return nil, errors.System.Newf("cannot synchronize accepted BECast recovery prefix: %w", err)
	}
	if _, err := file.Seek(scan.validEnd, io.SeekStart); err != nil {
		return nil, errors.System.Newf("cannot seek to BECast recovery position: %w", err)
	}
	if err := writeBECastRecoveryPlan(file, plan); err != nil {
		return nil, err
	}
	finalSize, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, errors.System.Newf("cannot determine recovered BECast size: %w", err)
	}
	verification, err := VerifyBECast(file, finalSize, options)
	if err != nil {
		return nil, errors.System.Newf("recovered BECast container failed final verification: %w", err)
	}
	return &BECastRecoveryResult{
		Verification: verification,
		Truncated:    scan.incompleteTail,
		Finalized:    true,
	}, nil
}

func scanActiveBECast(source io.ReaderAt, size int64, options BECastVerifyOptions, checkpoint audit.SessionRecordingBECastHead) (*beCastRecoveryScan, error) {
	if source == nil {
		return nil, errors.System.Newf("nil BECast recovery input")
	}
	if size < 1 || size > options.MaximumContainerBytes {
		return nil, errors.System.Newf("BECast recovery container size %d is outside the supported range", size)
	}
	maximumCastBytes := effectiveMaximumCastBytes(options.MaximumCastBytes)
	maximumChunks := effectiveMaximumBECastChunks(options.MaximumChunks)
	scanner := &beCastScanner{
		source:               source,
		size:                 size,
		maximumCastBytes:     uint64(maximumCastBytes),
		maximumChunks:        maximumChunks,
		context:              options.Context,
		ciphertextStreamHash: newDomainHasher(castBECastCiphertextStreamHashDomain),
	}
	magic, err := scanner.readBytes(len(castBECastFileMagic))
	if err != nil {
		return nil, errors.System.Newf("cannot read BECast recovery file magic: %w", err)
	}
	if !bytes.Equal(magic, []byte(castBECastFileMagic)) {
		return nil, errors.System.Newf("BECast recovery file magic mismatch")
	}
	headerUnit, _, err := scanner.readUnit(castBECastHeaderUnitType)
	if err != nil {
		return nil, errors.System.Newf("cannot read BECast recovery header: %w", err)
	}
	header, err := decodeBECastHeader(headerUnit)
	if err != nil {
		return nil, err
	}
	if header.FormatVersion != castBECastFormatVersion || header.CastVersion != castVersion || header.Codec != castBECastCodec || header.Encryption != castBECastEncryption {
		return nil, errors.System.Newf("unsupported BECast recovery header version, codec, or encryption")
	}
	publicKey, err := audit.VerifySessionRecordingBECastHeader(header)
	if err != nil {
		return nil, err
	}
	if header.ProducerId != options.ExpectedProducerId {
		return nil, errors.System.Newf("BECast recovery container belongs to producer %s instead of %s", header.ProducerId, options.ExpectedProducerId)
	}
	if header.RecipientFingerprint == ssh.FingerprintSHA256(publicKey.ToSsh()) {
		return nil, errors.System.Newf("BECast recovery encryption recipient matches its signing identity")
	}
	if checkpoint.FormatVersion != castBECastFormatVersion || checkpoint.RecordingId != header.RecordingId || checkpoint.ProducerId != header.ProducerId {
		return nil, errors.System.Newf("BECast checkpoint does not match its container")
	}
	if err := audit.VerifySessionRecordingBECastHead(publicKey, checkpoint); err != nil {
		return nil, errors.System.Newf("cannot verify BECast checkpoint: %w", err)
	}
	if checkpoint.CastState != castBECastOpenCastState {
		return nil, errors.System.Newf("BECast checkpoint has unsupported Cast state %d", checkpoint.CastState)
	}

	scanner.header = header
	scanner.publicKey = publicKey
	scanner.headerUnitHash = hashBECastUnit(headerUnit)
	scanner.previousUnitHash = scanner.headerUnitHash
	result := &beCastRecoveryScan{scanner: scanner, validEnd: scanner.offset}
	checkpointSeen := false

	for scanner.offset < size {
		if err := scanner.checkContext(); err != nil {
			return nil, err
		}
		unitStart := scanner.offset
		remaining := size - unitStart
		if remaining < castBECastUnitPrefixSize {
			result.incompleteTail = true
			break
		}
		prefix, err := scanner.readAt(unitStart, castBECastUnitPrefixSize)
		if err != nil {
			return nil, err
		}
		if string(prefix[:4]) != castBECastUnitMagic || prefix[5] != 0 || binary.BigEndian.Uint16(prefix[6:]) != 0 {
			return nil, errors.System.Newf("invalid complete BECast unit prefix at offset %d", unitStart)
		}
		bodyLength := binary.BigEndian.Uint32(prefix[8:])
		switch prefix[4] {
		case castBECastChunkUnitType:
			if bodyLength < castBECastChunkDescriptorSize || uint64(bodyLength) > uint64(castBECastChunkDescriptorSize+MaximumBECastCiphertext) {
				return nil, errors.System.Newf("BECast chunk at offset %d declares an invalid body size %d", unitStart, bodyLength)
			}
		case castBECastSealUnitType:
			if bodyLength != castBECastSealBodySize {
				return nil, errors.System.Newf("BECast seal at offset %d declares an invalid body size %d", unitStart, bodyLength)
			}
		default:
			return nil, errors.System.Newf("unexpected complete BECast unit type %d at offset %d", prefix[4], unitStart)
		}
		unitLength := uint64(castBECastUnitPrefixSize+castBECastUnitTrailerSize) + uint64(bodyLength)
		if unitLength > math.MaxInt || unitLength > uint64(remaining) {
			result.incompleteTail = true
			break
		}

		switch prefix[4] {
		case castBECastChunkUnitType:
			if err := scanner.readChunk(); err != nil {
				return nil, errors.System.Newf("cannot validate complete BECast recovery chunk: %w", err)
			}
			result.validEnd = scanner.offset
			chunk := scanner.chunks[len(scanner.chunks)-1].value
			if scanner.chunkCount == checkpoint.ChunkCount {
				if checkpoint.PrefixBytes != uint64(scanner.offset) || checkpoint.LastUnitHash != scanner.previousUnitHash || checkpoint.ContentHashState != chunk.ContentHashState || checkpoint.ContentHashBytes != chunk.ContentHashBytes {
					return nil, errors.System.Newf("BECast container does not contain its exact signed checkpoint state")
				}
				checkpointSeen = true
			}
			if chunk.ContentHashBytes != 0 {
				result.latestCheckpoint = castSha256Checkpoint{State: [32]byte(chunk.ContentHashState), Bytes: chunk.ContentHashBytes}
			}
		case castBECastSealUnitType:
			seal, err := scanner.readSeal()
			if err != nil {
				return nil, errors.System.Newf("cannot validate complete BECast recovery seal: %w", err)
			}
			result.validEnd = scanner.offset
			result.seal = &seal
		}
	}
	if !checkpointSeen {
		return nil, errors.System.Newf("BECast container lost data behind its signed checkpoint")
	}
	return result, nil
}

func validatedBECastRecoveryResult(checkpoint audit.SessionRecordingBECastHead, recoveredAt time.Time) (CastResult, error) {
	if recoveredAt.IsZero() || recoveredAt.Location() != time.UTC {
		return CastResult{}, errors.Config.Newf("BECast recovery time must be nonzero UTC")
	}
	if checkpoint.StartedAtNanoseconds >= 1_000_000_000 {
		return CastResult{}, errors.System.Newf("BECast checkpoint has invalid recording start nanoseconds")
	}
	startedAt := time.Unix(checkpoint.StartedAtUnixSeconds, int64(checkpoint.StartedAtNanoseconds)).UTC()
	if startedAt.Unix() != checkpoint.StartedAtUnixSeconds || startedAt.Nanosecond() != int(checkpoint.StartedAtNanoseconds) {
		return CastResult{}, errors.System.Newf("BECast checkpoint has an invalid recording start time")
	}
	result := CastResult{Status: CastStatusIncomplete, EndedAt: recoveredAt, Reason: startupRecoveryReason}
	if err := validateCastResult(CastMetadata{StartedAt: startedAt}, result, false); err != nil {
		return CastResult{}, errors.System.Newf("cannot create incomplete BECast recovery result: %w", err)
	}
	return result, nil
}

func planRecoveredBECast(identity *audit.Identity, recipient *crypto.AgeSshRecipient, scan *beCastRecoveryScan, checkpoint audit.SessionRecordingBECastHead, recoveredAt time.Time, options BECastVerifyOptions) (beCastRecoveryPlan, error) {
	scanner := scan.scanner
	status := scanner.finalStatus
	contentDigest := scanner.finalContentHash
	chunkCount := scanner.chunkCount
	castBytes := scanner.castBytes
	ciphertextBytes := scanner.ciphertextBytes
	prefixBytes := uint64(scan.validEnd)
	lastUnitHash := scanner.previousUnitHash
	var chunkUnit []byte

	if !scanner.finalChunkSeen {
		recoveryResult, err := validatedBECastRecoveryResult(checkpoint, recoveredAt)
		if err != nil {
			return beCastRecoveryPlan{}, err
		}
		if chunkCount >= effectiveMaximumBECastChunks(options.MaximumChunks) {
			return beCastRecoveryPlan{}, errors.System.Newf("recovered BECast container would exceed %d chunks", effectiveMaximumBECastChunks(options.MaximumChunks))
		}
		resultLine, err := encodeCastRecoveryResultLine(recoveryResult)
		if err != nil {
			return beCastRecoveryPlan{}, err
		}
		digest, err := resumeCastSha256(scan.latestCheckpoint)
		if err != nil {
			return beCastRecoveryPlan{}, err
		}
		_, _ = digest.Write(resultLine)
		var castDigest CastDigest
		copy(castDigest[:], digest.Sum(nil))
		signature, err := identity.NewSessionRecordingCastSignature(scanner.header.RecordingId.String(), castDigest.String())
		if err != nil {
			return beCastRecoveryPlan{}, err
		}
		signaturePayload, err := json.Marshal(signature)
		if err != nil {
			return beCastRecoveryPlan{}, errors.System.Newf("cannot encode recovered BECast Cast signature: %w", err)
		}
		suffix := append(append(resultLine, []byte(castSignatureCommentPrefix)...), signaturePayload...)
		suffix = append(suffix, '\n')
		if len(suffix) == 0 || len(suffix) > MaximumBECastChunkPlaintext || len(suffix) > math.MaxUint32 {
			return beCastRecoveryPlan{}, errors.System.Newf("recovered BECast final plaintext exceeds %d bytes", MaximumBECastChunkPlaintext)
		}
		if uint64(len(suffix)) > uint64(effectiveMaximumCastBytes(options.MaximumCastBytes))-castBytes {
			return beCastRecoveryPlan{}, errors.System.Newf("recovered BECast plaintext exceeds %d bytes", effectiveMaximumCastBytes(options.MaximumCastBytes))
		}
		ciphertext, err := encodeBECastRecoveryCiphertext(recipient, suffix)
		if err != nil {
			return beCastRecoveryPlan{}, err
		}
		nextCastBytes, err := checkedBECastCount("Cast", castBytes, uint64(len(suffix)))
		if err != nil {
			return beCastRecoveryPlan{}, err
		}
		nextCiphertextBytes, err := checkedBECastCount("ciphertext", ciphertextBytes, uint64(len(ciphertext)))
		if err != nil {
			return beCastRecoveryPlan{}, err
		}
		status, err = castBECastStatus(CastStatusIncomplete)
		if err != nil {
			return beCastRecoveryPlan{}, err
		}
		contentDigest = audit.SessionRecordingHash(castDigest)
		chunk, err := identity.NewSessionRecordingBECastChunk(audit.SessionRecordingBECastChunk{
			FormatVersion:    castBECastFormatVersion,
			FinalStatus:      status,
			RecordingId:      scanner.header.RecordingId,
			Sequence:         chunkCount + 1,
			PreviousUnitHash: lastUnitHash,
			PlaintextOffset:  castBytes,
			PlaintextLength:  uint32(len(suffix)),
			CiphertextLength: uint32(len(ciphertext)),
			CiphertextHash:   hashBECastCiphertext(ciphertext),
			ContentHashState: contentDigest,
		})
		if err != nil {
			return beCastRecoveryPlan{}, err
		}
		chunkUnit, err = encodeBECastChunk(chunk, ciphertext)
		if err != nil {
			return beCastRecoveryPlan{}, err
		}
		chunkCount++
		castBytes = nextCastBytes
		ciphertextBytes = nextCiphertextBytes
		prefixBytes, err = checkedBECastCount("prefix", prefixBytes, uint64(len(chunkUnit)))
		if err != nil {
			return beCastRecoveryPlan{}, err
		}
		lastUnitHash = hashBECastUnit(chunkUnit)
		_, _ = scanner.ciphertextStreamHash.Write(ciphertext)
	}

	if _, err := castStatusFromBECast(status); err != nil {
		return beCastRecoveryPlan{}, err
	}
	var streamHash audit.SessionRecordingHash
	copy(streamHash[:], scanner.ciphertextStreamHash.Sum(nil))
	seal, err := identity.NewSessionRecordingBECastSeal(audit.SessionRecordingBECastSeal{
		FormatVersion:        castBECastFormatVersion,
		RecordingId:          scanner.header.RecordingId,
		Status:               status,
		ChunkCount:           chunkCount,
		CastBytes:            castBytes,
		CiphertextBytes:      ciphertextBytes,
		PrefixBytes:          prefixBytes,
		HeaderUnitHash:       scanner.headerUnitHash,
		LastChunkUnitHash:    lastUnitHash,
		CastContentDigest:    contentDigest,
		CiphertextStreamHash: streamHash,
	})
	if err != nil {
		return beCastRecoveryPlan{}, err
	}
	sealUnit, err := encodeBECastSeal(seal)
	if err != nil {
		return beCastRecoveryPlan{}, err
	}
	additional := int64(len(chunkUnit)) + int64(len(sealUnit))
	if scan.validEnd < 0 || additional < 0 || scan.validEnd > math.MaxInt64-additional {
		return beCastRecoveryPlan{}, errors.System.Newf("recovered BECast container size overflows int64")
	}
	finalSize := scan.validEnd + additional
	if finalSize > options.MaximumContainerBytes {
		return beCastRecoveryPlan{}, errors.System.Newf("recovered BECast container would exceed %d bytes", options.MaximumContainerBytes)
	}
	return beCastRecoveryPlan{chunk: chunkUnit, seal: sealUnit}, nil
}

func encodeBECastRecoveryCiphertext(recipient *crypto.AgeSshRecipient, plaintext []byte) ([]byte, error) {
	encoder, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderCRC(true),
		zstd.WithEncoderConcurrency(1),
		zstd.WithWindowSize(castZstdWindowSize),
		zstd.WithSingleSegment(true),
	)
	if err != nil {
		return nil, errors.System.Newf("cannot create BECast recovery Zstandard encoder: %w", err)
	}
	frame := encoder.EncodeAll(plaintext, nil)
	encoder.Close()
	if len(frame) == 0 || len(frame) > MaximumBECastCiphertext || len(frame) > math.MaxUint32 {
		return nil, errors.System.Newf("BECast recovery compressed frame exceeds %d bytes", MaximumBECastCiphertext)
	}
	var ciphertext bytes.Buffer
	encrypted, err := recipient.Encrypt(&ciphertext)
	if err != nil {
		return nil, errors.System.Newf("cannot initialize BECast recovery encryption: %w", err)
	}
	written, writeErr := encrypted.Write(frame)
	closeErr := encrypted.Close()
	if writeErr != nil {
		return nil, errors.System.Newf("cannot encrypt BECast recovery chunk: %w", writeErr)
	}
	if written != len(frame) {
		return nil, errors.System.Newf("cannot encrypt BECast recovery chunk: %w", io.ErrShortWrite)
	}
	if closeErr != nil {
		return nil, errors.System.Newf("cannot finish BECast recovery encryption: %w", closeErr)
	}
	if ciphertext.Len() == 0 || ciphertext.Len() > MaximumBECastCiphertext || ciphertext.Len() > math.MaxUint32 {
		return nil, errors.System.Newf("BECast recovery ciphertext exceeds %d bytes", MaximumBECastCiphertext)
	}
	return ciphertext.Bytes(), nil
}

func writeBECastRecoveryPlan(file RecoveryFile, plan beCastRecoveryPlan) error {
	if len(plan.chunk) > 0 {
		if err := writeBECastBytes(file, plan.chunk); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return errors.System.Newf("cannot synchronize recovered BECast chunk: %w", err)
		}
	}
	if err := writeBECastBytes(file, plan.seal); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return errors.System.Newf("cannot synchronize recovered BECast seal: %w", err)
	}
	return nil
}
