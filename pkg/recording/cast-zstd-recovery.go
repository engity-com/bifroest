package recording

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"hash"
	"io"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/errors"
)

type CastZstdRecoveryResult struct {
	Verification  *CastZstdVerification
	AlreadySealed bool
	Truncated     bool
	Finalized     bool
}

// RecoverCastZstd repairs an active container and seals it. The caller must
// hold an exclusive lock for file throughout the call.
func RecoverCastZstd(file RecoveryFile, identity *audit.Identity, checkpoint audit.SessionRecordingZstdHead, recoveredAt time.Time, options CastZstdVerifyOptions) (*CastZstdRecoveryResult, error) {
	if file == nil {
		return nil, errors.System.Newf("nil Cast Zstandard recovery file")
	}
	if identity == nil || identity.PublicKey() == nil {
		return nil, errors.System.Newf("nil Cast Zstandard recovery identity")
	}
	if options.ExpectedProducerId != (audit.ProducerId{}) && options.ExpectedProducerId != identity.ProducerId() {
		return nil, errors.Config.Newf("cast Zstandard recovery identity does not match the expected producer")
	}
	options.ExpectedProducerId = identity.ProducerId()
	options.AllowUntrusted = false
	size, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, errors.System.Newf("cannot determine Cast Zstandard recovery size: %w", err)
	}

	scan, digest, metadata, err := scanActiveCastZstd(file, size, options, checkpoint)
	if err != nil {
		return nil, err
	}
	defer scan.close()
	if scan.header.ProducerId != identity.ProducerId() {
		return nil, errors.System.Newf("cast Zstandard recovery identity does not match its container")
	}
	if scan.seal != nil {
		verification, err := VerifyCastZstd(file, size, options)
		if err != nil {
			return nil, err
		}
		if err := file.Sync(); err != nil {
			return nil, errors.System.Newf("cannot synchronize sealed Cast Zstandard container: %w", err)
		}
		return &CastZstdRecoveryResult{Verification: verification, AlreadySealed: true}, nil
	}

	castVerification, complete := verifyExistingRecoveryCast(file, size, options, checkpoint)
	var suffix []byte
	if !complete {
		result := CastResult{
			Status:  CastStatusIncomplete,
			EndedAt: recoveredAt.UTC(),
			Reason:  startupRecoveryReason,
		}
		if err := validateCastResult(metadata, result, false); err != nil {
			return nil, errors.System.Newf("cannot create incomplete Cast recovery result: %w", err)
		}
		resultLine, err := encodeCastRecoveryResultLine(result)
		if err != nil {
			return nil, err
		}
		_, _ = digest.Write(resultLine)
		var contentDigest CastDigest
		copy(contentDigest[:], digest.Sum(nil))
		signature, err := identity.NewSessionRecordingCastSignature(metadata.RecordingId.String(), contentDigest.String())
		if err != nil {
			return nil, err
		}
		signaturePayload, err := json.Marshal(signature)
		if err != nil {
			return nil, errors.System.Newf("cannot encode recovered Cast signature: %w", err)
		}
		signatureLine := append(append([]byte(castSignatureCommentPrefix), signaturePayload...), '\n')
		suffix = append(resultLine, signatureLine...)
		castVerification, err = verifyRecoveredCast(file, size, suffix, options, checkpoint)
		if err != nil {
			return nil, errors.System.Newf("active Cast is not safely recoverable: %w", err)
		}
	}
	if castVerification.Metadata.RecordingId != Id(scan.header.RecordingId) || castVerification.Metadata.ProducerId != scan.header.ProducerId {
		return nil, errors.System.Newf("active Cast identity does not match its Zstandard container")
	}
	plan, err := planRecoveredCastZstdSeal(identity, scan, castVerification, suffix, options)
	if err != nil {
		return nil, err
	}
	currentSize, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, errors.System.Newf("cannot recheck Cast Zstandard recovery size: %w", err)
	}
	if currentSize != size {
		return nil, errors.System.Newf("cast Zstandard recovery file changed while being verified")
	}

	truncated := scan.incompleteTail
	if int64(scan.validEnd) != size {
		if !truncated {
			return nil, errors.System.Newf("refusing to truncate a complete Cast Zstandard unit")
		}
		if err := file.Truncate(scan.validEnd); err != nil {
			return nil, errors.System.Newf("cannot truncate incomplete Cast Zstandard tail: %w", err)
		}
		if err := file.Sync(); err != nil {
			return nil, errors.System.Newf("cannot synchronize Cast Zstandard truncation: %w", err)
		}
	}
	if _, err := file.Seek(scan.validEnd, io.SeekStart); err != nil {
		return nil, errors.System.Newf("cannot seek to Cast Zstandard recovery position: %w", err)
	}
	if err := writeCastZstdRecoveryPlan(file, plan); err != nil {
		return nil, err
	}
	finalSize, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, errors.System.Newf("cannot determine recovered Cast Zstandard size: %w", err)
	}
	verification, err := VerifyCastZstd(file, finalSize, options)
	if err != nil {
		return nil, errors.System.Newf("recovered Cast Zstandard container failed final verification: %w", err)
	}
	return &CastZstdRecoveryResult{
		Verification: verification,
		Truncated:    truncated,
		Finalized:    true,
	}, nil
}

func scanActiveCastZstd(file io.ReaderAt, size int64, options CastZstdVerifyOptions, checkpoint audit.SessionRecordingZstdHead) (*castZstdStream, hash.Hash, CastMetadata, error) {
	stream, err := newCastZstdStreamForRecovery(file, size, options, &checkpoint, true)
	if err != nil {
		return nil, nil, CastMetadata{}, err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(castContentHashDomain))
	capture := &castRecoveryPrefixCapture{}
	if _, err := io.Copy(io.MultiWriter(digest, capture), stream); err != nil {
		stream.close()
		return nil, nil, CastMetadata{}, errors.System.Newf("cannot scan active Cast Zstandard container: %w", err)
	}
	metadata, err := capture.metadata()
	if err != nil {
		stream.close()
		return nil, nil, CastMetadata{}, err
	}
	return stream, digest, metadata, nil
}

func verifyExistingRecoveryCast(file io.ReaderAt, size int64, options CastZstdVerifyOptions, checkpoint audit.SessionRecordingZstdHead) (*CastVerification, bool) {
	stream, err := newCastZstdStreamForRecovery(file, size, options, &checkpoint, true)
	if err != nil {
		return nil, false
	}
	defer stream.close()
	verification, err := VerifyCast(stream, CastVerifyOptions{Context: options.Context, MaximumBytes: effectiveMaximumCastBytes(options.MaximumCastBytes), ExpectedProducerId: options.ExpectedProducerId})
	return verification, err == nil
}

func verifyRecoveredCast(file io.ReaderAt, size int64, suffix []byte, options CastZstdVerifyOptions, checkpoint audit.SessionRecordingZstdHead) (*CastVerification, error) {
	stream, err := newCastZstdStreamForRecovery(file, size, options, &checkpoint, true)
	if err != nil {
		return nil, err
	}
	defer stream.close()
	return VerifyCast(io.MultiReader(stream, bytes.NewReader(suffix)), CastVerifyOptions{
		Context:            options.Context,
		MaximumBytes:       effectiveMaximumCastBytes(options.MaximumCastBytes),
		ExpectedProducerId: options.ExpectedProducerId,
	})
}

type castZstdRecoveryPlan struct {
	chunk []byte
	seal  []byte
}

func planRecoveredCastZstdSeal(identity *audit.Identity, scan *castZstdStream, cast *CastVerification, suffix []byte, options CastZstdVerifyOptions) (castZstdRecoveryPlan, error) {
	if len(suffix) > 0 && scan.chunkCount >= effectiveMaximumCastZstdChunks(options.MaximumChunks) {
		return castZstdRecoveryPlan{}, errors.System.Newf("recovered Cast Zstandard container would exceed %d chunks", effectiveMaximumCastZstdChunks(options.MaximumChunks))
	}
	encoder, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderCRC(true),
		zstd.WithEncoderConcurrency(1),
		zstd.WithWindowSize(castZstdWindowSize),
		zstd.WithSingleSegment(true),
	)
	if err != nil {
		return castZstdRecoveryPlan{}, errors.System.Newf("cannot create recovery Zstandard encoder: %w", err)
	}
	defer encoder.Close()
	limits, err := newRecordingWriterLimits(options.MaximumContainerBytes, options.MaximumCastBytes, options.MaximumChunks, DefaultMaximumCastZstdBytes, DefaultMaximumCastZstdChunks)
	if err != nil {
		return castZstdRecoveryPlan{}, err
	}
	var chunk bytes.Buffer
	sink := &castZstdSink{
		output:           &chunk,
		encoder:          encoder,
		identity:         identity,
		recordingId:      scan.header.RecordingId,
		chunkSize:        DefaultCastZstdChunkSize,
		limits:           limits,
		streamHash:       scan.streamHash,
		prefixBytes:      uint64(scan.validEnd),
		castBytes:        scan.castBytes,
		zstdBytes:        scan.zstdBytes,
		chunkCount:       scan.chunkCount,
		headerUnitHash:   scan.headerUnitHash,
		previousUnitHash: scan.previousUnitHash,
	}
	if len(suffix) > 0 {
		separator := bytes.IndexByte(suffix, '\n') + 1
		if separator <= 0 || separator >= len(suffix) {
			return castZstdRecoveryPlan{}, errors.System.Newf("illegal recovered Cast suffix")
		}
		if _, err := sink.Write(suffix[:separator]); err != nil {
			return castZstdRecoveryPlan{}, err
		}
		if _, err := sink.Write(suffix[separator:]); err != nil {
			return castZstdRecoveryPlan{}, err
		}
		if err := sink.flush(true); err != nil {
			return castZstdRecoveryPlan{}, err
		}
	}
	status, err := castZstdStatus(cast.Result.Status)
	if err != nil {
		return castZstdRecoveryPlan{}, err
	}
	var digest audit.SessionRecordingHash
	copy(digest[:], cast.Digest[:])
	var streamHash audit.SessionRecordingHash
	copy(streamHash[:], sink.streamHash.Sum(nil))
	seal, err := identity.NewSessionRecordingZstdSeal(audit.SessionRecordingZstdSeal{
		FormatVersion:     castZstdFormatVersion,
		RecordingId:       scan.header.RecordingId,
		Status:            status,
		ChunkCount:        sink.chunkCount,
		CastBytes:         sink.castBytes,
		ZstdBytes:         sink.zstdBytes,
		PrefixBytes:       sink.prefixBytes,
		HeaderUnitHash:    sink.headerUnitHash,
		LastChunkUnitHash: sink.previousUnitHash,
		CastContentDigest: digest,
		CastStreamHash:    streamHash,
	})
	if err != nil {
		return castZstdRecoveryPlan{}, err
	}
	sealFrame, err := encodeCastZstdSeal(seal)
	if err != nil {
		return castZstdRecoveryPlan{}, err
	}
	appendedBytes := uint64(chunk.Len()) + uint64(len(sealFrame))
	if scan.validEnd < 0 || recordingCountExceedsLimit(uint64(scan.validEnd), appendedBytes, 0, limits.maximumContainerBytes) {
		return castZstdRecoveryPlan{}, errors.System.Newf("recovered Cast Zstandard container would exceed %d bytes", limits.maximumContainerBytes)
	}
	return castZstdRecoveryPlan{chunk: chunk.Bytes(), seal: sealFrame}, nil
}

func writeCastZstdRecoveryPlan(file RecoveryFile, plan castZstdRecoveryPlan) error {
	if len(plan.chunk) > 0 {
		if err := writeCastZstdBytes(file, plan.chunk); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return errors.System.Newf("cannot synchronize recovered Cast Zstandard chunk: %w", err)
		}
	}
	if err := writeCastZstdBytes(file, plan.seal); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return errors.System.Newf("cannot synchronize recovered Cast Zstandard seal: %w", err)
	}
	return nil
}

func encodeCastRecoveryResultLine(result CastResult) ([]byte, error) {
	payload, err := json.Marshal(castResultWire{Schema: castResultSchema, CastResult: result})
	if err != nil {
		return nil, errors.System.Newf("cannot encode recovered Cast result: %w", err)
	}
	return append(append([]byte(castResultCommentPrefix), payload...), '\n'), nil
}

type castRecoveryPrefixCapture struct {
	content []byte
	lines   int
}

func (this *castRecoveryPrefixCapture) Write(value []byte) (int, error) {
	for _, current := range value {
		if this.lines >= 2 {
			break
		}
		this.content = append(this.content, current)
		if len(this.content) > 2*(MaximumCastLineBytes+1) {
			return 0, errors.System.Newf("cast recovery header exceeds its line limits")
		}
		if current == '\n' {
			this.lines++
		}
	}
	return len(value), nil
}

func (this *castRecoveryPrefixCapture) metadata() (CastMetadata, error) {
	lines := bytes.Split(this.content, []byte{'\n'})
	if this.lines != 2 || len(lines) < 3 {
		return CastMetadata{}, errors.System.Newf("active Cast has no complete header and metadata")
	}
	var header CastHeader
	if err := decodeCastHeader(lines[0], &header); err != nil {
		return CastMetadata{}, errors.System.Newf("illegal active Cast header: %w", err)
	}
	payload, ok := bytes.CutPrefix(lines[1], []byte(castMetadataCommentPrefix))
	if !ok {
		return CastMetadata{}, errors.System.Newf("active Cast metadata is not the second line")
	}
	var metadata castMetadataWire
	if err := decodeCanonicalCastJSON(payload, &metadata); err != nil {
		return CastMetadata{}, errors.System.Newf("illegal active Cast metadata: %w", err)
	}
	if metadata.Schema != castMetadataSchema {
		return CastMetadata{}, errors.System.Newf("unsupported active Cast metadata schema %q", metadata.Schema)
	}
	if err := validateCastMetadata(header, metadata.CastMetadata); err != nil {
		return CastMetadata{}, err
	}
	return metadata.CastMetadata, nil
}
