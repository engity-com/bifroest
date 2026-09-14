package recording

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"

	"github.com/engity-com/bifroest/pkg/audit"
)

type CastZstdWriter struct {
	cast     *CastWriter
	sink     *castZstdSink
	identity *audit.Identity
	metadata CastMetadata
	sealed   bool
}

type castZstdSink struct {
	output           io.Writer
	encoder          *zstd.Encoder
	identity         *audit.Identity
	recordingId      uuid.UUID
	chunkSize        int
	buffer           bytes.Buffer
	streamHash       hash.Hash
	prefixBytes      uint64
	castBytes        uint64
	zstdBytes        uint64
	chunkCount       uint64
	headerUnitHash   audit.SessionRecordingHash
	previousUnitHash audit.SessionRecordingHash
	pendingGroup     bool
	initialLines     int
	poisoned         error
}

func NewCastZstdWriter(output io.Writer, identity *audit.Identity, header CastHeader, metadata CastMetadata, chunkSize int) (*CastZstdWriter, error) {
	if output == nil {
		return nil, fmt.Errorf("nil Cast Zstandard output")
	}
	if identity == nil || identity.PublicKey() == nil {
		return nil, fmt.Errorf("nil Cast Zstandard signing identity")
	}
	if err := validateCastHeader(header); err != nil {
		return nil, err
	}
	if err := validateCastMetadata(header, metadata); err != nil {
		return nil, err
	}
	if metadata.ProducerId != identity.ProducerId() {
		return nil, fmt.Errorf("recording producer ID does not match signing identity")
	}
	if chunkSize == 0 {
		chunkSize = DefaultCastZstdChunkSize
	}
	if chunkSize < 1 || chunkSize > MaximumCastZstdChunkSize {
		return nil, fmt.Errorf("cast Zstandard chunk size must be between 1 and %d", MaximumCastZstdChunkSize)
	}
	encoder, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderCRC(true),
		zstd.WithEncoderConcurrency(1),
		zstd.WithWindowSize(castZstdWindowSize),
		zstd.WithSingleSegment(true),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot create Cast Zstandard encoder: %w", err)
	}
	headerValue, err := identity.NewSessionRecordingZstdHeader(castZstdFormatVersion, castVersion, castZstdCodec, uuid.UUID(metadata.RecordingId))
	if err != nil {
		encoder.Close()
		return nil, err
	}
	headerFrame, err := encodeCastZstdHeader(headerValue)
	if err != nil {
		encoder.Close()
		return nil, err
	}
	if err := writeCastZstdBytes(output, headerFrame); err != nil {
		encoder.Close()
		return nil, err
	}
	streamHasher := sha256.New()
	_, _ = streamHasher.Write([]byte(castZstdStreamHashDomain))
	headerHash := hashSessionRecording(castZstdUnitHashDomain, headerFrame)
	sink := &castZstdSink{
		output:           output,
		encoder:          encoder,
		identity:         identity,
		recordingId:      uuid.UUID(metadata.RecordingId),
		chunkSize:        chunkSize,
		streamHash:       streamHasher,
		prefixBytes:      uint64(len(headerFrame)),
		headerUnitHash:   headerHash,
		previousUnitHash: headerHash,
		initialLines:     2,
	}
	cast, err := NewCastWriter(sink, identity, header, metadata)
	if err != nil {
		encoder.Close()
		return nil, err
	}
	if err := sink.flush(false); err != nil {
		encoder.Close()
		return nil, err
	}
	return &CastZstdWriter{cast: cast, sink: sink, identity: identity, metadata: metadata}, nil
}

func (this *CastZstdWriter) WriteOutput(elapsed time.Duration, stream OutputStream, data []byte) error {
	if this == nil || this.cast == nil {
		return fmt.Errorf("nil Cast Zstandard writer")
	}
	return this.cast.WriteOutput(elapsed, stream, data)
}

func (this *CastZstdWriter) WriteResize(elapsed time.Duration, columns, rows uint32) error {
	if this == nil || this.cast == nil {
		return fmt.Errorf("nil Cast Zstandard writer")
	}
	return this.cast.WriteResize(elapsed, columns, rows)
}

func (this *CastZstdWriter) WriteMarker(elapsed time.Duration, label string) error {
	if this == nil || this.cast == nil {
		return fmt.Errorf("nil Cast Zstandard writer")
	}
	return this.cast.WriteMarker(elapsed, label)
}

func (this *CastZstdWriter) Flush() error {
	if this == nil || this.sink == nil {
		return fmt.Errorf("nil Cast Zstandard writer")
	}
	if this.sealed {
		return fmt.Errorf("cast Zstandard writer is already sealed")
	}
	return this.sink.flush(false)
}

// Checkpoint flushes complete Cast lines and returns a signed active head. The
// caller must synchronize the container before atomically persisting the head.
func (this *CastZstdWriter) Checkpoint() (audit.SessionRecordingZstdHead, error) {
	if this == nil || this.sink == nil {
		return audit.SessionRecordingZstdHead{}, fmt.Errorf("nil Cast Zstandard writer")
	}
	if this.sealed {
		return audit.SessionRecordingZstdHead{}, fmt.Errorf("cast Zstandard writer is already sealed")
	}
	if err := this.sink.flush(false); err != nil {
		return audit.SessionRecordingZstdHead{}, err
	}
	return this.identity.NewSessionRecordingZstdHead(audit.SessionRecordingZstdHead{
		FormatVersion: castZstdFormatVersion,
		RecordingId:   this.sink.recordingId,
		ChunkCount:    this.sink.chunkCount,
		PrefixBytes:   this.sink.prefixBytes,
		LastUnitHash:  this.sink.previousUnitHash,
	})
}

func (this *CastZstdWriter) replaceOutput(output io.Writer) error {
	if this == nil || this.sink == nil || output == nil {
		return fmt.Errorf("invalid Cast Zstandard replacement output")
	}
	if this.sealed || this.sink.poisoned != nil || this.sink.buffer.Len() != 0 || this.sink.pendingGroup {
		return fmt.Errorf("cast Zstandard writer cannot replace its output in the current state")
	}
	this.sink.output = output
	return nil
}

func (this *CastZstdWriter) Seal(elapsed time.Duration, result CastResult, exitStatus *uint32) (CastZstdSummary, error) {
	if this == nil || this.cast == nil || this.sink == nil {
		return CastZstdSummary{}, fmt.Errorf("nil Cast Zstandard writer")
	}
	if this.sealed {
		return CastZstdSummary{}, fmt.Errorf("cast Zstandard writer is already sealed")
	}
	digest, err := this.cast.Seal(elapsed, result, exitStatus)
	if err != nil {
		return CastZstdSummary{}, err
	}
	if err := this.sink.flush(true); err != nil {
		return CastZstdSummary{}, err
	}
	status, err := castZstdStatus(result.Status)
	if err != nil {
		return CastZstdSummary{}, err
	}
	var castDigest audit.SessionRecordingHash
	copy(castDigest[:], digest[:])
	var streamHash audit.SessionRecordingHash
	copy(streamHash[:], this.sink.streamHash.Sum(nil))
	sealValue, err := this.identity.NewSessionRecordingZstdSeal(audit.SessionRecordingZstdSeal{
		FormatVersion:     castZstdFormatVersion,
		RecordingId:       uuid.UUID(this.metadata.RecordingId),
		Status:            status,
		ChunkCount:        this.sink.chunkCount,
		CastBytes:         this.sink.castBytes,
		ZstdBytes:         this.sink.zstdBytes,
		PrefixBytes:       this.sink.prefixBytes,
		HeaderUnitHash:    this.sink.headerUnitHash,
		LastChunkUnitHash: this.sink.previousUnitHash,
		CastContentDigest: castDigest,
		CastStreamHash:    streamHash,
	})
	if err != nil {
		return CastZstdSummary{}, err
	}
	sealFrame, err := encodeCastZstdSeal(sealValue)
	if err != nil {
		return CastZstdSummary{}, err
	}
	if err := writeCastZstdBytes(this.sink.output, sealFrame); err != nil {
		return CastZstdSummary{}, this.sink.poison(err)
	}
	this.sealed = true
	this.sink.encoder.Close()
	return CastZstdSummary{
		RecordingId: this.metadata.RecordingId,
		ProducerId:  this.metadata.ProducerId,
		Status:      result.Status,
		ChunkCount:  this.sink.chunkCount,
		CastBytes:   this.sink.castBytes,
		ZstdBytes:   this.sink.zstdBytes,
		Digest:      digest,
		StreamHash:  streamHash,
	}, nil
}

func (this *castZstdSink) Write(value []byte) (int, error) {
	if this.poisoned != nil {
		return 0, this.poisoned
	}
	if len(value) == 0 || value[len(value)-1] != '\n' || len(value) > MaximumCastLineBytes+1 {
		return 0, this.poison(fmt.Errorf("cast Zstandard sink received an illegal Cast line"))
	}
	isEventMetadata := bytes.HasPrefix(value, []byte(castEventCommentPrefix))
	isResult := bytes.HasPrefix(value, []byte(castResultCommentPrefix))
	continuation := this.pendingGroup
	if !continuation && this.buffer.Len() > 0 && this.buffer.Len()+len(value) > this.chunkSize {
		if err := this.flush(false); err != nil {
			return 0, err
		}
	}
	if _, err := this.buffer.Write(value); err != nil {
		return 0, this.poison(err)
	}
	_, _ = this.streamHash.Write(value)
	if this.initialLines > 0 {
		this.initialLines--
		this.pendingGroup = this.initialLines > 0
	} else if continuation {
		this.pendingGroup = false
	} else {
		this.pendingGroup = isEventMetadata || isResult
	}
	if !this.pendingGroup && this.buffer.Len() >= this.chunkSize {
		if err := this.flush(false); err != nil {
			return len(value), err
		}
	}
	return len(value), nil
}

func (this *castZstdSink) flush(final bool) error {
	if this.poisoned != nil {
		return this.poisoned
	}
	if this.pendingGroup && !final {
		return nil
	}
	if this.pendingGroup {
		return this.poison(fmt.Errorf("cast Zstandard stream ends inside an atomic line group"))
	}
	if this.buffer.Len() == 0 {
		return nil
	}
	if this.buffer.Len() > MaximumCastZstdChunkSize || this.buffer.Len() > math.MaxUint32 {
		return this.poison(fmt.Errorf("cast Zstandard plaintext chunk exceeds %d bytes", MaximumCastZstdChunkSize))
	}
	plaintext := this.buffer.Bytes()
	frame := this.encoder.EncodeAll(plaintext, nil)
	if len(frame) == 0 || len(frame) > MaximumCastZstdFrameSize || len(frame) > math.MaxUint32 {
		return this.poison(fmt.Errorf("cast Zstandard frame exceeds %d bytes", MaximumCastZstdFrameSize))
	}
	frameHash := hashSessionRecording(castZstdFrameHashDomain, frame)
	chunkValue, err := this.identity.NewSessionRecordingZstdChunk(audit.SessionRecordingZstdChunk{
		FormatVersion:    castZstdFormatVersion,
		RecordingId:      this.recordingId,
		Sequence:         this.chunkCount + 1,
		PreviousUnitHash: this.previousUnitHash,
		PlaintextOffset:  this.castBytes,
		PlaintextLength:  uint32(len(plaintext)),
		FrameLength:      uint32(len(frame)),
		FrameHash:        frameHash,
	})
	if err != nil {
		return this.poison(err)
	}
	descriptor, err := encodeCastZstdChunk(chunkValue)
	if err != nil {
		return this.poison(err)
	}
	if err := writeCastZstdBytes(this.output, descriptor); err != nil {
		return this.poison(err)
	}
	if err := writeCastZstdBytes(this.output, frame); err != nil {
		return this.poison(err)
	}
	this.previousUnitHash = hashSessionRecording(castZstdUnitHashDomain, descriptor, frame)
	this.prefixBytes += uint64(len(descriptor) + len(frame))
	this.castBytes += uint64(len(plaintext))
	this.zstdBytes += uint64(len(frame))
	this.chunkCount++
	this.buffer.Reset()
	return nil
}

func (this *castZstdSink) poison(err error) error {
	if this.poisoned == nil {
		this.poisoned = err
	}
	return err
}

func writeCastZstdBytes(output io.Writer, value []byte) error {
	written, err := output.Write(value)
	if err != nil {
		return fmt.Errorf("cannot write Cast Zstandard data: %w", err)
	}
	if written != len(value) {
		return fmt.Errorf("cannot write Cast Zstandard data: %w", io.ErrShortWrite)
	}
	return nil
}
