package recording

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"io"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

const maximumBECastCheckpointPaddingBytes = len(castCheckpointPaddingCommentPrefix) + sha256.BlockSize

// castBECastOpenCastState marks an open, valid Cast at a complete atomic line
// boundary before any result or final signature has been emitted.
const castBECastOpenCastState = 1

type BECastWriter struct {
	cast                 *CastWriter
	sink                 *beCastSink
	identity             *audit.Identity
	metadata             CastMetadata
	recipientFingerprint string
	sealed               bool
}

type beCastSink struct {
	output           io.Writer
	encoder          *zstd.Encoder
	recipient        *crypto.AgeSshRecipient
	identity         *audit.Identity
	recordingId      uuid.UUID
	chunkSize        int
	limits           recordingWriterLimits
	buffer           bytes.Buffer
	ciphertextStream hash.Hash
	prefixBytes      uint64
	castBytes        uint64
	ciphertextBytes  uint64
	chunkCount       uint64
	headerUnitHash   audit.SessionRecordingHash
	previousUnitHash audit.SessionRecordingHash
	lastCheckpoint   castSha256Checkpoint
	pendingGroup     bool
	initialLines     int
	flushing         bool
	sealing          bool
	poisoned         error
	cast             *CastWriter
}

func NewBECastWriter(output io.Writer, identity *audit.Identity, recipient *crypto.AgeSshRecipient, header CastHeader, metadata CastMetadata, chunkSize int) (*BECastWriter, error) {
	return newBECastWriter(output, identity, recipient, header, metadata, chunkSize, BECastVerifyOptions{})
}

func newBECastWriter(output io.Writer, identity *audit.Identity, recipient *crypto.AgeSshRecipient, header CastHeader, metadata CastMetadata, chunkSize int, options BECastVerifyOptions) (*BECastWriter, error) {
	if output == nil {
		return nil, errors.System.Newf("nil BECast output")
	}
	if identity == nil || identity.PublicKey() == nil {
		return nil, errors.System.Newf("nil BECast signing identity")
	}
	if recipient == nil || recipient.Fingerprint() == "" {
		return nil, errors.System.Newf("nil BECast age SSH recipient")
	}
	if recipient.Fingerprint() == identity.Fingerprint() {
		return nil, errors.Config.Newf("BECast encryption recipient must differ from the signing identity")
	}
	if err := validateCastHeader(header); err != nil {
		return nil, err
	}
	if err := validateCastMetadata(header, metadata); err != nil {
		return nil, err
	}
	if metadata.ProducerId != identity.ProducerId() {
		return nil, errors.Config.Newf("recording producer ID does not match signing identity")
	}
	if chunkSize == 0 {
		chunkSize = DefaultBECastChunkPlaintextTarget
	}
	if chunkSize < 1 || chunkSize > MaximumBECastChunkPlaintext {
		return nil, errors.Config.Newf("BECast plaintext chunk target must be between 1 and %d", MaximumBECastChunkPlaintext)
	}
	limits, err := newRecordingWriterLimits(options.MaximumContainerBytes, options.MaximumCastBytes, options.MaximumChunks, DefaultMaximumBECastBytes, DefaultMaximumBECastChunks)
	if err != nil {
		return nil, err
	}

	encoder, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderCRC(true),
		zstd.WithEncoderConcurrency(1),
		zstd.WithWindowSize(castZstdWindowSize),
		zstd.WithSingleSegment(true),
	)
	if err != nil {
		return nil, errors.System.Newf("cannot create BECast Zstandard encoder: %w", err)
	}
	fail := func(err error) (*BECastWriter, error) {
		encoder.Close()
		return nil, err
	}

	headerValue, err := identity.NewSessionRecordingBECastHeader(castBECastFormatVersion, castVersion, castBECastCodec, castBECastEncryption, uuid.UUID(metadata.RecordingId), recipient.Fingerprint())
	if err != nil {
		return fail(err)
	}
	headerUnit, err := encodeBECastHeader(headerValue)
	if err != nil {
		return fail(err)
	}
	prefix := make([]byte, 0, len(castBECastFileMagic)+len(headerUnit))
	prefix = append(prefix, castBECastFileMagic...)
	prefix = append(prefix, headerUnit...)
	if recordingCountExceedsLimit(0, uint64(len(prefix)), castBECastSealUnitSize, limits.maximumContainerBytes) {
		return fail(errors.Config.Newf("maximum BECast container size cannot contain the header and seal"))
	}
	if err := writeBECastBytes(output, prefix); err != nil {
		return fail(err)
	}

	headerHash := hashBECastUnit(headerUnit)
	streamHasher := sha256.New()
	_, _ = streamHasher.Write([]byte(castBECastCiphertextStreamHashDomain))
	sink := &beCastSink{
		output:           output,
		encoder:          encoder,
		recipient:        recipient,
		identity:         identity,
		recordingId:      uuid.UUID(metadata.RecordingId),
		chunkSize:        chunkSize,
		limits:           limits,
		ciphertextStream: streamHasher,
		prefixBytes:      uint64(len(prefix)),
		headerUnitHash:   headerHash,
		previousUnitHash: headerHash,
		initialLines:     2,
	}
	cast, err := newCastWriter(sink, identity, header, metadata, sink.beforeContentLine, sink.afterContentLine)
	if err != nil {
		return fail(err)
	}
	sink.cast = cast
	if err := sink.flush(false, nil, 0); err != nil {
		return fail(err)
	}
	return &BECastWriter{
		cast:                 cast,
		sink:                 sink,
		identity:             identity,
		metadata:             metadata,
		recipientFingerprint: recipient.Fingerprint(),
	}, nil
}

func (this *BECastWriter) WriteOutput(elapsed time.Duration, stream OutputStream, data []byte) error {
	if this == nil || this.cast == nil {
		return errors.System.Newf("nil BECast writer")
	}
	return this.cast.WriteOutput(elapsed, stream, data)
}

func (this *BECastWriter) WriteResize(elapsed time.Duration, columns, rows uint32) error {
	if this == nil || this.cast == nil {
		return errors.System.Newf("nil BECast writer")
	}
	return this.cast.WriteResize(elapsed, columns, rows)
}

func (this *BECastWriter) WriteMarker(elapsed time.Duration, label string) error {
	if this == nil || this.cast == nil {
		return errors.System.Newf("nil BECast writer")
	}
	return this.cast.WriteMarker(elapsed, label)
}

func (this *BECastWriter) Flush() error {
	if this == nil || this.sink == nil {
		return errors.System.Newf("nil BECast writer")
	}
	if this.sealed {
		return errors.System.Newf("BECast writer is already sealed")
	}
	return this.sink.flush(false, nil, 0)
}

// Checkpoint flushes complete Cast line groups and returns a signed active
// head. The caller must synchronize the container before persisting the head.
func (this *BECastWriter) Checkpoint() (audit.SessionRecordingBECastHead, error) {
	if this == nil || this.sink == nil {
		return audit.SessionRecordingBECastHead{}, errors.System.Newf("nil BECast writer")
	}
	if this.sealed {
		return audit.SessionRecordingBECastHead{}, errors.System.Newf("BECast writer is already sealed")
	}
	if err := this.sink.flush(false, nil, 0); err != nil {
		return audit.SessionRecordingBECastHead{}, err
	}
	checkpoint := this.sink.lastCheckpoint
	head, err := this.identity.NewSessionRecordingBECastHead(audit.SessionRecordingBECastHead{
		FormatVersion:        castBECastFormatVersion,
		CastState:            castBECastOpenCastState,
		RecordingId:          this.sink.recordingId,
		StartedAtUnixSeconds: this.metadata.StartedAt.Unix(),
		StartedAtNanoseconds: uint32(this.metadata.StartedAt.Nanosecond()),
		ChunkCount:           this.sink.chunkCount,
		PrefixBytes:          this.sink.prefixBytes,
		LastUnitHash:         this.sink.previousUnitHash,
		ContentHashState:     audit.SessionRecordingHash(checkpoint.State),
		ContentHashBytes:     checkpoint.Bytes,
	})
	if err != nil {
		return audit.SessionRecordingBECastHead{}, this.sink.poison(err)
	}
	return head, nil
}

func (this *BECastWriter) replaceOutput(output io.Writer) error {
	if this == nil || this.sink == nil || output == nil {
		return errors.System.Newf("invalid BECast replacement output")
	}
	if this.sealed || this.sink.poisoned != nil || this.sink.buffer.Len() != 0 || this.sink.pendingGroup {
		return errors.System.Newf("BECast writer cannot replace its output in the current state")
	}
	this.sink.output = output
	return nil
}

func (this *BECastWriter) repositoryFailure() error {
	if this == nil {
		return errors.System.Newf("nil BECast writer")
	}
	if this.cast != nil && this.cast.poisoned != nil {
		return this.cast.poisoned
	}
	if this.sink != nil {
		return this.sink.poisoned
	}
	return nil
}

func (this *BECastWriter) release() error {
	if this == nil || this.sink == nil || this.sink.encoder == nil || this.sealed {
		return nil
	}
	encoder := this.sink.encoder
	this.sink.encoder = nil
	if err := encoder.Close(); err != nil {
		return errors.System.Newf("cannot close BECast Zstandard encoder: %w", err)
	}
	return nil
}

func (this *BECastWriter) Seal(elapsed time.Duration, result CastResult, exitStatus *uint32) (BECastSummary, error) {
	if this == nil || this.cast == nil || this.sink == nil {
		return BECastSummary{}, errors.System.Newf("nil BECast writer")
	}
	if this.sink.poisoned != nil {
		this.sink.encoder.Close()
		return BECastSummary{}, this.sink.poisoned
	}
	if this.sealed {
		return BECastSummary{}, errors.System.Newf("BECast writer is already sealed")
	}
	if this.sink.buffer.Len() > MaximumBECastChunkPlaintext-maximumCastSealGroupBytes {
		if err := this.sink.flush(false, nil, 0); err != nil {
			this.sink.encoder.Close()
			return BECastSummary{}, err
		}
	}

	this.sink.sealing = true
	digest, err := this.cast.Seal(elapsed, result, exitStatus)
	this.sink.sealing = false
	if err != nil {
		if this.cast.poisoned != nil {
			_ = this.sink.poison(err)
			this.sink.encoder.Close()
		}
		return BECastSummary{}, err
	}
	status, err := castBECastStatus(result.Status)
	if err != nil {
		return BECastSummary{}, this.failSeal(err)
	}
	if err := this.sink.flush(true, &digest, status); err != nil {
		this.sink.encoder.Close()
		return BECastSummary{}, err
	}
	var castDigest audit.SessionRecordingHash
	copy(castDigest[:], digest[:])
	var streamHash audit.SessionRecordingHash
	copy(streamHash[:], this.sink.ciphertextStream.Sum(nil))
	sealValue, err := this.identity.NewSessionRecordingBECastSeal(audit.SessionRecordingBECastSeal{
		FormatVersion:        castBECastFormatVersion,
		RecordingId:          uuid.UUID(this.metadata.RecordingId),
		Status:               status,
		ChunkCount:           this.sink.chunkCount,
		CastBytes:            this.sink.castBytes,
		CiphertextBytes:      this.sink.ciphertextBytes,
		PrefixBytes:          this.sink.prefixBytes,
		HeaderUnitHash:       this.sink.headerUnitHash,
		LastChunkUnitHash:    this.sink.previousUnitHash,
		CastContentDigest:    castDigest,
		CiphertextStreamHash: streamHash,
	})
	if err != nil {
		return BECastSummary{}, this.failSeal(err)
	}
	sealUnit, err := encodeBECastSeal(sealValue)
	if err != nil {
		return BECastSummary{}, this.failSeal(err)
	}
	if recordingCountExceedsLimit(this.sink.prefixBytes, uint64(len(sealUnit)), 0, this.sink.limits.maximumContainerBytes) {
		return BECastSummary{}, this.failSeal(errors.System.Newf("BECast container exceeds maximum size"))
	}
	if err := writeBECastBytes(this.sink.output, sealUnit); err != nil {
		return BECastSummary{}, this.failSeal(err)
	}

	this.sealed = true
	this.sink.encoder.Close()
	return BECastSummary{
		RecordingId:          this.metadata.RecordingId,
		ProducerId:           this.metadata.ProducerId,
		RecipientFingerprint: this.recipientFingerprint,
		Status:               result.Status,
		ChunkCount:           this.sink.chunkCount,
		CastBytes:            this.sink.castBytes,
		CiphertextBytes:      this.sink.ciphertextBytes,
		Digest:               digest,
		CiphertextStreamHash: streamHash,
	}, nil
}

func (this *BECastWriter) failSeal(err error) error {
	_ = this.sink.poison(err)
	this.sink.encoder.Close()
	return err
}

func (this *beCastSink) Write(value []byte) (int, error) {
	if this.poisoned != nil {
		return 0, this.poisoned
	}
	if len(value) == 0 || value[len(value)-1] != '\n' || len(value) > MaximumCastLineBytes+1 {
		return 0, this.poison(errors.System.Newf("BECast sink received an illegal Cast line"))
	}
	if this.buffer.Len() == 0 && this.chunkCount >= this.limits.maximumChunks {
		return 0, this.poison(errors.System.Newf("BECast chunk count exceeds maximum"))
	}
	if recordingCountExceedsLimit(this.castBytes, uint64(this.buffer.Len())+uint64(len(value)), 0, this.limits.maximumCastBytes) {
		return 0, this.poison(errors.System.Newf("BECast Cast size exceeds maximum"))
	}
	if this.buffer.Len() > MaximumBECastChunkPlaintext-len(value) {
		return 0, this.poison(errors.System.Newf("BECast plaintext chunk exceeds %d bytes", MaximumBECastChunkPlaintext))
	}

	isEventMetadata := bytes.HasPrefix(value, []byte(castEventCommentPrefix))
	isResult := bytes.HasPrefix(value, []byte(castResultCommentPrefix))
	continuation := this.pendingGroup
	if _, err := this.buffer.Write(value); err != nil {
		return 0, this.poison(err)
	}
	if this.initialLines > 0 {
		this.initialLines--
		this.pendingGroup = this.initialLines > 0
	} else if continuation {
		this.pendingGroup = false
	} else {
		this.pendingGroup = isEventMetadata || isResult
	}
	return len(value), nil
}

func (this *beCastSink) beforeContentLine(value []byte) error {
	if this.poisoned != nil {
		return this.poisoned
	}
	if this.cast == nil || this.flushing || this.sealing || this.pendingGroup || this.buffer.Len() == 0 {
		return nil
	}
	remainingTarget := this.chunkSize - this.buffer.Len()
	remainingMaximum := MaximumBECastChunkPlaintext - maximumBECastCheckpointPaddingBytes - this.buffer.Len()
	maximumGroupBytes := len(value)
	if bytes.HasPrefix(value, []byte(castEventCommentPrefix)) {
		maximumGroupBytes += maximumCastOutputEventLineBytes
	}
	if len(value) > remainingTarget || maximumGroupBytes > remainingMaximum {
		return this.flush(false, nil, 0)
	}
	return nil
}

func (this *beCastSink) afterContentLine([]byte) error {
	if this.poisoned != nil {
		return this.poisoned
	}
	if this.cast == nil || this.flushing || this.sealing || this.pendingGroup || this.buffer.Len() < this.chunkSize {
		return nil
	}
	return this.flush(false, nil, 0)
}

func (this *beCastSink) flush(final bool, finalDigest *CastDigest, finalStatus uint8) error {
	if this.poisoned != nil {
		return this.poisoned
	}
	if this.pendingGroup && !final {
		return nil
	}
	if this.pendingGroup {
		return this.poison(errors.System.Newf("BECast stream ends inside an atomic Cast line group"))
	}
	if this.buffer.Len() == 0 {
		return nil
	}
	if this.chunkCount >= this.limits.maximumChunks {
		return this.poison(errors.System.Newf("BECast chunk count exceeds maximum"))
	}
	if final != (finalDigest != nil) || final != (finalStatus != 0) {
		return this.poison(errors.System.Newf("BECast flush has an invalid final digest"))
	}

	var checkpoint castSha256Checkpoint
	if final {
		copy(checkpoint.State[:], finalDigest[:])
	} else {
		this.flushing = true
		var err error
		checkpoint, err = padCastForSha256Checkpoint(this.cast)
		this.flushing = false
		if err != nil {
			return this.poison(err)
		}
	}
	if this.buffer.Len() > MaximumBECastChunkPlaintext || uint64(this.buffer.Len()) > math.MaxUint32 {
		return this.poison(errors.System.Newf("BECast plaintext chunk exceeds %d bytes", MaximumBECastChunkPlaintext))
	}
	if recordingCountExceedsLimit(this.castBytes, uint64(this.buffer.Len()), 0, this.limits.maximumCastBytes) {
		return this.poison(errors.System.Newf("BECast Cast size exceeds maximum"))
	}
	plaintext := this.buffer.Bytes()
	frame := this.encoder.EncodeAll(plaintext, nil)
	if len(frame) == 0 || len(frame) > MaximumBECastCiphertext || uint64(len(frame)) > math.MaxUint32 {
		return this.poison(errors.System.Newf("BECast compressed frame exceeds %d bytes", MaximumBECastCiphertext))
	}

	var ciphertext bytes.Buffer
	encrypted, err := this.recipient.Encrypt(&ciphertext)
	if err != nil {
		return this.poison(errors.System.Newf("cannot initialize BECast chunk encryption: %w", err))
	}
	written, writeErr := encrypted.Write(frame)
	closeErr := encrypted.Close()
	if writeErr != nil {
		return this.poison(errors.System.Newf("cannot encrypt BECast chunk: %w", writeErr))
	}
	if written != len(frame) {
		return this.poison(errors.System.Newf("cannot encrypt BECast chunk: %w", io.ErrShortWrite))
	}
	if closeErr != nil {
		return this.poison(errors.System.Newf("cannot finish BECast chunk encryption: %w", closeErr))
	}
	if ciphertext.Len() == 0 || ciphertext.Len() > MaximumBECastCiphertext || uint64(ciphertext.Len()) > math.MaxUint32 {
		return this.poison(errors.System.Newf("BECast ciphertext exceeds %d bytes", MaximumBECastCiphertext))
	}
	if this.chunkCount == math.MaxUint64 {
		return this.poison(errors.System.Newf("BECast chunk sequence overflow"))
	}
	nextCastBytes, err := checkedBECastCount("Cast", this.castBytes, uint64(len(plaintext)))
	if err != nil {
		return this.poison(err)
	}
	nextCiphertextBytes, err := checkedBECastCount("ciphertext", this.ciphertextBytes, uint64(ciphertext.Len()))
	if err != nil {
		return this.poison(err)
	}

	ciphertextHash := hashBECastCiphertext(ciphertext.Bytes())
	chunkValue, err := this.identity.NewSessionRecordingBECastChunk(audit.SessionRecordingBECastChunk{
		FormatVersion:    castBECastFormatVersion,
		FinalStatus:      finalStatus,
		RecordingId:      this.recordingId,
		Sequence:         this.chunkCount + 1,
		PreviousUnitHash: this.previousUnitHash,
		PlaintextOffset:  this.castBytes,
		PlaintextLength:  uint32(len(plaintext)),
		CiphertextLength: uint32(ciphertext.Len()),
		CiphertextHash:   ciphertextHash,
		ContentHashState: audit.SessionRecordingHash(checkpoint.State),
		ContentHashBytes: checkpoint.Bytes,
	})
	if err != nil {
		return this.poison(err)
	}
	unit, err := encodeBECastChunk(chunkValue, ciphertext.Bytes())
	if err != nil {
		return this.poison(err)
	}
	if recordingCountExceedsLimit(this.prefixBytes, uint64(len(unit)), castBECastSealUnitSize, this.limits.maximumContainerBytes) {
		return this.poison(errors.System.Newf("BECast container exceeds maximum size"))
	}
	nextPrefixBytes, err := checkedBECastCount("prefix", this.prefixBytes, uint64(len(unit)))
	if err != nil {
		return this.poison(err)
	}
	if err := writeBECastBytes(this.output, unit); err != nil {
		return this.poison(err)
	}

	this.previousUnitHash = hashBECastUnit(unit)
	this.prefixBytes = nextPrefixBytes
	this.castBytes = nextCastBytes
	this.ciphertextBytes = nextCiphertextBytes
	this.chunkCount++
	_, _ = this.ciphertextStream.Write(ciphertext.Bytes())
	if !final {
		this.lastCheckpoint = checkpoint
	}
	this.buffer.Reset()
	return nil
}

func (this *beCastSink) poison(err error) error {
	if this.poisoned == nil {
		this.poisoned = err
		if this.cast != nil {
			_ = this.cast.poison(err)
		}
	}
	return err
}

func checkedBECastCount(name string, current, increment uint64) (uint64, error) {
	if math.MaxUint64-current < increment {
		return 0, errors.System.Newf("BECast %s byte count overflow", name)
	}
	return current + increment, nil
}

func writeBECastBytes(output io.Writer, value []byte) error {
	written, err := output.Write(value)
	if err != nil {
		return errors.System.Newf("cannot write BECast data: %w", err)
	}
	if written != len(value) {
		return errors.System.Newf("cannot write BECast data: %w", io.ErrShortWrite)
	}
	return nil
}
