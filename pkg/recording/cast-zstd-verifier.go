package recording

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"

	"github.com/klauspost/compress/zstd"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

const DefaultMaximumCastZstdBytes = int64(32 << 30)

type CastZstdVerifyOptions struct {
	Context               context.Context
	MaximumContainerBytes int64
	MaximumCastBytes      int64
	MaximumChunks         uint64
	ExpectedProducerId    audit.ProducerId
	AllowUntrusted        bool
}

type CastZstdVerification struct {
	Cast        *CastVerification
	Summary     CastZstdSummary
	Fingerprint string
	Trusted     bool
}

type castZstdStream struct {
	source           io.ReaderAt
	size             int64
	offset           int64
	decoder          *zstd.Decoder
	header           audit.SessionRecordingZstdHeader
	publicKey        bfcrypto.PublicKey
	headerUnitHash   audit.SessionRecordingHash
	previousUnitHash audit.SessionRecordingHash
	streamHash       hash.Hash
	maximumCastBytes uint64
	maximumChunks    uint64
	castBytes        uint64
	zstdBytes        uint64
	chunkCount       uint64
	pending          []byte
	pendingOffset    int
	seal             *audit.SessionRecordingZstdSeal
	recovery         bool
	incompleteTail   bool
	validEnd         int64
	checkpoint       *audit.SessionRecordingZstdHead
	checkpointSeen   bool
	context          context.Context
	closed           bool
}

func VerifyCastZstd(source io.ReaderAt, size int64, options CastZstdVerifyOptions) (*CastZstdVerification, error) {
	stream, err := newCastZstdStream(source, size, options)
	if err != nil {
		return nil, err
	}
	defer stream.close()
	cast, err := VerifyCast(stream, CastVerifyOptions{
		MaximumBytes:       effectiveMaximumCastBytes(options.MaximumCastBytes),
		ExpectedProducerId: options.ExpectedProducerId,
		AllowUntrusted:     options.AllowUntrusted,
	})
	if err != nil {
		return nil, errors.System.Newf("cannot verify Cast inside Zstandard container: %w", err)
	}
	if stream.seal == nil {
		return nil, errors.System.Newf("cast Zstandard container has no final seal")
	}
	if cast.Metadata.RecordingId.String() != stream.header.RecordingId.String() || cast.Metadata.ProducerId != stream.header.ProducerId {
		return nil, errors.System.Newf("cast identity does not match its Zstandard container")
	}
	status, err := castStatusFromZstd(stream.seal.Status)
	if err != nil {
		return nil, err
	}
	if status != cast.Result.Status {
		return nil, errors.System.Newf("cast status does not match its Zstandard seal")
	}
	if !bytes.Equal(cast.Digest[:], stream.seal.CastContentDigest[:]) {
		return nil, errors.System.Newf("cast digest does not match its Zstandard seal")
	}
	trusted := options.ExpectedProducerId != (audit.ProducerId{})
	return &CastZstdVerification{
		Cast: cast,
		Summary: CastZstdSummary{
			RecordingId: Id(stream.header.RecordingId),
			ProducerId:  stream.header.ProducerId,
			Status:      status,
			ChunkCount:  stream.chunkCount,
			CastBytes:   stream.castBytes,
			ZstdBytes:   stream.zstdBytes,
			Digest:      cast.Digest,
			StreamHash:  stream.seal.CastStreamHash,
		},
		Fingerprint: cast.Fingerprint,
		Trusted:     trusted,
	}, nil
}

// ExportCastZstd verifies source before writing plaintext. Source must provide
// an immutable snapshot for both verification passes.
func ExportCastZstd(source io.ReaderAt, size int64, output io.Writer, options CastZstdVerifyOptions) (*CastZstdVerification, error) {
	if output == nil {
		return nil, errors.System.Newf("nil Cast Zstandard export output")
	}
	verification, err := VerifyCastZstd(source, size, options)
	if err != nil {
		return nil, err
	}
	stream, err := newCastZstdStream(source, size, options)
	if err != nil {
		return nil, err
	}
	defer stream.close()
	if stream.header.RecordingId != [16]byte(verification.Summary.RecordingId) || stream.header.ProducerId != verification.Summary.ProducerId {
		return nil, errors.System.Newf("cast Zstandard input changed between verification and export")
	}
	written, err := io.Copy(output, stream)
	if err != nil {
		return nil, errors.System.Newf("cannot export Cast Zstandard content: %w", err)
	}
	if uint64(written) != verification.Summary.CastBytes || stream.seal == nil || stream.seal.CastStreamHash != verification.Summary.StreamHash {
		return nil, errors.System.Newf("cast Zstandard input changed between verification and export")
	}
	return verification, nil
}

func newCastZstdStream(source io.ReaderAt, size int64, options CastZstdVerifyOptions) (*castZstdStream, error) {
	return newCastZstdStreamForRecovery(source, size, options, nil, false)
}

func newCastZstdStreamForRecovery(source io.ReaderAt, size int64, options CastZstdVerifyOptions, checkpoint *audit.SessionRecordingZstdHead, recovery bool) (*castZstdStream, error) {
	if source == nil {
		return nil, errors.System.Newf("nil Cast Zstandard input")
	}
	maximumContainerBytes := options.MaximumContainerBytes
	if maximumContainerBytes == 0 {
		maximumContainerBytes = DefaultMaximumCastZstdBytes
	}
	if maximumContainerBytes < 1 {
		return nil, errors.Config.Newf("maximum Cast Zstandard container size must be positive")
	}
	if size < 1 || size > maximumContainerBytes {
		return nil, errors.System.Newf("cast Zstandard container size %d is outside the supported range", size)
	}
	if options.ExpectedProducerId == (audit.ProducerId{}) && !options.AllowUntrusted {
		return nil, errors.Config.Newf("expected producer ID is required unless untrusted verification is explicitly allowed")
	}
	maximumCastBytes := effectiveMaximumCastBytes(options.MaximumCastBytes)
	if maximumCastBytes < 1 {
		return nil, errors.Config.Newf("maximum Cast size must be positive")
	}
	maximumChunks := effectiveMaximumCastZstdChunks(options.MaximumChunks)
	decoder, err := zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxWindow(castZstdWindowSize),
		zstd.WithDecoderMaxMemory(uint64(MaximumCastZstdChunkSize+castZstdWindowSize)),
		zstd.WithDecodeAllCapLimit(true),
	)
	if err != nil {
		return nil, errors.System.Newf("cannot create Cast Zstandard decoder: %w", err)
	}
	stream := &castZstdStream{
		source:           source,
		size:             size,
		decoder:          decoder,
		maximumCastBytes: uint64(maximumCastBytes),
		maximumChunks:    maximumChunks,
		recovery:         recovery,
		checkpoint:       checkpoint,
		context:          options.Context,
	}
	headerFrame, headerPayload, err := stream.readSkippableFrame(castZstdHeaderSkippableId, castZstdHeaderPayloadSize)
	if err != nil {
		decoder.Close()
		return nil, errors.System.Newf("cannot read Cast Zstandard header: %w", err)
	}
	header, err := decodeCastZstdHeader(headerPayload)
	if err != nil {
		decoder.Close()
		return nil, err
	}
	if header.FormatVersion != castZstdFormatVersion || header.CastVersion != castVersion || header.Codec != castZstdCodec {
		decoder.Close()
		return nil, errors.System.Newf("unsupported Cast Zstandard header version or codec")
	}
	publicKey, err := audit.VerifySessionRecordingZstdHeader(header)
	if err != nil {
		decoder.Close()
		return nil, err
	}
	if options.ExpectedProducerId != (audit.ProducerId{}) && header.ProducerId != options.ExpectedProducerId {
		decoder.Close()
		return nil, errors.System.Newf("cast Zstandard container belongs to producer %s instead of %s", header.ProducerId, options.ExpectedProducerId)
	}
	streamHasher := newDomainHasher(castZstdStreamHashDomain)
	headerUnitHash := hashDomainValues(castZstdUnitHashDomain, headerFrame)
	stream.header = header
	stream.publicKey = publicKey
	stream.headerUnitHash = headerUnitHash
	stream.previousUnitHash = headerUnitHash
	stream.streamHash = streamHasher
	stream.validEnd = stream.offset
	if checkpoint != nil {
		if checkpoint.FormatVersion != castZstdFormatVersion || checkpoint.RecordingId != header.RecordingId || checkpoint.ProducerId != header.ProducerId {
			decoder.Close()
			return nil, errors.System.Newf("cast Zstandard checkpoint does not match its container")
		}
		if err := audit.VerifySessionRecordingZstdHead(publicKey, *checkpoint); err != nil {
			decoder.Close()
			return nil, err
		}
	}
	return stream, nil
}

func (this *castZstdStream) Read(target []byte) (int, error) {
	if len(target) == 0 {
		return 0, nil
	}
	if this.closed {
		return 0, io.EOF
	}
	for this.pendingOffset >= len(this.pending) {
		this.pending = nil
		this.pendingOffset = 0
		if this.seal != nil {
			if this.recovery && this.checkpoint != nil && !this.checkpointSeen {
				return 0, errors.System.Newf("cast Zstandard container lost data behind its signed checkpoint")
			}
			return 0, io.EOF
		}
		if err := this.readNextUnit(); err != nil {
			return 0, err
		}
	}
	read := copy(target, this.pending[this.pendingOffset:])
	this.pendingOffset += read
	return read, nil
}

func (this *castZstdStream) readNextUnit() error {
	if this.context != nil {
		select {
		case <-this.context.Done():
			return this.context.Err()
		default:
		}
	}
	unitStart := this.offset
	magic, err := this.peekMagic()
	if err != nil {
		if err == io.EOF {
			if this.recovery {
				return this.finishRecoveryPrefix()
			}
			return errors.System.Newf("cast Zstandard container has no final seal")
		}
		if err == io.ErrUnexpectedEOF && this.recovery {
			return this.finishIncompleteTail(unitStart)
		}
		return err
	}
	switch magic {
	case zstdSkippableMagicBase | castZstdChunkSkippableId:
		if err := this.ensureRecoveryUnitAvailable(unitStart, castZstdChunkPayloadSize); err != nil {
			return err
		}
		return this.readChunk()
	case zstdSkippableMagicBase | castZstdSealSkippableId:
		if err := this.ensureRecoveryUnitAvailable(unitStart, castZstdSealPayloadSize); err != nil {
			return err
		}
		return this.readSeal()
	default:
		return errors.System.Newf("unexpected Cast Zstandard unit magic 0x%08x at offset %d", magic, this.offset)
	}
}

func (this *castZstdStream) readChunk() error {
	if this.chunkCount >= this.maximumChunks {
		return errors.System.Newf("cast Zstandard container exceeds %d chunks", this.maximumChunks)
	}
	descriptor, payload, err := this.readSkippableFrame(castZstdChunkSkippableId, castZstdChunkPayloadSize)
	if err != nil {
		return errors.System.Newf("cannot read Cast Zstandard chunk %d: %w", this.chunkCount+1, err)
	}
	value, err := decodeCastZstdChunk(payload, this.header.RecordingId, this.header.ProducerId)
	if err != nil {
		return err
	}
	if value.FormatVersion != castZstdFormatVersion || value.Sequence != this.chunkCount+1 || value.PreviousUnitHash != this.previousUnitHash || value.PlaintextOffset != this.castBytes {
		return errors.System.Newf("cast Zstandard chunk %d does not continue its chain", value.Sequence)
	}
	if value.PlaintextLength == 0 || value.PlaintextLength > MaximumCastZstdChunkSize || value.FrameLength == 0 || value.FrameLength > MaximumCastZstdFrameSize {
		return errors.System.Newf("cast Zstandard chunk %d exceeds its limits", value.Sequence)
	}
	if uint64(value.PlaintextLength) > this.maximumCastBytes-this.castBytes {
		return errors.System.Newf("cast Zstandard plaintext exceeds %d bytes", this.maximumCastBytes)
	}
	if err := audit.VerifySessionRecordingZstdChunk(this.publicKey, value); err != nil {
		return err
	}
	if this.recovery && int64(value.FrameLength) > this.size-this.offset {
		return this.finishIncompleteTail(this.offset - int64(8+castZstdChunkPayloadSize))
	}
	frame, err := this.readBytes(int(value.FrameLength))
	if err != nil {
		return errors.System.Newf("cannot read Cast Zstandard frame %d: %w", value.Sequence, err)
	}
	if hashDomainValues(castZstdFrameHashDomain, frame) != value.FrameHash {
		return errors.System.Newf("cast Zstandard frame %d hash is invalid", value.Sequence)
	}
	if err := validateSingleCastZstdFrame(frame, value.PlaintextLength); err != nil {
		return errors.System.Newf("illegal Cast Zstandard frame %d: %w", value.Sequence, err)
	}
	plaintext, err := this.decoder.DecodeAll(frame, make([]byte, 0, int(value.PlaintextLength)))
	if err != nil {
		return errors.System.Newf("cannot decompress Cast Zstandard frame %d: %w", value.Sequence, err)
	}
	if len(plaintext) != int(value.PlaintextLength) {
		return errors.System.Newf("cast Zstandard frame %d produced %d bytes instead of %d", value.Sequence, len(plaintext), value.PlaintextLength)
	}
	if err := validateCastZstdChunkLines(plaintext, this.chunkCount == 0); err != nil {
		return errors.System.Newf("illegal Cast Zstandard frame %d boundaries: %w", value.Sequence, err)
	}
	this.previousUnitHash = hashDomainValues(castZstdUnitHashDomain, descriptor, frame)
	this.castBytes += uint64(len(plaintext))
	this.zstdBytes += uint64(len(frame))
	this.chunkCount++
	this.validEnd = this.offset
	if this.checkpoint != nil && this.chunkCount == this.checkpoint.ChunkCount {
		if this.checkpoint.PrefixBytes != uint64(this.offset) || this.checkpoint.LastUnitHash != this.previousUnitHash {
			return errors.System.Newf("cast Zstandard container does not contain its signed checkpoint state")
		}
		this.checkpointSeen = true
	}
	_, _ = this.streamHash.Write(plaintext)
	this.pending = plaintext
	return nil
}

func (this *castZstdStream) readSeal() error {
	prefixBytes := uint64(this.offset)
	_, payload, err := this.readSkippableFrame(castZstdSealSkippableId, castZstdSealPayloadSize)
	if err != nil {
		return errors.System.Newf("cannot read Cast Zstandard seal: %w", err)
	}
	if this.offset != this.size {
		return errors.System.Newf("cast Zstandard container contains data after its final seal")
	}
	value, err := decodeCastZstdSeal(payload, this.header.RecordingId, this.header.ProducerId)
	if err != nil {
		return err
	}
	if value.FormatVersion != castZstdFormatVersion || value.ChunkCount != this.chunkCount || value.CastBytes != this.castBytes || value.ZstdBytes != this.zstdBytes || value.PrefixBytes != prefixBytes || value.HeaderUnitHash != this.headerUnitHash || value.LastChunkUnitHash != this.previousUnitHash {
		return errors.System.Newf("cast Zstandard seal does not match its container")
	}
	var streamHash audit.SessionRecordingHash
	copy(streamHash[:], this.streamHash.Sum(nil))
	if value.CastStreamHash != streamHash {
		return errors.System.Newf("cast Zstandard stream hash does not match its seal")
	}
	if _, err := castStatusFromZstd(value.Status); err != nil {
		return err
	}
	if err := audit.VerifySessionRecordingZstdSeal(this.publicKey, value); err != nil {
		return err
	}
	this.seal = &value
	this.validEnd = this.offset
	return nil
}

func (this *castZstdStream) ensureRecoveryUnitAvailable(unitStart int64, payloadSize int) error {
	if !this.recovery {
		return nil
	}
	remaining := this.size - unitStart
	if remaining < 8 {
		return this.finishIncompleteTail(unitStart)
	}
	var header [8]byte
	read, err := this.source.ReadAt(header[:], unitStart)
	if err != nil && err != io.EOF {
		return err
	}
	if read != len(header) {
		return this.finishIncompleteTail(unitStart)
	}
	if binary.LittleEndian.Uint32(header[4:]) != uint32(payloadSize) {
		return errors.System.Newf("cast Zstandard unit at offset %d has an illegal payload size", unitStart)
	}
	if remaining < int64(8+payloadSize) {
		return this.finishIncompleteTail(unitStart)
	}
	return nil
}

func (this *castZstdStream) finishIncompleteTail(unitStart int64) error {
	this.incompleteTail = true
	this.offset = unitStart
	return this.finishRecoveryPrefix()
}

func (this *castZstdStream) finishRecoveryPrefix() error {
	if this.checkpoint != nil && !this.checkpointSeen {
		return errors.System.Newf("cast Zstandard container lost data behind its signed checkpoint")
	}
	return io.EOF
}

func (this *castZstdStream) readSkippableFrame(expectedId, expectedPayloadSize int) ([]byte, []byte, error) {
	header, err := this.readBytes(8)
	if err != nil {
		return nil, nil, err
	}
	expectedMagic := zstdSkippableMagicBase | uint32(expectedId)
	if binary.LittleEndian.Uint32(header) != expectedMagic {
		return nil, nil, errors.System.Newf("unexpected skippable magic")
	}
	payloadSize := binary.LittleEndian.Uint32(header[4:])
	if payloadSize != uint32(expectedPayloadSize) {
		return nil, nil, errors.System.Newf("skippable payload has %d bytes instead of %d", payloadSize, expectedPayloadSize)
	}
	payload, err := this.readBytes(expectedPayloadSize)
	if err != nil {
		return nil, nil, err
	}
	frame := append(append([]byte(nil), header...), payload...)
	return frame, payload, nil
}

func (this *castZstdStream) peekMagic() (uint32, error) {
	if this.offset == this.size {
		return 0, io.EOF
	}
	if this.size-this.offset < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	var raw [4]byte
	read, err := this.source.ReadAt(raw[:], this.offset)
	if read != len(raw) {
		return 0, io.ErrUnexpectedEOF
	}
	if err != nil && err != io.EOF {
		return 0, err
	}
	return binary.LittleEndian.Uint32(raw[:]), nil
}

func (this *castZstdStream) readBytes(size int) ([]byte, error) {
	if size < 0 || int64(size) > this.size-this.offset {
		return nil, io.ErrUnexpectedEOF
	}
	result := make([]byte, size)
	read, err := this.source.ReadAt(result, this.offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if read != size {
		return nil, io.ErrUnexpectedEOF
	}
	this.offset += int64(size)
	return result, nil
}

func (this *castZstdStream) close() {
	if !this.closed {
		this.closed = true
		this.decoder.Close()
	}
}

func validateSingleCastZstdFrame(frame []byte, expectedPlaintext uint32) error {
	length, err := scanZstdFrameLength(frame)
	if err != nil {
		return err
	}
	if length != len(frame) {
		return errors.System.Newf("frame contains %d trailing bytes", len(frame)-length)
	}
	var header zstd.Header
	if err := header.Decode(frame); err != nil {
		return err
	}
	if header.Skippable || !header.HasCheckSum || header.DictionaryID != 0 || !header.HasFCS || header.FrameContentSize != uint64(expectedPlaintext) {
		return errors.System.Newf("frame header has illegal checksum, dictionary, or content-size metadata")
	}
	if !header.SingleSegment && (header.WindowSize == 0 || header.WindowSize > castZstdWindowSize) {
		return errors.System.Newf("frame window %d exceeds %d", header.WindowSize, castZstdWindowSize)
	}
	return nil
}

func scanZstdFrameLength(frame []byte) (int, error) {
	if len(frame) < 5 || binary.LittleEndian.Uint32(frame) != 0xfd2fb528 {
		return 0, errors.System.Newf("missing Zstandard frame magic")
	}
	descriptor := frame[4]
	if descriptor&0x08 != 0 {
		return 0, errors.System.Newf("zstandard frame descriptor uses its reserved bit")
	}
	contentSizeFlag := descriptor >> 6
	singleSegment := descriptor&0x20 != 0
	dictionarySize := [...]int{0, 1, 2, 4}[descriptor&0x03]
	contentSizeBytes := [...]int{0, 2, 4, 8}[contentSizeFlag]
	if singleSegment && contentSizeFlag == 0 {
		contentSizeBytes = 1
	}
	offset := 5
	if !singleSegment {
		offset++
	}
	offset += dictionarySize + contentSizeBytes
	if offset > len(frame) {
		return 0, io.ErrUnexpectedEOF
	}
	for blocks := 0; ; blocks++ {
		if blocks >= maximumCastZstdBlocks {
			return 0, errors.System.Newf("zstandard frame contains too many blocks")
		}
		if len(frame)-offset < 3 {
			return 0, io.ErrUnexpectedEOF
		}
		blockHeader := uint32(frame[offset]) | uint32(frame[offset+1])<<8 | uint32(frame[offset+2])<<16
		offset += 3
		last := blockHeader&1 != 0
		blockType := blockHeader >> 1 & 0x03
		blockSize := int(blockHeader >> 3)
		if blockType == 3 {
			return 0, errors.System.Newf("zstandard frame contains a reserved block type")
		}
		physicalSize := blockSize
		if blockType == 1 {
			physicalSize = 1
		}
		if physicalSize < 0 || physicalSize > len(frame)-offset {
			return 0, io.ErrUnexpectedEOF
		}
		offset += physicalSize
		if last {
			break
		}
	}
	if descriptor&0x04 != 0 {
		if len(frame)-offset < 4 {
			return 0, io.ErrUnexpectedEOF
		}
		offset += 4
	}
	return offset, nil
}

func validateCastZstdChunkLines(plaintext []byte, initial bool) error {
	if len(plaintext) == 0 || plaintext[len(plaintext)-1] != '\n' {
		return errors.System.Newf("frame does not end at a complete Cast line")
	}
	lines := bytes.Split(plaintext[:len(plaintext)-1], []byte{'\n'})
	if initial && len(lines) < 2 {
		return errors.System.Newf("initial frame does not contain Cast header and metadata")
	}
	pending := false
	for _, line := range lines {
		if pending {
			pending = false
			continue
		}
		pending = bytes.HasPrefix(line, []byte(castEventCommentPrefix)) || bytes.HasPrefix(line, []byte(castResultCommentPrefix))
	}
	if pending {
		return errors.System.Newf("frame ends inside an atomic Cast line group")
	}
	return nil
}

func effectiveMaximumCastBytes(value int64) int64 {
	if value == 0 {
		return DefaultMaximumCastBytes
	}
	return value
}

func effectiveMaximumCastZstdChunks(value uint64) uint64 {
	if value == 0 {
		return DefaultMaximumCastZstdChunks
	}
	return value
}

func newDomainHasher(domain string) hash.Hash {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(domain))
	return hasher
}
