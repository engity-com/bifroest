package recording

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"
	"math"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

const DefaultMaximumBECastBytes = int64(32 << 30)

type BECastVerifyOptions struct {
	ExpectedProducerId    audit.ProducerId
	AllowUntrusted        bool
	MaximumContainerBytes int64
	MaximumCastBytes      int64
	MaximumChunks         uint64
	Context               context.Context
}

type BECastVerification struct {
	Summary BECastSummary
	Header  audit.SessionRecordingBECastHeader
	Trusted bool
	Cast    *CastVerification
}

type beCastVerifiedChunk struct {
	value            audit.SessionRecordingBECastChunk
	ciphertextOffset int64
}

type beCastManifest struct {
	verification *BECastVerification
	publicKey    bfcrypto.PublicKey
	chunks       []beCastVerifiedChunk
}

type beCastScanner struct {
	source               io.ReaderAt
	size                 int64
	offset               int64
	maximumCastBytes     uint64
	maximumChunks        uint64
	context              context.Context
	header               audit.SessionRecordingBECastHeader
	publicKey            bfcrypto.PublicKey
	headerUnitHash       audit.SessionRecordingHash
	previousUnitHash     audit.SessionRecordingHash
	ciphertextStreamHash hash.Hash
	castBytes            uint64
	ciphertextBytes      uint64
	chunkCount           uint64
	finalChunkSeen       bool
	finalContentHash     audit.SessionRecordingHash
	chunks               []beCastVerifiedChunk
}

// VerifyBECast verifies the signed outer container without decrypting it.
// Source must remain an immutable ReaderAt snapshot for the duration of the call.
func VerifyBECast(source io.ReaderAt, size int64, options BECastVerifyOptions) (*BECastVerification, error) {
	manifest, err := verifyBECastManifest(source, size, options)
	if err != nil {
		return nil, err
	}
	return manifest.verification, nil
}

// DecryptBECast verifies the complete outer container and then verifies the
// decrypted Cast in a no-output pass before decrypting it again into output.
// Source must provide an immutable ReaderAt snapshot across all three passes.
func DecryptBECast(source io.ReaderAt, size int64, identities *bfcrypto.AgeSshIdentities, output io.Writer, options BECastVerifyOptions) (*BECastVerification, error) {
	if identities == nil {
		return nil, errors.System.Newf("nil BECast age SSH identities")
	}
	if output == nil {
		return nil, errors.System.Newf("nil BECast plaintext output")
	}
	manifest, err := verifyBECastManifest(source, size, options)
	if err != nil {
		return nil, err
	}
	stream, err := newBECastPlaintextStream(source, identities, manifest, options.Context)
	if err != nil {
		return nil, err
	}
	cast, verifyErr := VerifyCast(stream, CastVerifyOptions{
		MaximumBytes:       int64(manifest.verification.Summary.CastBytes),
		ExpectedProducerId: options.ExpectedProducerId,
		AllowUntrusted:     options.AllowUntrusted,
	})
	closeErr := stream.close()
	if verifyErr != nil {
		return nil, errors.System.Newf("cannot verify Cast inside BECast container: %w", verifyErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err := verifyBECastPlaintext(manifest, cast); err != nil {
		return nil, err
	}

	exportStream, err := newBECastPlaintextStream(source, identities, manifest, options.Context)
	if err != nil {
		return nil, err
	}
	written, copyErr := io.Copy(output, exportStream)
	closeErr = exportStream.close()
	if copyErr != nil {
		return nil, errors.System.Newf("cannot export BECast plaintext: %w", copyErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if written < 0 || uint64(written) != manifest.verification.Summary.CastBytes {
		return nil, errors.System.Newf("BECast input changed between verification and export")
	}
	manifest.verification.Cast = cast
	return manifest.verification, nil
}

func verifyBECastManifest(source io.ReaderAt, size int64, options BECastVerifyOptions) (*beCastManifest, error) {
	if source == nil {
		return nil, errors.System.Newf("nil BECast input")
	}
	maximumContainerBytes := options.MaximumContainerBytes
	if maximumContainerBytes == 0 {
		maximumContainerBytes = DefaultMaximumBECastBytes
	}
	if maximumContainerBytes < 1 {
		return nil, errors.Config.Newf("maximum BECast container size must be positive")
	}
	if size < 1 || size > maximumContainerBytes {
		return nil, errors.System.Newf("BECast container size %d is outside the supported range", size)
	}
	if options.ExpectedProducerId == (audit.ProducerId{}) && !options.AllowUntrusted {
		return nil, errors.Config.Newf("expected producer ID is required unless untrusted verification is explicitly allowed")
	}
	maximumCastBytes := effectiveMaximumCastBytes(options.MaximumCastBytes)
	if maximumCastBytes < 1 {
		return nil, errors.Config.Newf("maximum Cast size must be positive")
	}
	maximumChunks := effectiveMaximumBECastChunks(options.MaximumChunks)

	scanner := &beCastScanner{
		source:               source,
		size:                 size,
		maximumCastBytes:     uint64(maximumCastBytes),
		maximumChunks:        maximumChunks,
		context:              options.Context,
		ciphertextStreamHash: hashSessionRecordingWriter(castBECastCiphertextStreamHashDomain),
	}
	magic, err := scanner.readBytes(len(castBECastFileMagic))
	if err != nil {
		return nil, errors.System.Newf("cannot read BECast file magic: %w", err)
	}
	if !bytes.Equal(magic, []byte(castBECastFileMagic)) {
		return nil, errors.System.Newf("BECast file magic mismatch")
	}
	headerUnit, _, err := scanner.readUnit(castBECastHeaderUnitType)
	if err != nil {
		return nil, errors.System.Newf("cannot read BECast header: %w", err)
	}
	header, err := decodeBECastHeader(headerUnit)
	if err != nil {
		return nil, err
	}
	if header.FormatVersion != castBECastFormatVersion || header.CastVersion != castVersion || header.Codec != castBECastCodec || header.Encryption != castBECastEncryption {
		return nil, errors.System.Newf("unsupported BECast header version, codec, or encryption")
	}
	publicKey, err := audit.VerifySessionRecordingBECastHeader(header)
	if err != nil {
		return nil, err
	}
	if options.ExpectedProducerId != (audit.ProducerId{}) && header.ProducerId != options.ExpectedProducerId {
		return nil, errors.System.Newf("BECast container belongs to producer %s instead of %s", header.ProducerId, options.ExpectedProducerId)
	}
	if header.RecipientFingerprint == ssh.FingerprintSHA256(publicKey.ToSsh()) {
		return nil, errors.System.Newf("BECast encryption recipient matches its signing identity")
	}
	scanner.header = header
	scanner.publicKey = publicKey
	scanner.headerUnitHash = hashBECastUnit(headerUnit)
	scanner.previousUnitHash = scanner.headerUnitHash

	for {
		if err := scanner.checkContext(); err != nil {
			return nil, err
		}
		unitType, err := scanner.peekUnitType()
		if err != nil {
			return nil, errors.System.Newf("BECast container has no final seal: %w", err)
		}
		switch unitType {
		case castBECastChunkUnitType:
			if err := scanner.readChunk(); err != nil {
				return nil, err
			}
		case castBECastSealUnitType:
			seal, err := scanner.readSeal()
			if err != nil {
				return nil, err
			}
			status, err := castStatusFromBECast(seal.Status)
			if err != nil {
				return nil, err
			}
			var digest CastDigest
			copy(digest[:], seal.CastContentDigest[:])
			verification := &BECastVerification{
				Summary: BECastSummary{
					RecordingId:          Id(header.RecordingId),
					ProducerId:           header.ProducerId,
					RecipientFingerprint: header.RecipientFingerprint,
					Status:               status,
					ChunkCount:           scanner.chunkCount,
					CastBytes:            scanner.castBytes,
					CiphertextBytes:      scanner.ciphertextBytes,
					Digest:               digest,
					CiphertextStreamHash: seal.CiphertextStreamHash,
				},
				Header:  header,
				Trusted: options.ExpectedProducerId != (audit.ProducerId{}),
			}
			return &beCastManifest{verification: verification, publicKey: publicKey, chunks: scanner.chunks}, nil
		default:
			return nil, errors.System.Newf("unexpected BECast unit type %d at offset %d", unitType, scanner.offset)
		}
	}
}

func (this *beCastScanner) readChunk() error {
	if this.finalChunkSeen {
		return errors.System.Newf("BECast container contains a continuation chunk after its final chunk")
	}
	if this.chunkCount >= this.maximumChunks {
		return errors.System.Newf("BECast container exceeds %d chunks", this.maximumChunks)
	}
	unitStart := this.offset
	unit, bodyLength, err := this.readUnit(castBECastChunkUnitType)
	if err != nil {
		return errors.System.Newf("cannot read BECast chunk %d: %w", this.chunkCount+1, err)
	}
	value, ciphertext, err := decodeBECastChunk(unit, this.header.RecordingId, this.header.ProducerId)
	if err != nil {
		return err
	}
	if value.FormatVersion != castBECastFormatVersion || value.Sequence != this.chunkCount+1 || value.PreviousUnitHash != this.previousUnitHash || value.PlaintextOffset != this.castBytes {
		return errors.System.Newf("BECast chunk %d does not continue its chain", value.Sequence)
	}
	if value.PlaintextLength == 0 || value.PlaintextLength > MaximumBECastChunkPlaintext || value.CiphertextLength == 0 || value.CiphertextLength > MaximumBECastCiphertext {
		return errors.System.Newf("BECast chunk %d exceeds its limits", value.Sequence)
	}
	if uint64(value.PlaintextLength) > this.maximumCastBytes-this.castBytes {
		return errors.System.Newf("BECast plaintext exceeds %d bytes", this.maximumCastBytes)
	}
	nextCastBytes, err := checkedBECastCount("Cast", this.castBytes, uint64(value.PlaintextLength))
	if err != nil {
		return err
	}
	nextCiphertextBytes, err := checkedBECastCount("ciphertext", this.ciphertextBytes, uint64(value.CiphertextLength))
	if err != nil {
		return err
	}
	if value.ContentHashBytes == 0 {
		this.finalChunkSeen = true
		this.finalContentHash = value.ContentHashState
	} else {
		expectedHashBytes, err := checkedBECastCount("content hash", uint64(len(castContentHashDomain)), nextCastBytes)
		if err != nil {
			return err
		}
		if value.ContentHashBytes != expectedHashBytes || value.ContentHashBytes%sha256.BlockSize != 0 {
			return errors.System.Newf("BECast chunk %d has an invalid content hash continuation", value.Sequence)
		}
	}
	if err := audit.VerifySessionRecordingBECastChunk(this.publicKey, value); err != nil {
		return err
	}
	_, _ = this.ciphertextStreamHash.Write(ciphertext)
	this.previousUnitHash = hashBECastUnit(unit)
	this.castBytes = nextCastBytes
	this.ciphertextBytes = nextCiphertextBytes
	this.chunkCount++
	ciphertextOffset := unitStart + castBECastUnitPrefixSize + castBECastChunkDescriptorSize
	this.chunks = append(this.chunks, beCastVerifiedChunk{value: value, ciphertextOffset: ciphertextOffset})
	if uint64(bodyLength) != uint64(castBECastChunkDescriptorSize)+uint64(value.CiphertextLength) {
		return errors.System.Newf("BECast chunk %d has an inconsistent ciphertext length", value.Sequence)
	}
	return nil
}

func (this *beCastScanner) readSeal() (audit.SessionRecordingBECastSeal, error) {
	if !this.finalChunkSeen {
		return audit.SessionRecordingBECastSeal{}, errors.System.Newf("BECast seal is not preceded by a final chunk")
	}
	prefixBytes := uint64(this.offset)
	unit, _, err := this.readUnit(castBECastSealUnitType)
	if err != nil {
		return audit.SessionRecordingBECastSeal{}, errors.System.Newf("cannot read BECast seal: %w", err)
	}
	if this.offset != this.size {
		return audit.SessionRecordingBECastSeal{}, errors.System.Newf("BECast container contains data after its final seal")
	}
	value, err := decodeBECastSeal(unit, this.header.RecordingId, this.header.ProducerId)
	if err != nil {
		return audit.SessionRecordingBECastSeal{}, err
	}
	if value.FormatVersion != castBECastFormatVersion || value.ChunkCount != this.chunkCount || value.CastBytes != this.castBytes || value.CiphertextBytes != this.ciphertextBytes || value.PrefixBytes != prefixBytes || value.HeaderUnitHash != this.headerUnitHash || value.LastChunkUnitHash != this.previousUnitHash {
		return audit.SessionRecordingBECastSeal{}, errors.System.Newf("BECast seal does not match its container")
	}
	if value.CastContentDigest != this.finalContentHash {
		return audit.SessionRecordingBECastSeal{}, errors.System.Newf("BECast final chunk content hash does not match its seal")
	}
	var streamHash audit.SessionRecordingHash
	copy(streamHash[:], this.ciphertextStreamHash.Sum(nil))
	if value.CiphertextStreamHash != streamHash {
		return audit.SessionRecordingBECastSeal{}, errors.System.Newf("BECast ciphertext stream hash does not match its seal")
	}
	if _, err := castStatusFromBECast(value.Status); err != nil {
		return audit.SessionRecordingBECastSeal{}, err
	}
	if err := audit.VerifySessionRecordingBECastSeal(this.publicKey, value); err != nil {
		return audit.SessionRecordingBECastSeal{}, err
	}
	return value, nil
}

func (this *beCastScanner) peekUnitType() (uint8, error) {
	if this.offset == this.size {
		return 0, errors.System.Newf("unexpected end of BECast container")
	}
	prefix, err := this.readAt(this.offset, castBECastUnitPrefixSize)
	if err != nil {
		return 0, err
	}
	if string(prefix[:4]) != castBECastUnitMagic {
		return 0, errors.System.Newf("BECast unit magic mismatch")
	}
	return prefix[4], nil
}

func (this *beCastScanner) readUnit(expectedType uint8) ([]byte, uint32, error) {
	if err := this.checkContext(); err != nil {
		return nil, 0, err
	}
	prefix, err := this.readAt(this.offset, castBECastUnitPrefixSize)
	if err != nil {
		return nil, 0, err
	}
	if string(prefix[:4]) != castBECastUnitMagic || prefix[4] != expectedType || prefix[5] != 0 || binary.BigEndian.Uint16(prefix[6:]) != 0 {
		return nil, 0, errors.System.Newf("invalid BECast unit prefix for type %d", expectedType)
	}
	bodyLength := binary.BigEndian.Uint32(prefix[8:])
	switch expectedType {
	case castBECastHeaderUnitType:
		if bodyLength != castBECastHeaderBodySize {
			return nil, 0, errors.System.Newf("BECast header declares an invalid body size %d", bodyLength)
		}
	case castBECastChunkUnitType:
		if bodyLength < castBECastChunkDescriptorSize || uint64(bodyLength) > uint64(castBECastChunkDescriptorSize+MaximumBECastCiphertext) {
			return nil, 0, errors.System.Newf("BECast chunk declares an invalid body size %d", bodyLength)
		}
	case castBECastSealUnitType:
		if bodyLength != castBECastSealBodySize {
			return nil, 0, errors.System.Newf("BECast seal declares an invalid body size %d", bodyLength)
		}
	default:
		return nil, 0, errors.System.Newf("unsupported BECast unit type %d", expectedType)
	}
	unitLength := uint64(castBECastUnitPrefixSize+castBECastUnitTrailerSize) + uint64(bodyLength)
	if unitLength > math.MaxInt || unitLength > uint64(this.size-this.offset) {
		return nil, 0, errors.System.Newf("truncated BECast unit at offset %d", this.offset)
	}
	unit, err := this.readBytes(int(unitLength))
	if err != nil {
		return nil, 0, err
	}
	if _, err := decodeBECastUnit(unit, expectedType); err != nil {
		return nil, 0, err
	}
	return unit, bodyLength, nil
}

func (this *beCastScanner) readBytes(length int) ([]byte, error) {
	value, err := this.readAt(this.offset, length)
	if err != nil {
		return nil, err
	}
	this.offset += int64(length)
	return value, nil
}

func (this *beCastScanner) readAt(offset int64, length int) ([]byte, error) {
	if offset < 0 || length < 0 || offset > this.size || int64(length) > this.size-offset {
		return nil, errors.System.Newf("truncated BECast data at offset %d", offset)
	}
	value := make([]byte, length)
	read, err := this.source.ReadAt(value, offset)
	if err != nil && (err != io.EOF || read != length) {
		return nil, errors.System.Newf("cannot read BECast data at offset %d: %w", offset, err)
	}
	if read != length {
		return nil, errors.System.Newf("short BECast read at offset %d", offset)
	}
	return value, nil
}

func (this *beCastScanner) checkContext() error {
	if this.context == nil {
		return nil
	}
	select {
	case <-this.context.Done():
		return errors.System.Newf("BECast verification canceled: %w", this.context.Err())
	default:
		return nil
	}
}

type beCastPlaintextStream struct {
	source      io.ReaderAt
	identities  *bfcrypto.AgeSshIdentities
	manifest    *beCastManifest
	decoder     *zstd.Decoder
	contentHash hash.Hash
	context     context.Context
	chunkIndex  int
	pending     []byte
	pendingAt   int
	closed      bool
}

func newBECastPlaintextStream(source io.ReaderAt, identities *bfcrypto.AgeSshIdentities, manifest *beCastManifest, ctx context.Context) (*beCastPlaintextStream, error) {
	decoder, err := zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxWindow(castZstdWindowSize),
		zstd.WithDecoderMaxMemory(uint64(MaximumBECastChunkPlaintext+castZstdWindowSize)),
		zstd.WithDecodeAllCapLimit(true),
	)
	if err != nil {
		return nil, errors.System.Newf("cannot create BECast Zstandard decoder: %w", err)
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(castContentHashDomain))
	return &beCastPlaintextStream{source: source, identities: identities, manifest: manifest, decoder: decoder, contentHash: hasher, context: ctx}, nil
}

func (this *beCastPlaintextStream) Read(target []byte) (int, error) {
	if len(target) == 0 {
		return 0, nil
	}
	if this.closed {
		return 0, io.EOF
	}
	for this.pendingAt >= len(this.pending) {
		this.pending = nil
		this.pendingAt = 0
		if this.chunkIndex >= len(this.manifest.chunks) {
			return 0, io.EOF
		}
		if err := this.readChunk(); err != nil {
			return 0, err
		}
	}
	read := copy(target, this.pending[this.pendingAt:])
	this.pendingAt += read
	return read, nil
}

func (this *beCastPlaintextStream) readChunk() error {
	if this.context != nil {
		select {
		case <-this.context.Done():
			return errors.System.Newf("BECast decryption canceled: %w", this.context.Err())
		default:
		}
	}
	chunk := this.manifest.chunks[this.chunkIndex]
	ciphertextLength := int(chunk.value.CiphertextLength)
	ciphertext := make([]byte, ciphertextLength)
	read, err := this.source.ReadAt(ciphertext, chunk.ciphertextOffset)
	if err != nil && (err != io.EOF || read != ciphertextLength) {
		return errors.System.Newf("cannot reread BECast chunk %d ciphertext: %w", chunk.value.Sequence, err)
	}
	if read != ciphertextLength || hashBECastCiphertext(ciphertext) != chunk.value.CiphertextHash {
		return errors.System.Newf("BECast input changed at chunk %d", chunk.value.Sequence)
	}
	decrypted, err := this.identities.DecryptForFingerprint(bytes.NewReader(ciphertext), this.manifest.verification.Header.RecipientFingerprint)
	if err != nil {
		return errors.Config.Newf("cannot decrypt BECast chunk %d: %w", chunk.value.Sequence, err)
	}
	frame, err := io.ReadAll(io.LimitReader(decrypted, int64(MaximumBECastCiphertext)+1))
	if err != nil {
		return errors.System.Newf("cannot authenticate BECast chunk %d ciphertext: %w", chunk.value.Sequence, err)
	}
	if len(frame) == 0 || len(frame) > MaximumBECastCiphertext {
		return errors.System.Newf("BECast chunk %d compressed plaintext exceeds %d bytes", chunk.value.Sequence, MaximumBECastCiphertext)
	}
	if err := validateSingleCastZstdFrame(frame, chunk.value.PlaintextLength); err != nil {
		return errors.System.Newf("illegal BECast chunk %d Zstandard frame: %w", chunk.value.Sequence, err)
	}
	plaintext, err := this.decoder.DecodeAll(frame, make([]byte, 0, int(chunk.value.PlaintextLength)))
	if err != nil {
		return errors.System.Newf("cannot decompress BECast chunk %d: %w", chunk.value.Sequence, err)
	}
	if len(plaintext) != int(chunk.value.PlaintextLength) {
		return errors.System.Newf("BECast chunk %d produced %d plaintext bytes instead of %d", chunk.value.Sequence, len(plaintext), chunk.value.PlaintextLength)
	}
	if chunk.value.ContentHashBytes != 0 {
		_, _ = this.contentHash.Write(plaintext)
		checkpoint, err := checkpointCastSha256(this.contentHash)
		if err != nil {
			return err
		}
		if checkpoint.Bytes != chunk.value.ContentHashBytes || audit.SessionRecordingHash(checkpoint.State) != chunk.value.ContentHashState {
			return errors.System.Newf("BECast chunk %d plaintext does not match its content hash continuation", chunk.value.Sequence)
		}
	}
	this.chunkIndex++
	this.pending = plaintext
	return nil
}

func (this *beCastPlaintextStream) close() error {
	if this == nil || this.closed {
		return nil
	}
	this.closed = true
	this.decoder.Close()
	return nil
}

func verifyBECastPlaintext(manifest *beCastManifest, cast *CastVerification) error {
	verification := manifest.verification
	if cast.Metadata.RecordingId.String() != verification.Header.RecordingId.String() || cast.Metadata.ProducerId != verification.Header.ProducerId {
		return errors.System.Newf("Cast identity does not match its BECast container")
	}
	if cast.Result.Status != verification.Summary.Status {
		return errors.System.Newf("Cast status does not match its BECast seal")
	}
	if cast.Digest != verification.Summary.Digest {
		return errors.System.Newf("Cast digest does not match its BECast seal")
	}
	expectedFingerprint := ssh.FingerprintSHA256(manifest.publicKey.ToSsh())
	if cast.Fingerprint != expectedFingerprint {
		return errors.System.Newf("Cast signing key does not match its BECast header")
	}
	return nil
}

func effectiveMaximumBECastChunks(value uint64) uint64 {
	if value == 0 {
		return DefaultMaximumBECastChunks
	}
	return value
}
