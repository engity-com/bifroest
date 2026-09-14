package audit

import (
	"crypto/ed25519"
	"encoding/binary"

	"github.com/google/uuid"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	sessionRecordingZstdHeaderSignatureDomain = "BIFROEST-SESSION-RECORDING-ZSTD-HEADER-SIGNATURE/v1\x00"
	sessionRecordingZstdChunkSignatureDomain  = "BIFROEST-SESSION-RECORDING-ZSTD-CHUNK-SIGNATURE/v1\x00"
	sessionRecordingZstdSealSignatureDomain   = "BIFROEST-SESSION-RECORDING-ZSTD-SEAL-SIGNATURE/v1\x00"
	sessionRecordingZstdHeadSignatureDomain   = "BIFROEST-SESSION-RECORDING-ZSTD-HEAD-SIGNATURE/v1\x00"
)

type SessionRecordingHash [32]byte

func (this SessionRecordingHash) IsZero() bool {
	return this == SessionRecordingHash{}
}

type SessionRecordingZstdHeader struct {
	FormatVersion uint8
	CastVersion   uint8
	Codec         uint8
	RecordingId   uuid.UUID
	ProducerId    ProducerId
	PublicKey     []byte
	Signature     []byte
}

type SessionRecordingZstdChunk struct {
	FormatVersion    uint8
	RecordingId      uuid.UUID
	ProducerId       ProducerId
	Sequence         uint64
	PreviousUnitHash SessionRecordingHash
	PlaintextOffset  uint64
	PlaintextLength  uint32
	FrameLength      uint32
	FrameHash        SessionRecordingHash
	Signature        []byte
}

type SessionRecordingZstdSeal struct {
	FormatVersion     uint8
	RecordingId       uuid.UUID
	ProducerId        ProducerId
	Status            uint8
	ChunkCount        uint64
	CastBytes         uint64
	ZstdBytes         uint64
	PrefixBytes       uint64
	HeaderUnitHash    SessionRecordingHash
	LastChunkUnitHash SessionRecordingHash
	CastContentDigest SessionRecordingHash
	CastStreamHash    SessionRecordingHash
	Signature         []byte
}

type SessionRecordingZstdHead struct {
	FormatVersion uint8
	RecordingId   uuid.UUID
	ProducerId    ProducerId
	ChunkCount    uint64
	PrefixBytes   uint64
	LastUnitHash  SessionRecordingHash
	Signature     []byte
}

func (this *Identity) NewSessionRecordingZstdHeader(formatVersion, castVersion, codec uint8, recordingId uuid.UUID) (SessionRecordingZstdHeader, error) {
	if this == nil || this.PublicKey() == nil {
		return SessionRecordingZstdHeader{}, errors.System.Newf("nil audit identity signer")
	}
	value := SessionRecordingZstdHeader{
		FormatVersion: formatVersion,
		CastVersion:   castVersion,
		Codec:         codec,
		RecordingId:   recordingId,
		ProducerId:    this.ProducerId(),
		PublicKey:     this.PublicKey().Marshal(),
	}
	if err := validateSessionRecordingZstdHeader(value); err != nil {
		return SessionRecordingZstdHeader{}, err
	}
	unsigned := marshalSessionRecordingZstdHeader(value)
	signature, err := this.sign(append([]byte(sessionRecordingZstdHeaderSignatureDomain), unsigned...))
	if err != nil {
		return SessionRecordingZstdHeader{}, err
	}
	value.Signature = signature
	return value, nil
}

func VerifySessionRecordingZstdHeader(value SessionRecordingZstdHeader) (bfcrypto.PublicKey, error) {
	if err := validateSessionRecordingZstdHeader(value); err != nil {
		return nil, err
	}
	publicKey, err := bfcrypto.ParsePublicKeyBytes(value.PublicKey)
	if err != nil {
		return nil, errors.System.Newf("cannot parse session recording Zstandard public key: %w", err)
	}
	if newProducerId(publicKey.Marshal()) != value.ProducerId {
		return nil, errors.System.Newf("session recording Zstandard public key does not match its producer ID")
	}
	unsigned := marshalSessionRecordingZstdHeader(value)
	if err := verifySessionRecordingSignature(publicKey, sessionRecordingZstdHeaderSignatureDomain, unsigned, value.Signature); err != nil {
		return nil, err
	}
	return publicKey, nil
}

func (this *Identity) NewSessionRecordingZstdChunk(value SessionRecordingZstdChunk) (SessionRecordingZstdChunk, error) {
	if this == nil {
		return SessionRecordingZstdChunk{}, errors.System.Newf("nil audit identity signer")
	}
	value.ProducerId = this.ProducerId()
	if err := validateSessionRecordingZstdChunk(value); err != nil {
		return SessionRecordingZstdChunk{}, err
	}
	unsigned := marshalSessionRecordingZstdChunk(value)
	signature, err := this.sign(append([]byte(sessionRecordingZstdChunkSignatureDomain), unsigned...))
	if err != nil {
		return SessionRecordingZstdChunk{}, err
	}
	value.Signature = signature
	return value, nil
}

func VerifySessionRecordingZstdChunk(publicKey bfcrypto.PublicKey, value SessionRecordingZstdChunk) error {
	if err := validateSessionRecordingZstdChunk(value); err != nil {
		return err
	}
	if publicKey == nil || newProducerId(publicKey.Marshal()) != value.ProducerId {
		return errors.System.Newf("session recording Zstandard chunk has an invalid producer key")
	}
	return verifySessionRecordingSignature(publicKey, sessionRecordingZstdChunkSignatureDomain, marshalSessionRecordingZstdChunk(value), value.Signature)
}

func (this *Identity) NewSessionRecordingZstdSeal(value SessionRecordingZstdSeal) (SessionRecordingZstdSeal, error) {
	if this == nil {
		return SessionRecordingZstdSeal{}, errors.System.Newf("nil audit identity signer")
	}
	value.ProducerId = this.ProducerId()
	if err := validateSessionRecordingZstdSeal(value); err != nil {
		return SessionRecordingZstdSeal{}, err
	}
	unsigned := marshalSessionRecordingZstdSeal(value)
	signature, err := this.sign(append([]byte(sessionRecordingZstdSealSignatureDomain), unsigned...))
	if err != nil {
		return SessionRecordingZstdSeal{}, err
	}
	value.Signature = signature
	return value, nil
}

func VerifySessionRecordingZstdSeal(publicKey bfcrypto.PublicKey, value SessionRecordingZstdSeal) error {
	if err := validateSessionRecordingZstdSeal(value); err != nil {
		return err
	}
	if publicKey == nil || newProducerId(publicKey.Marshal()) != value.ProducerId {
		return errors.System.Newf("session recording Zstandard seal has an invalid producer key")
	}
	return verifySessionRecordingSignature(publicKey, sessionRecordingZstdSealSignatureDomain, marshalSessionRecordingZstdSeal(value), value.Signature)
}

func (this *Identity) NewSessionRecordingZstdHead(value SessionRecordingZstdHead) (SessionRecordingZstdHead, error) {
	if this == nil {
		return SessionRecordingZstdHead{}, errors.System.Newf("nil audit identity signer")
	}
	value.ProducerId = this.ProducerId()
	if err := validateSessionRecordingZstdHead(value); err != nil {
		return SessionRecordingZstdHead{}, err
	}
	unsigned := marshalSessionRecordingZstdHead(value)
	signature, err := this.sign(append([]byte(sessionRecordingZstdHeadSignatureDomain), unsigned...))
	if err != nil {
		return SessionRecordingZstdHead{}, err
	}
	value.Signature = signature
	return value, nil
}

func VerifySessionRecordingZstdHead(publicKey bfcrypto.PublicKey, value SessionRecordingZstdHead) error {
	if err := validateSessionRecordingZstdHead(value); err != nil {
		return err
	}
	if publicKey == nil || newProducerId(publicKey.Marshal()) != value.ProducerId {
		return errors.System.Newf("session recording Zstandard head has an invalid producer key")
	}
	return verifySessionRecordingSignature(publicKey, sessionRecordingZstdHeadSignatureDomain, marshalSessionRecordingZstdHead(value), value.Signature)
}

func validateSessionRecordingZstdHeader(value SessionRecordingZstdHeader) error {
	if value.FormatVersion == 0 || value.CastVersion == 0 || value.Codec == 0 {
		return errors.System.Newf("session recording Zstandard header contains an empty version or codec")
	}
	if err := validateSessionRecordingUuid(value.RecordingId); err != nil {
		return err
	}
	if value.ProducerId.IsZero() || len(value.PublicKey) == 0 {
		return errors.System.Newf("session recording Zstandard header contains an empty identity")
	}
	return nil
}

func validateSessionRecordingZstdChunk(value SessionRecordingZstdChunk) error {
	if value.FormatVersion == 0 || value.Sequence == 0 || value.ProducerId.IsZero() || value.PreviousUnitHash.IsZero() || value.FrameHash.IsZero() {
		return errors.System.Newf("session recording Zstandard chunk contains empty metadata")
	}
	if err := validateSessionRecordingUuid(value.RecordingId); err != nil {
		return err
	}
	if value.PlaintextLength == 0 || value.FrameLength == 0 {
		return errors.System.Newf("session recording Zstandard chunk contains an empty frame")
	}
	return nil
}

func validateSessionRecordingZstdSeal(value SessionRecordingZstdSeal) error {
	if value.FormatVersion == 0 || value.Status == 0 || value.ChunkCount == 0 || value.CastBytes == 0 || value.ZstdBytes == 0 || value.PrefixBytes == 0 || value.ProducerId.IsZero() {
		return errors.System.Newf("session recording Zstandard seal contains empty metadata")
	}
	if err := validateSessionRecordingUuid(value.RecordingId); err != nil {
		return err
	}
	if value.HeaderUnitHash.IsZero() || value.LastChunkUnitHash.IsZero() || value.CastContentDigest.IsZero() || value.CastStreamHash.IsZero() {
		return errors.System.Newf("session recording Zstandard seal contains an empty hash")
	}
	return nil
}

func validateSessionRecordingZstdHead(value SessionRecordingZstdHead) error {
	if value.FormatVersion == 0 || value.ProducerId.IsZero() || value.ChunkCount == 0 || value.PrefixBytes == 0 || value.LastUnitHash.IsZero() {
		return errors.System.Newf("session recording Zstandard head contains empty metadata")
	}
	return validateSessionRecordingUuid(value.RecordingId)
}

func validateSessionRecordingUuid(value uuid.UUID) error {
	if value == uuid.Nil || value.Version() != 4 || value.Variant() != uuid.RFC4122 {
		return errors.System.Newf("illegal session recording ID %q", value)
	}
	return nil
}

func marshalSessionRecordingZstdHeader(value SessionRecordingZstdHeader) []byte {
	result := make([]byte, 0, 3+len(value.RecordingId)+len(value.ProducerId)+len(value.PublicKey))
	result = append(result, value.FormatVersion, value.CastVersion, value.Codec)
	result = append(result, value.RecordingId[:]...)
	result = append(result, value.ProducerId[:]...)
	return append(result, value.PublicKey...)
}

func marshalSessionRecordingZstdChunk(value SessionRecordingZstdChunk) []byte {
	result := make([]byte, 1+len(value.RecordingId)+len(value.ProducerId)+8+32+8+4+4+32)
	result[0] = value.FormatVersion
	copy(result[1:], value.RecordingId[:])
	copy(result[17:], value.ProducerId[:])
	binary.BigEndian.PutUint64(result[49:], value.Sequence)
	copy(result[57:], value.PreviousUnitHash[:])
	binary.BigEndian.PutUint64(result[89:], value.PlaintextOffset)
	binary.BigEndian.PutUint32(result[97:], value.PlaintextLength)
	binary.BigEndian.PutUint32(result[101:], value.FrameLength)
	copy(result[105:], value.FrameHash[:])
	return result
}

func marshalSessionRecordingZstdSeal(value SessionRecordingZstdSeal) []byte {
	result := make([]byte, 1+len(value.RecordingId)+len(value.ProducerId)+1+8+8+8+8+32+32+32+32)
	result[0] = value.FormatVersion
	copy(result[1:], value.RecordingId[:])
	copy(result[17:], value.ProducerId[:])
	result[49] = value.Status
	binary.BigEndian.PutUint64(result[50:], value.ChunkCount)
	binary.BigEndian.PutUint64(result[58:], value.CastBytes)
	binary.BigEndian.PutUint64(result[66:], value.ZstdBytes)
	binary.BigEndian.PutUint64(result[74:], value.PrefixBytes)
	copy(result[82:], value.HeaderUnitHash[:])
	copy(result[114:], value.LastChunkUnitHash[:])
	copy(result[146:], value.CastContentDigest[:])
	copy(result[178:], value.CastStreamHash[:])
	return result
}

func marshalSessionRecordingZstdHead(value SessionRecordingZstdHead) []byte {
	result := make([]byte, 1+len(value.RecordingId)+len(value.ProducerId)+8+8+32)
	result[0] = value.FormatVersion
	copy(result[1:], value.RecordingId[:])
	copy(result[17:], value.ProducerId[:])
	binary.BigEndian.PutUint64(result[49:], value.ChunkCount)
	binary.BigEndian.PutUint64(result[57:], value.PrefixBytes)
	copy(result[65:], value.LastUnitHash[:])
	return result
}

func verifySessionRecordingSignature(publicKey bfcrypto.PublicKey, domain string, payload, signature []byte) error {
	if publicKey == nil {
		return errors.System.Newf("nil session recording public key")
	}
	ed25519PublicKey, ok := publicKey.ToSdk().(ed25519.PublicKey)
	if !ok || len(ed25519PublicKey) != ed25519.PublicKeySize {
		return errors.System.Newf("session recording public key is not Ed25519")
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519PublicKey, append([]byte(domain), payload...), signature) {
		return errors.System.Newf("illegal session recording signature")
	}
	return nil
}
