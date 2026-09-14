package audit

import (
	"encoding/base64"
	"encoding/binary"
	"strings"

	"github.com/google/uuid"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	sessionRecordingBECastHeaderSignatureDomain = "BIFROEST-SESSION-RECORDING-BECAST-HEADER-SIGNATURE/v1\x00"
	sessionRecordingBECastChunkSignatureDomain  = "BIFROEST-SESSION-RECORDING-BECAST-CHUNK-SIGNATURE/v1\x00"
	sessionRecordingBECastSealSignatureDomain   = "BIFROEST-SESSION-RECORDING-BECAST-SEAL-SIGNATURE/v1\x00"
	sessionRecordingBECastHeadSignatureDomain   = "BIFROEST-SESSION-RECORDING-BECAST-HEAD-SIGNATURE/v1\x00"
)

type SessionRecordingBECastHeader struct {
	FormatVersion        uint8
	CastVersion          uint8
	Codec                uint8
	Encryption           uint8
	RecordingId          uuid.UUID
	ProducerId           ProducerId
	PublicKey            []byte
	RecipientFingerprint string
	Signature            []byte
}

type SessionRecordingBECastChunk struct {
	FormatVersion    uint8
	RecordingId      uuid.UUID
	ProducerId       ProducerId
	Sequence         uint64
	PreviousUnitHash SessionRecordingHash
	PlaintextOffset  uint64
	PlaintextLength  uint32
	CiphertextLength uint32
	CiphertextHash   SessionRecordingHash
	ContentHashState SessionRecordingHash
	ContentHashBytes uint64
	Signature        []byte
}

type SessionRecordingBECastSeal struct {
	FormatVersion        uint8
	RecordingId          uuid.UUID
	ProducerId           ProducerId
	Status               uint8
	ChunkCount           uint64
	CastBytes            uint64
	CiphertextBytes      uint64
	PrefixBytes          uint64
	HeaderUnitHash       SessionRecordingHash
	LastChunkUnitHash    SessionRecordingHash
	CastContentDigest    SessionRecordingHash
	CiphertextStreamHash SessionRecordingHash
	Signature            []byte
}

type SessionRecordingBECastHead struct {
	FormatVersion    uint8
	RecordingId      uuid.UUID
	ProducerId       ProducerId
	ChunkCount       uint64
	PrefixBytes      uint64
	LastUnitHash     SessionRecordingHash
	ContentHashState SessionRecordingHash
	ContentHashBytes uint64
	Signature        []byte
}

func (this *Identity) NewSessionRecordingBECastHeader(formatVersion, castVersion, codec, encryption uint8, recordingId uuid.UUID, recipientFingerprint string) (SessionRecordingBECastHeader, error) {
	if this == nil || this.PublicKey() == nil {
		return SessionRecordingBECastHeader{}, errors.System.Newf("nil audit identity signer")
	}
	value := SessionRecordingBECastHeader{
		FormatVersion:        formatVersion,
		CastVersion:          castVersion,
		Codec:                codec,
		Encryption:           encryption,
		RecordingId:          recordingId,
		ProducerId:           this.ProducerId(),
		PublicKey:            this.PublicKey().Marshal(),
		RecipientFingerprint: recipientFingerprint,
	}
	if err := validateSessionRecordingBECastHeader(value); err != nil {
		return SessionRecordingBECastHeader{}, err
	}
	unsigned := marshalSessionRecordingBECastHeader(value)
	signature, err := this.sign(append([]byte(sessionRecordingBECastHeaderSignatureDomain), unsigned...))
	if err != nil {
		return SessionRecordingBECastHeader{}, err
	}
	value.Signature = signature
	return value, nil
}

func VerifySessionRecordingBECastHeader(value SessionRecordingBECastHeader) (bfcrypto.PublicKey, error) {
	if err := validateSessionRecordingBECastHeader(value); err != nil {
		return nil, err
	}
	publicKey, err := bfcrypto.ParsePublicKeyBytes(value.PublicKey)
	if err != nil {
		return nil, errors.System.Newf("cannot parse session recording BECast public key: %w", err)
	}
	if newProducerId(publicKey.Marshal()) != value.ProducerId {
		return nil, errors.System.Newf("session recording BECast public key does not match its producer ID")
	}
	unsigned := marshalSessionRecordingBECastHeader(value)
	if err := verifySessionRecordingSignature(publicKey, sessionRecordingBECastHeaderSignatureDomain, unsigned, value.Signature); err != nil {
		return nil, err
	}
	return publicKey, nil
}

func (this *Identity) NewSessionRecordingBECastChunk(value SessionRecordingBECastChunk) (SessionRecordingBECastChunk, error) {
	if this == nil {
		return SessionRecordingBECastChunk{}, errors.System.Newf("nil audit identity signer")
	}
	value.ProducerId = this.ProducerId()
	if err := validateSessionRecordingBECastChunk(value); err != nil {
		return SessionRecordingBECastChunk{}, err
	}
	unsigned := marshalSessionRecordingBECastChunk(value)
	signature, err := this.sign(append([]byte(sessionRecordingBECastChunkSignatureDomain), unsigned...))
	if err != nil {
		return SessionRecordingBECastChunk{}, err
	}
	value.Signature = signature
	return value, nil
}

func VerifySessionRecordingBECastChunk(publicKey bfcrypto.PublicKey, value SessionRecordingBECastChunk) error {
	if err := validateSessionRecordingBECastChunk(value); err != nil {
		return err
	}
	if publicKey == nil || newProducerId(publicKey.Marshal()) != value.ProducerId {
		return errors.System.Newf("session recording BECast chunk has an invalid producer key")
	}
	return verifySessionRecordingSignature(publicKey, sessionRecordingBECastChunkSignatureDomain, marshalSessionRecordingBECastChunk(value), value.Signature)
}

func (this *Identity) NewSessionRecordingBECastSeal(value SessionRecordingBECastSeal) (SessionRecordingBECastSeal, error) {
	if this == nil {
		return SessionRecordingBECastSeal{}, errors.System.Newf("nil audit identity signer")
	}
	value.ProducerId = this.ProducerId()
	if err := validateSessionRecordingBECastSeal(value); err != nil {
		return SessionRecordingBECastSeal{}, err
	}
	unsigned := marshalSessionRecordingBECastSeal(value)
	signature, err := this.sign(append([]byte(sessionRecordingBECastSealSignatureDomain), unsigned...))
	if err != nil {
		return SessionRecordingBECastSeal{}, err
	}
	value.Signature = signature
	return value, nil
}

func VerifySessionRecordingBECastSeal(publicKey bfcrypto.PublicKey, value SessionRecordingBECastSeal) error {
	if err := validateSessionRecordingBECastSeal(value); err != nil {
		return err
	}
	if publicKey == nil || newProducerId(publicKey.Marshal()) != value.ProducerId {
		return errors.System.Newf("session recording BECast seal has an invalid producer key")
	}
	return verifySessionRecordingSignature(publicKey, sessionRecordingBECastSealSignatureDomain, marshalSessionRecordingBECastSeal(value), value.Signature)
}

func (this *Identity) NewSessionRecordingBECastHead(value SessionRecordingBECastHead) (SessionRecordingBECastHead, error) {
	if this == nil {
		return SessionRecordingBECastHead{}, errors.System.Newf("nil audit identity signer")
	}
	value.ProducerId = this.ProducerId()
	if err := validateSessionRecordingBECastHead(value); err != nil {
		return SessionRecordingBECastHead{}, err
	}
	unsigned := marshalSessionRecordingBECastHead(value)
	signature, err := this.sign(append([]byte(sessionRecordingBECastHeadSignatureDomain), unsigned...))
	if err != nil {
		return SessionRecordingBECastHead{}, err
	}
	value.Signature = signature
	return value, nil
}

func VerifySessionRecordingBECastHead(publicKey bfcrypto.PublicKey, value SessionRecordingBECastHead) error {
	if err := validateSessionRecordingBECastHead(value); err != nil {
		return err
	}
	if publicKey == nil || newProducerId(publicKey.Marshal()) != value.ProducerId {
		return errors.System.Newf("session recording BECast head has an invalid producer key")
	}
	return verifySessionRecordingSignature(publicKey, sessionRecordingBECastHeadSignatureDomain, marshalSessionRecordingBECastHead(value), value.Signature)
}

func validateSessionRecordingBECastHeader(value SessionRecordingBECastHeader) error {
	if value.FormatVersion == 0 || value.CastVersion == 0 || value.Codec == 0 || value.Encryption == 0 {
		return errors.System.Newf("session recording BECast header contains an empty version, codec, or encryption")
	}
	if err := validateSessionRecordingUuid(value.RecordingId); err != nil {
		return err
	}
	if value.ProducerId.IsZero() || len(value.PublicKey) == 0 {
		return errors.System.Newf("session recording BECast header contains an empty identity")
	}
	return validateSessionRecordingBECastRecipientFingerprint(value.RecipientFingerprint)
}

func validateSessionRecordingBECastChunk(value SessionRecordingBECastChunk) error {
	if value.FormatVersion == 0 || value.Sequence == 0 || value.ProducerId.IsZero() || value.PreviousUnitHash.IsZero() || value.CiphertextHash.IsZero() || value.ContentHashBytes == 0 {
		return errors.System.Newf("session recording BECast chunk contains empty metadata")
	}
	if err := validateSessionRecordingUuid(value.RecordingId); err != nil {
		return err
	}
	if value.PlaintextLength == 0 || value.CiphertextLength == 0 {
		return errors.System.Newf("session recording BECast chunk contains an empty ciphertext")
	}
	if value.ContentHashBytes%64 != 0 {
		return errors.System.Newf("session recording BECast chunk content hash byte count is not aligned to 64 bytes")
	}
	return nil
}

func validateSessionRecordingBECastSeal(value SessionRecordingBECastSeal) error {
	if value.FormatVersion == 0 || value.Status == 0 || value.ChunkCount == 0 || value.CastBytes == 0 || value.CiphertextBytes == 0 || value.PrefixBytes == 0 || value.ProducerId.IsZero() {
		return errors.System.Newf("session recording BECast seal contains empty metadata")
	}
	if err := validateSessionRecordingUuid(value.RecordingId); err != nil {
		return err
	}
	if value.HeaderUnitHash.IsZero() || value.LastChunkUnitHash.IsZero() || value.CastContentDigest.IsZero() || value.CiphertextStreamHash.IsZero() {
		return errors.System.Newf("session recording BECast seal contains an empty hash")
	}
	return nil
}

func validateSessionRecordingBECastHead(value SessionRecordingBECastHead) error {
	if value.FormatVersion == 0 || value.ProducerId.IsZero() || value.ChunkCount == 0 || value.PrefixBytes == 0 || value.LastUnitHash.IsZero() || value.ContentHashBytes == 0 {
		return errors.System.Newf("session recording BECast head contains empty metadata")
	}
	if err := validateSessionRecordingUuid(value.RecordingId); err != nil {
		return err
	}
	if value.ContentHashBytes%64 != 0 {
		return errors.System.Newf("session recording BECast head content hash byte count is not aligned to 64 bytes")
	}
	return nil
}

func validateSessionRecordingBECastRecipientFingerprint(value string) error {
	const prefix = "SHA256:"
	if len(value) != len(prefix)+43 || !strings.HasPrefix(value, prefix) {
		return errors.System.Newf("illegal session recording BECast recipient fingerprint %q", value)
	}
	decoded, err := base64.RawStdEncoding.Strict().DecodeString(value[len(prefix):])
	if err != nil || len(decoded) != 32 {
		return errors.System.Newf("illegal session recording BECast recipient fingerprint %q", value)
	}
	return nil
}

func marshalSessionRecordingBECastHeader(value SessionRecordingBECastHeader) []byte {
	result := make([]byte, 0, 4+len(value.RecordingId)+len(value.ProducerId)+len(value.PublicKey)+len(value.RecipientFingerprint))
	result = append(result, value.FormatVersion, value.CastVersion, value.Codec, value.Encryption)
	result = append(result, value.RecordingId[:]...)
	result = append(result, value.ProducerId[:]...)
	result = append(result, value.PublicKey...)
	return append(result, value.RecipientFingerprint...)
}

func marshalSessionRecordingBECastChunk(value SessionRecordingBECastChunk) []byte {
	result := make([]byte, 1+len(value.RecordingId)+len(value.ProducerId)+8+32+8+4+4+32+32+8)
	result[0] = value.FormatVersion
	copy(result[1:], value.RecordingId[:])
	copy(result[17:], value.ProducerId[:])
	binary.BigEndian.PutUint64(result[49:], value.Sequence)
	copy(result[57:], value.PreviousUnitHash[:])
	binary.BigEndian.PutUint64(result[89:], value.PlaintextOffset)
	binary.BigEndian.PutUint32(result[97:], value.PlaintextLength)
	binary.BigEndian.PutUint32(result[101:], value.CiphertextLength)
	copy(result[105:], value.CiphertextHash[:])
	copy(result[137:], value.ContentHashState[:])
	binary.BigEndian.PutUint64(result[169:], value.ContentHashBytes)
	return result
}

func marshalSessionRecordingBECastSeal(value SessionRecordingBECastSeal) []byte {
	result := make([]byte, 1+len(value.RecordingId)+len(value.ProducerId)+1+8+8+8+8+32+32+32+32)
	result[0] = value.FormatVersion
	copy(result[1:], value.RecordingId[:])
	copy(result[17:], value.ProducerId[:])
	result[49] = value.Status
	binary.BigEndian.PutUint64(result[50:], value.ChunkCount)
	binary.BigEndian.PutUint64(result[58:], value.CastBytes)
	binary.BigEndian.PutUint64(result[66:], value.CiphertextBytes)
	binary.BigEndian.PutUint64(result[74:], value.PrefixBytes)
	copy(result[82:], value.HeaderUnitHash[:])
	copy(result[114:], value.LastChunkUnitHash[:])
	copy(result[146:], value.CastContentDigest[:])
	copy(result[178:], value.CiphertextStreamHash[:])
	return result
}

func marshalSessionRecordingBECastHead(value SessionRecordingBECastHead) []byte {
	result := make([]byte, 1+len(value.RecordingId)+len(value.ProducerId)+8+8+32+32+8)
	result[0] = value.FormatVersion
	copy(result[1:], value.RecordingId[:])
	copy(result[17:], value.ProducerId[:])
	binary.BigEndian.PutUint64(result[49:], value.ChunkCount)
	binary.BigEndian.PutUint64(result[57:], value.PrefixBytes)
	copy(result[65:], value.LastUnitHash[:])
	copy(result[97:], value.ContentHashState[:])
	binary.BigEndian.PutUint64(result[129:], value.ContentHashBytes)
	return result
}
