package audit

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

const (
	nativeRecordingHeaderSignatureDomain = "BIFROEST-BCAST-HEADER-SIGNATURE/v1\x00"
	nativeRecordingChunkSignatureDomain  = "BIFROEST-BCAST-CHUNK-SIGNATURE/v1\x00"
	nativeRecordingSealSignatureDomain   = "BIFROEST-BCAST-SEAL-SIGNATURE/v1\x00"
	nativeRecordingHeadSignatureDomain   = "BIFROEST-BCAST-HEAD-SIGNATURE/v1\x00"
)

// The four content types encode exactly the unsigned CBOR wire maps. Keep
// these key assignments in sync with pkg/recording/native-wire.go.
type NativeRecordingHeaderContent struct {
	Version     uint8                  `cbor:"1,keyasint"`
	Encryption  uint8                  `cbor:"2,keyasint"`
	RecordingId [16]byte               `cbor:"3,keyasint"`
	ProducerId  [32]byte               `cbor:"4,keyasint"`
	PublicKey   []byte                 `cbor:"5,keyasint"`
	StartedAt   nativeformat.Timestamp `cbor:"6,keyasint"`
	Recipient   string                 `cbor:"7,keyasint,omitempty"`
}

type NativeRecordingChunkContent struct {
	Sequence         uint64                  `cbor:"1,keyasint"`
	PreviousUnitHash [32]byte                `cbor:"2,keyasint"`
	DecodedLength    uint32                  `cbor:"3,keyasint"`
	StoredPayload    []byte                  `cbor:"4,keyasint"`
	StoredHash       [32]byte                `cbor:"5,keyasint"`
	CastHashState    [32]byte                `cbor:"6,keyasint"`
	CastHashBytes    uint64                  `cbor:"7,keyasint"`
	FinalStatus      uint8                   `cbor:"9,keyasint,omitempty"`
	CastDigest       *[32]byte               `cbor:"10,keyasint,omitempty"`
	CastSignature    []byte                  `cbor:"11,keyasint,omitempty"`
	CastBytes        *uint64                 `cbor:"12,keyasint,omitempty"`
	EndedAt          *nativeformat.Timestamp `cbor:"13,keyasint,omitempty"`
	LastElapsedNanos *uint64                 `cbor:"14,keyasint,omitempty"`
}

type NativeRecordingSealContent struct {
	Status        uint8                  `cbor:"1,keyasint"`
	ChunkCount    uint64                 `cbor:"2,keyasint"`
	LastUnitHash  [32]byte               `cbor:"3,keyasint"`
	ContentHash   [32]byte               `cbor:"4,keyasint"`
	CastDigest    [32]byte               `cbor:"5,keyasint"`
	CastSignature []byte                 `cbor:"6,keyasint"`
	CastBytes     uint64                 `cbor:"7,keyasint"`
	EndedAt       nativeformat.Timestamp `cbor:"8,keyasint"`
}

type NativeRecordingHeadContent struct {
	Version       uint8    `cbor:"1,keyasint"`
	RecordingId   [16]byte `cbor:"2,keyasint"`
	ProducerId    [32]byte `cbor:"3,keyasint"`
	PrefixBytes   uint64   `cbor:"4,keyasint"`
	ChunkCount    uint64   `cbor:"5,keyasint"`
	LastUnitHash  [32]byte `cbor:"6,keyasint"`
	CastHashState [32]byte `cbor:"7,keyasint"`
	CastHashBytes uint64   `cbor:"8,keyasint"`
}

func (this *Identity) SignNativeRecordingHeader(value NativeRecordingHeaderContent) ([]byte, error) {
	if this == nil || this.PublicKey() == nil || value.Version != 1 || value.ProducerId != [32]byte(this.ProducerId()) || !bytes.Equal(value.PublicKey, this.PublicKey().Marshal()) || value.Encryption > 1 || (value.Encryption == 1) != (value.Recipient != "") {
		return nil, fmt.Errorf("native recording header does not match signing identity or mode")
	}
	return this.signNativeRecordingContent(nativeRecordingHeaderSignatureDomain, value, nativeformat.MaxMetadataPayload)
}

func (this *Identity) SignNativeRecordingChunk(value NativeRecordingChunkContent) ([]byte, error) {
	if value.Sequence == 0 || value.DecodedLength == 0 || value.DecodedLength > nativeformat.MaxRecordingDecodedChunk || len(value.StoredPayload) == 0 || len(value.StoredPayload) > nativeformat.MaxRecordingChunkPayload-256 || value.StoredHash != sha256.Sum256(value.StoredPayload) {
		return nil, fmt.Errorf("invalid native recording chunk signature content")
	}
	if value.CastHashBytes == 0 {
		if value.FinalStatus < 1 || value.FinalStatus > 3 || value.CastDigest == nil || value.CastHashState != *value.CastDigest || len(value.CastSignature) != 64 || value.CastBytes == nil || *value.CastBytes == 0 || value.EndedAt == nil || value.LastElapsedNanos != nil {
			return nil, fmt.Errorf("invalid native recording final chunk signature content")
		}
		if ended, err := value.EndedAt.Time(); err != nil || ended.IsZero() {
			return nil, fmt.Errorf("invalid native recording final chunk end time")
		}
	} else if value.CastHashBytes%sha256.BlockSize != 0 || value.FinalStatus != 0 || value.CastDigest != nil || len(value.CastSignature) != 0 || value.CastBytes != nil || value.EndedAt != nil || value.LastElapsedNanos == nil {
		return nil, fmt.Errorf("invalid native recording continuation signature content")
	}
	return this.signNativeRecordingContent(nativeRecordingChunkSignatureDomain, value, nativeformat.MaxRecordingChunkPayload)
}

func (this *Identity) SignNativeRecordingSeal(value NativeRecordingSealContent) ([]byte, error) {
	if value.Status < 1 || value.Status > 3 || value.ChunkCount == 0 || value.CastBytes == 0 || len(value.CastSignature) != 64 || value.EndedAt.Nanoseconds >= 1e9 {
		return nil, fmt.Errorf("invalid native recording seal signature content")
	}
	return this.signNativeRecordingContent(nativeRecordingSealSignatureDomain, value, nativeformat.MaxMetadataPayload)
}

func (this *Identity) SignNativeRecordingHead(value NativeRecordingHeadContent) ([]byte, error) {
	if this == nil || value.Version != 1 || value.ProducerId != [32]byte(this.ProducerId()) || value.ChunkCount == 0 || value.PrefixBytes <= uint64(len(nativeformat.RecordingMagic)) || value.CastHashBytes == 0 || value.CastHashBytes%sha256.BlockSize != 0 {
		return nil, fmt.Errorf("invalid native recording head signature content")
	}
	return this.signNativeRecordingContent(nativeRecordingHeadSignatureDomain, value, nativeformat.MaxMetadataPayload)
}

func (this *Identity) signNativeRecordingContent(domain string, value any, maximum int) ([]byte, error) {
	encoded, err := nativeformat.Marshal(value, maximum)
	if err != nil {
		return nil, err
	}
	return this.sign(append([]byte(domain), encoded...))
}
