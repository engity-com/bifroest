package recording

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

type nativeRecordingHeader struct {
	Version     uint8                  `cbor:"1,keyasint"`
	Encryption  uint8                  `cbor:"2,keyasint"`
	RecordingId [16]byte               `cbor:"3,keyasint"`
	ProducerId  [32]byte               `cbor:"4,keyasint"`
	PublicKey   []byte                 `cbor:"5,keyasint"`
	StartedAt   nativeformat.Timestamp `cbor:"6,keyasint"`
	Recipient   string                 `cbor:"7,keyasint,omitempty"`
	Signature   []byte                 `cbor:"8,keyasint"`
}

type nativeRecordingChunk struct {
	Sequence         uint64                  `cbor:"1,keyasint"`
	PreviousUnitHash [32]byte                `cbor:"2,keyasint"`
	DecodedLength    uint32                  `cbor:"3,keyasint"`
	StoredPayload    []byte                  `cbor:"4,keyasint"`
	StoredHash       [32]byte                `cbor:"5,keyasint"`
	CastHashState    [32]byte                `cbor:"6,keyasint"`
	CastHashBytes    uint64                  `cbor:"7,keyasint"`
	Signature        []byte                  `cbor:"8,keyasint"`
	FinalStatus      uint8                   `cbor:"9,keyasint,omitempty"`
	CastDigest       *[32]byte               `cbor:"10,keyasint,omitempty"`
	CastSignature    []byte                  `cbor:"11,keyasint,omitempty"`
	CastBytes        *uint64                 `cbor:"12,keyasint,omitempty"`
	EndedAt          *nativeformat.Timestamp `cbor:"13,keyasint,omitempty"`
	LastElapsedNanos *uint64                 `cbor:"14,keyasint,omitempty"`
}

func (this nativeRecordingChunk) ValidateNativeWire() error {
	if this.DecodedLength == 0 || this.DecodedLength > nativeformat.MaxRecordingDecodedChunk {
		return fmt.Errorf("native recording chunk has invalid decoded length %d", this.DecodedLength)
	}
	if this.CastHashBytes == 0 {
		if this.FinalStatus < 1 || this.FinalStatus > 3 || this.CastDigest == nil || this.CastHashState != *this.CastDigest || len(this.CastSignature) != 64 || this.CastBytes == nil || *this.CastBytes == 0 || this.EndedAt == nil || this.LastElapsedNanos != nil {
			return fmt.Errorf("native recording final chunk has invalid signed Cast commitment")
		}
		if ended, err := this.EndedAt.Time(); err != nil || ended.IsZero() {
			return fmt.Errorf("native recording final chunk has invalid end time")
		}
	} else if this.CastHashBytes%64 != 0 || this.FinalStatus != 0 || this.CastDigest != nil || len(this.CastSignature) != 0 || this.CastBytes != nil || this.EndedAt != nil || this.LastElapsedNanos == nil || *this.LastElapsedNanos > uint64(maximumEventElapsed) {
		return fmt.Errorf("native recording continuation chunk contains final data or invalid Cast hash state")
	}
	return nil
}

type nativeRecordingSeal struct {
	Status        uint8                  `cbor:"1,keyasint"`
	ChunkCount    uint64                 `cbor:"2,keyasint"`
	LastUnitHash  [32]byte               `cbor:"3,keyasint"`
	ContentHash   [32]byte               `cbor:"4,keyasint"`
	CastDigest    [32]byte               `cbor:"5,keyasint"`
	CastSignature []byte                 `cbor:"6,keyasint"`
	CastBytes     uint64                 `cbor:"7,keyasint"`
	EndedAt       nativeformat.Timestamp `cbor:"8,keyasint"`
	Signature     []byte                 `cbor:"9,keyasint"`
}
