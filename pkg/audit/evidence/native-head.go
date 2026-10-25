package evidence

import (
	"bytes"
	"fmt"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

const nativeAuditHeadSignatureDomain = "BIFROEST-BAUDIT-HEAD-SIGNATURE/v1\x00"

// The head is a separate signed checkpoint, never an event-data source.
type nativeAuditHead struct {
	Version        uint8    `cbor:"1,keyasint"`
	ProducerId     [32]byte `cbor:"2,keyasint"`
	PublicKey      []byte   `cbor:"3,keyasint"`
	LastRecordHash [32]byte `cbor:"4,keyasint"`
	Signature      []byte   `cbor:"5,keyasint"`
}

func nativeAuditHeadFields(h nativeAuditHead) map[uint64]any {
	return map[uint64]any{1: h.Version, 2: h.ProducerId, 3: h.PublicKey, 4: h.LastRecordHash}
}

func decodeNativeAuditHead(payload []byte, identity JournalIdentity) (nativeAuditHead, error) {
	h, err := nativeformat.Unmarshal[nativeAuditHead](payload, nativeformat.MaxMetadataPayload)
	if err != nil {
		return nativeAuditHead{}, err
	}
	if identity == nil || h.Version != 1 || h.ProducerId != [32]byte(identity.ProducerId()) || !bytes.Equal(h.PublicKey, identity.PublicKeyBytes()) {
		return nativeAuditHead{}, fmt.Errorf("native audit head identity mismatch")
	}
	unsigned, err := nativeformat.Marshal(nativeAuditHeadFields(h), nativeformat.MaxMetadataPayload)
	if err != nil {
		return nativeAuditHead{}, err
	}
	if err := identity.VerifySignature(append([]byte(nativeAuditHeadSignatureDomain), unsigned...), h.Signature); err != nil {
		return nativeAuditHead{}, err
	}
	return h, nil
}
