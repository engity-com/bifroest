package audit

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

const nativeAuditHeadSignatureDomain = evidence.AuditHeadSignatureDomain

type nativeAuditHead = evidence.NativeAuditHead

func nativeAuditHeadFields(h nativeAuditHead) map[uint64]any {
	return evidence.AuditHeadFields(h)
}

func newNativeAuditHead(identity *Identity, lastRecordHash journalHash) (nativeAuditHead, []byte, error) {
	if identity == nil || identity.PublicKey() == nil {
		return nativeAuditHead{}, nil, fmt.Errorf("missing native audit head identity")
	}
	h := nativeAuditHead{Version: 1, ProducerId: [32]byte(identity.ProducerId()), PublicKey: identity.journalPublicKey(), LastRecordHash: [32]byte(lastRecordHash)}
	unsigned, err := nativeformat.Marshal(nativeAuditHeadFields(h), nativeformat.MaxMetadataPayload)
	if err != nil {
		return nativeAuditHead{}, nil, err
	}
	h.Signature, err = identity.sign(append([]byte(nativeAuditHeadSignatureDomain), unsigned...))
	if err != nil {
		return nativeAuditHead{}, nil, err
	}
	payload, err := nativeformat.Marshal(h, nativeformat.MaxMetadataPayload)
	return h, payload, err
}

func decodeNativeAuditHead(payload []byte, identity journalIdentity) (nativeAuditHead, error) {
	return evidence.DecodeAuditHead(payload, asPortableJournalIdentity(identity))
}
