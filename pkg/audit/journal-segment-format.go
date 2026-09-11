package audit

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	journalSegmentHeaderSchema          = "bifroest.audit-segment-header/v1"
	journalSegmentSealSchema            = "bifroest.audit-segment-seal/v1"
	journalSegmentHeaderSignatureDomain = "BIFROEST-AUDIT-SEGMENT-HEADER-SIGNATURE/v1\x00"
	journalSegmentSealSignatureDomain   = "BIFROEST-AUDIT-SEGMENT-SEAL-SIGNATURE/v1\x00"
	journalSegmentContentHashDomain     = "BIFROEST-AUDIT-SEGMENT-CONTENT-HASH/v1\x00"
	journalSegmentHashDomain            = "BIFROEST-AUDIT-SEGMENT-HASH/v1\x00"
)

type journalSegmentHeaderContent struct {
	Schema              string      `json:"schema"`
	ProducerId          ProducerId  `json:"producerId"`
	Sequence            uint64      `json:"sequence"`
	CreatedAt           time.Time   `json:"createdAt"`
	PreviousSegmentHash journalHash `json:"previousSegmentHash"`
	PreviousRecordHash  journalHash `json:"previousRecordHash"`
	PublicKey           []byte      `json:"publicKey"`
}

type journalSegmentHeader struct {
	journalSegmentHeaderContent
	Signature []byte `json:"signature"`
}

type journalSegmentSealContent struct {
	Schema         string      `json:"schema"`
	ProducerId     ProducerId  `json:"producerId"`
	Sequence       uint64      `json:"sequence"`
	SealedAt       time.Time   `json:"sealedAt"`
	RecordCount    uint64      `json:"recordCount"`
	ContentBytes   uint64      `json:"contentBytes"`
	ContentHash    journalHash `json:"contentHash"`
	LastRecordHash journalHash `json:"lastRecordHash"`
}

type journalSegmentSeal struct {
	journalSegmentSealContent
	Signature []byte `json:"signature"`
}

func newJournalSegmentHeader(identity *Identity, sequence uint64, previousSegmentHash, previousRecordHash journalHash, createdAt time.Time) (journalSegmentHeader, []byte, error) {
	content := journalSegmentHeaderContent{
		Schema:              journalSegmentHeaderSchema,
		ProducerId:          identity.ProducerId(),
		Sequence:            sequence,
		CreatedAt:           createdAt.UTC(),
		PreviousSegmentHash: previousSegmentHash,
		PreviousRecordHash:  previousRecordHash,
		PublicKey:           identity.PublicKey().Marshal(),
	}
	unsigned, err := json.Marshal(content)
	if err != nil {
		return journalSegmentHeader{}, nil, errors.System.Newf("cannot encode audit segment header: %w", err)
	}
	signature, err := identity.sign(append([]byte(journalSegmentHeaderSignatureDomain), unsigned...))
	if err != nil {
		return journalSegmentHeader{}, nil, err
	}
	header := journalSegmentHeader{journalSegmentHeaderContent: content, Signature: signature}
	payload, err := json.Marshal(header)
	if err != nil {
		return journalSegmentHeader{}, nil, errors.System.Newf("cannot encode signed audit segment header: %w", err)
	}
	return header, payload, nil
}

func decodeJournalSegmentHeader(payload []byte, identity *Identity, expectedSequence uint64, expectedSegmentHash, expectedRecordHash journalHash) (journalSegmentHeader, error) {
	var header journalSegmentHeader
	if err := decodeCanonicalJournalPayload(payload, &header); err != nil {
		return journalSegmentHeader{}, err
	}
	if header.Schema != journalSegmentHeaderSchema || header.Sequence != expectedSequence {
		return journalSegmentHeader{}, errors.System.Newf("illegal audit segment header schema or sequence")
	}
	if header.CreatedAt.IsZero() {
		return journalSegmentHeader{}, errors.System.Newf("audit segment creation time is empty")
	}
	if header.ProducerId != identity.ProducerId() || !bytes.Equal(header.PublicKey, identity.PublicKey().Marshal()) {
		return journalSegmentHeader{}, errors.Config.Newf("audit segment header belongs to a different identity")
	}
	if header.PreviousSegmentHash != expectedSegmentHash || header.PreviousRecordHash != expectedRecordHash {
		return journalSegmentHeader{}, errors.System.Newf("audit segment header does not continue the previous chain")
	}
	unsigned, err := json.Marshal(header.journalSegmentHeaderContent)
	if err != nil {
		return journalSegmentHeader{}, errors.System.Newf("cannot re-encode audit segment header: %w", err)
	}
	if err := identity.verify(append([]byte(journalSegmentHeaderSignatureDomain), unsigned...), header.Signature); err != nil {
		return journalSegmentHeader{}, err
	}
	return header, nil
}

func newJournalSegmentSeal(identity *Identity, sequence, recordCount, contentBytes uint64, contentHash, lastRecordHash journalHash, sealedAt time.Time) (journalSegmentSeal, []byte, error) {
	content := journalSegmentSealContent{
		Schema:         journalSegmentSealSchema,
		ProducerId:     identity.ProducerId(),
		Sequence:       sequence,
		SealedAt:       sealedAt.UTC(),
		RecordCount:    recordCount,
		ContentBytes:   contentBytes,
		ContentHash:    contentHash,
		LastRecordHash: lastRecordHash,
	}
	unsigned, err := json.Marshal(content)
	if err != nil {
		return journalSegmentSeal{}, nil, errors.System.Newf("cannot encode audit segment seal: %w", err)
	}
	signature, err := identity.sign(append([]byte(journalSegmentSealSignatureDomain), unsigned...))
	if err != nil {
		return journalSegmentSeal{}, nil, err
	}
	seal := journalSegmentSeal{journalSegmentSealContent: content, Signature: signature}
	payload, err := json.Marshal(seal)
	if err != nil {
		return journalSegmentSeal{}, nil, errors.System.Newf("cannot encode signed audit segment seal: %w", err)
	}
	return seal, payload, nil
}

func decodeJournalSegmentSeal(payload []byte, identity *Identity, state journalSegmentState, expectedContentHash journalHash) (journalSegmentSeal, error) {
	var seal journalSegmentSeal
	if err := decodeCanonicalJournalPayload(payload, &seal); err != nil {
		return journalSegmentSeal{}, err
	}
	if seal.Schema != journalSegmentSealSchema || seal.ProducerId != identity.ProducerId() || seal.Sequence != state.sequence {
		return journalSegmentSeal{}, errors.System.Newf("illegal audit segment seal identity or sequence")
	}
	if seal.SealedAt.IsZero() || seal.RecordCount != state.recordCount || seal.ContentBytes != uint64(state.contentBytes) || seal.ContentHash != expectedContentHash || seal.LastRecordHash != state.previousRecordHash {
		return journalSegmentSeal{}, errors.System.Newf("audit segment seal does not match its content")
	}
	unsigned, err := json.Marshal(seal.journalSegmentSealContent)
	if err != nil {
		return journalSegmentSeal{}, errors.System.Newf("cannot re-encode audit segment seal: %w", err)
	}
	if err := identity.verify(append([]byte(journalSegmentSealSignatureDomain), unsigned...), seal.Signature); err != nil {
		return journalSegmentSeal{}, err
	}
	return seal, nil
}
