package audit

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	journalRecordSchema          = "bifroest.audit-record/v1"
	journalRecordSignatureDomain = "BIFROEST-AUDIT-RECORD-SIGNATURE/v1\x00"
	journalRecordHashDomain      = "BIFROEST-AUDIT-RECORD-HASH/v1\x00"
)

type journalRecordContent struct {
	Schema       string      `json:"schema"`
	Id           uuid.UUID   `json:"id"`
	RecordedAt   time.Time   `json:"recordedAt"`
	ProducerId   ProducerId  `json:"producerId"`
	Event        Event       `json:"event"`
	PreviousHash journalHash `json:"previousHash"`
	PublicKey    []byte      `json:"publicKey"`
}

type journalRecord struct {
	journalRecordContent
	Signature []byte `json:"signature"`
}

func newJournalRecord(identity *Identity, previousHash journalHash, event Event, id uuid.UUID, recordedAt time.Time) (journalRecord, []byte, journalHash, error) {
	content := journalRecordContent{
		Schema:       journalRecordSchema,
		Id:           id,
		RecordedAt:   recordedAt.UTC(),
		ProducerId:   identity.ProducerId(),
		Event:        event,
		PreviousHash: previousHash,
		PublicKey:    identity.PublicKey().Marshal(),
	}
	unsigned, err := json.Marshal(content)
	if err != nil {
		return journalRecord{}, nil, journalHash{}, errors.System.Newf("cannot encode unsigned audit record: %w", err)
	}
	signature, err := identity.sign(append([]byte(journalRecordSignatureDomain), unsigned...))
	if err != nil {
		return journalRecord{}, nil, journalHash{}, err
	}
	record := journalRecord{journalRecordContent: content, Signature: signature}
	payload, err := json.Marshal(record)
	if err != nil {
		return journalRecord{}, nil, journalHash{}, errors.System.Newf("cannot encode signed audit record: %w", err)
	}
	return record, payload, hashJournalBytes(journalRecordHashDomain, payload), nil
}

func decodeJournalRecord(payload []byte, identity *Identity, expectedPreviousHash journalHash) (journalRecord, journalHash, error) {
	var record journalRecord
	if err := decodeCanonicalJournalPayload(payload, &record); err != nil {
		return journalRecord{}, journalHash{}, err
	}
	if record.Schema != journalRecordSchema {
		return journalRecord{}, journalHash{}, errors.System.Newf("unsupported audit record schema %q", record.Schema)
	}
	if record.Id == uuid.Nil || record.Id.Version() != 4 || record.Id.Variant() != uuid.RFC4122 {
		return journalRecord{}, journalHash{}, errors.System.Newf("illegal audit record ID %q", record.Id)
	}
	if record.RecordedAt.IsZero() {
		return journalRecord{}, journalHash{}, errors.System.Newf("audit record time is empty")
	}
	if record.ProducerId != identity.ProducerId() {
		return journalRecord{}, journalHash{}, errors.Config.Newf("audit record belongs to producer %s instead of %s", record.ProducerId, identity.ProducerId())
	}
	if !bytes.Equal(record.PublicKey, identity.PublicKey().Marshal()) {
		return journalRecord{}, journalHash{}, errors.Config.Newf("audit record contains a different signing public key")
	}
	if record.PreviousHash != expectedPreviousHash {
		return journalRecord{}, journalHash{}, errors.System.Newf("audit record chain does not continue from %s", expectedPreviousHash)
	}
	if err := validateAuditEvent(record.Event); err != nil {
		return journalRecord{}, journalHash{}, err
	}
	unsigned, err := json.Marshal(record.journalRecordContent)
	if err != nil {
		return journalRecord{}, journalHash{}, errors.System.Newf("cannot re-encode unsigned audit record: %w", err)
	}
	if err := identity.verify(append([]byte(journalRecordSignatureDomain), unsigned...), record.Signature); err != nil {
		return journalRecord{}, journalHash{}, err
	}
	return record, hashJournalBytes(journalRecordHashDomain, payload), nil
}

func decodeCanonicalJournalPayload(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.System.Newf("cannot decode audit journal payload: %w", err)
	}
	if err := ensureJsonEof(decoder); err != nil {
		return err
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return errors.System.Newf("cannot re-encode audit journal payload: %w", err)
	}
	if !bytes.Equal(payload, canonical) {
		return errors.System.Newf("audit journal payload is not canonically encoded")
	}
	return nil
}
