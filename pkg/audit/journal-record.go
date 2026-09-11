package audit

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	journalRecordSchema                   = "bifroest.audit-record/v1"
	journalEncryptedRecordSchema          = "bifroest.audit-record/v2"
	journalRecordSignatureDomain          = "BIFROEST-AUDIT-RECORD-SIGNATURE/v1\x00"
	journalEncryptedRecordSignatureDomain = "BIFROEST-AUDIT-RECORD-SIGNATURE/v2\x00"
	journalRecordHashDomain               = "BIFROEST-AUDIT-RECORD-HASH/v1\x00"
	journalEncryptedRecordHashDomain      = "BIFROEST-AUDIT-RECORD-HASH/v2\x00"
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
	Signature           []byte `json:"signature"`
	encryptionRecipient string `json:"-"`
}

type journalEncryptedRecordContent struct {
	Schema         string                `json:"schema"`
	Id             uuid.UUID             `json:"id"`
	RecordedAt     time.Time             `json:"recordedAt"`
	ProducerId     ProducerId            `json:"producerId"`
	EncryptedEvent journalEncryptedEvent `json:"encryptedEvent"`
	PreviousHash   journalHash           `json:"previousHash"`
	PublicKey      []byte                `json:"publicKey"`
}

type journalEncryptedRecord struct {
	journalEncryptedRecordContent
	Signature []byte `json:"signature"`
}

func newJournalRecord(identity *Identity, previousHash journalHash, event Event, id uuid.UUID, recordedAt time.Time, encryptors ...*journalEventEncryptor) (journalRecord, []byte, journalHash, error) {
	if len(encryptors) > 0 && encryptors[0] != nil {
		return newEncryptedJournalRecord(identity, previousHash, event, id, recordedAt, encryptors[0])
	}
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

func newEncryptedJournalRecord(identity *Identity, previousHash journalHash, event Event, id uuid.UUID, recordedAt time.Time, encryptor *journalEventEncryptor) (journalRecord, []byte, journalHash, error) {
	encryptedEvent, err := encryptor.encrypt(event)
	if err != nil {
		return journalRecord{}, nil, journalHash{}, err
	}
	content := journalEncryptedRecordContent{
		Schema:         journalEncryptedRecordSchema,
		Id:             id,
		RecordedAt:     recordedAt.UTC(),
		ProducerId:     identity.ProducerId(),
		EncryptedEvent: encryptedEvent,
		PreviousHash:   previousHash,
		PublicKey:      identity.PublicKey().Marshal(),
	}
	unsigned, err := json.Marshal(content)
	if err != nil {
		return journalRecord{}, nil, journalHash{}, errors.System.Newf("cannot encode unsigned encrypted audit record: %w", err)
	}
	signature, err := identity.sign(append([]byte(journalEncryptedRecordSignatureDomain), unsigned...))
	if err != nil {
		return journalRecord{}, nil, journalHash{}, err
	}
	wireRecord := journalEncryptedRecord{journalEncryptedRecordContent: content, Signature: signature}
	payload, err := json.Marshal(wireRecord)
	if err != nil {
		return journalRecord{}, nil, journalHash{}, errors.System.Newf("cannot encode signed encrypted audit record: %w", err)
	}
	return journalRecord{
		journalRecordContent: journalRecordContent{
			Schema:       journalEncryptedRecordSchema,
			Id:           id,
			RecordedAt:   recordedAt.UTC(),
			ProducerId:   identity.ProducerId(),
			Event:        event,
			PreviousHash: previousHash,
			PublicKey:    identity.PublicKey().Marshal(),
		},
		Signature:           signature,
		encryptionRecipient: encryptedEvent.Recipient,
	}, payload, hashJournalBytes(journalEncryptedRecordHashDomain, payload), nil
}

func decodeJournalRecord(payload []byte, identity journalIdentity, expectedPreviousHash journalHash, decrypters ...*journalEventDecrypter) (journalRecord, journalHash, error) {
	var envelope struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return journalRecord{}, journalHash{}, errors.System.Newf("cannot identify audit record: %w", err)
	}
	if envelope.Schema == journalEncryptedRecordSchema {
		var decrypter *journalEventDecrypter
		if len(decrypters) > 0 {
			decrypter = decrypters[0]
		}
		return decodeEncryptedJournalRecord(payload, identity, expectedPreviousHash, decrypter)
	}
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
	if !bytes.Equal(record.PublicKey, identity.journalPublicKey()) {
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

func decodeEncryptedJournalRecord(payload []byte, identity journalIdentity, expectedPreviousHash journalHash, decrypter *journalEventDecrypter) (journalRecord, journalHash, error) {
	var encrypted journalEncryptedRecord
	if err := decodeCanonicalJournalPayload(payload, &encrypted); err != nil {
		return journalRecord{}, journalHash{}, err
	}
	if encrypted.Schema != journalEncryptedRecordSchema {
		return journalRecord{}, journalHash{}, errors.System.Newf("unsupported encrypted audit record schema %q", encrypted.Schema)
	}
	if encrypted.Id == uuid.Nil || encrypted.Id.Version() != 4 || encrypted.Id.Variant() != uuid.RFC4122 {
		return journalRecord{}, journalHash{}, errors.System.Newf("illegal audit record ID %q", encrypted.Id)
	}
	if encrypted.RecordedAt.IsZero() {
		return journalRecord{}, journalHash{}, errors.System.Newf("audit record time is empty")
	}
	if encrypted.ProducerId != identity.ProducerId() {
		return journalRecord{}, journalHash{}, errors.Config.Newf("audit record belongs to producer %s instead of %s", encrypted.ProducerId, identity.ProducerId())
	}
	if !bytes.Equal(encrypted.PublicKey, identity.journalPublicKey()) {
		return journalRecord{}, journalHash{}, errors.Config.Newf("audit record contains a different signing public key")
	}
	if encrypted.PreviousHash != expectedPreviousHash {
		return journalRecord{}, journalHash{}, errors.System.Newf("audit record chain does not continue from %s", expectedPreviousHash)
	}
	if encrypted.EncryptedEvent.Scheme != journalEventEncryptionScheme || encrypted.EncryptedEvent.Recipient == "" || len(encrypted.EncryptedEvent.Ciphertext) == 0 {
		return journalRecord{}, journalHash{}, errors.System.Newf("illegal encrypted audit event metadata")
	}
	unsigned, err := json.Marshal(encrypted.journalEncryptedRecordContent)
	if err != nil {
		return journalRecord{}, journalHash{}, errors.System.Newf("cannot re-encode unsigned encrypted audit record: %w", err)
	}
	if err := identity.verify(append([]byte(journalEncryptedRecordSignatureDomain), unsigned...), encrypted.Signature); err != nil {
		return journalRecord{}, journalHash{}, err
	}
	var event Event
	if decrypter != nil {
		event, err = decrypter.decrypt(encrypted.EncryptedEvent)
		if err != nil {
			return journalRecord{}, journalHash{}, err
		}
	}
	return journalRecord{
		journalRecordContent: journalRecordContent{
			Schema:       encrypted.Schema,
			Id:           encrypted.Id,
			RecordedAt:   encrypted.RecordedAt,
			ProducerId:   encrypted.ProducerId,
			Event:        event,
			PreviousHash: encrypted.PreviousHash,
			PublicKey:    encrypted.PublicKey,
		},
		Signature:           encrypted.Signature,
		encryptionRecipient: encrypted.EncryptedEvent.Recipient,
	}, hashJournalBytes(journalEncryptedRecordHashDomain, payload), nil
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
