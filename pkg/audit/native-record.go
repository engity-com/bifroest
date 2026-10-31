package audit

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

const (
	nativeAuditHeaderSignatureDomain = evidence.AuditHeaderSignatureDomain
	nativeAuditRecordSignatureDomain = evidence.AuditRecordSignatureDomain
	nativeAuditSealSignatureDomain   = evidence.AuditSealSignatureDomain
	nativeAuditRecordHashDomain      = evidence.AuditRecordHashDomain
	nativeAuditContentHashDomain     = evidence.AuditContentHashDomain
	nativeAuditSegmentHashDomain     = evidence.AuditSegmentHashDomain
)

var nativeAuditPayloadLimits = evidence.AuditPayloadLimits()

func validNativeAuditRecipientFingerprint(fingerprint string) bool {
	return evidence.ValidAuditRecipientFingerprint(fingerprint)
}

func nativeAuditHeaderFields(h nativeAuditHeader) map[uint64]any {
	return evidence.AuditHeaderFields(h)
}

func nativeAuditRecordFields(r nativeAuditRecord) map[uint64]any {
	return evidence.AuditRecordFields(r)
}

func nativeAuditPrivateFromEvent(event Event) nativeAuditPrivateEvent {
	return evidence.AuditPrivateFromEvent(event)
}

func nativeAuditSealFields(s nativeAuditSeal) map[uint64]any {
	return evidence.AuditSealFields(s)
}

func newNativeAuditHeader(identity *Identity, seq uint64, prevSegmentHash, prevRecordHash journalHash, at time.Time, recipientFingerprint string) (nativeAuditHeader, []byte, error) {
	if identity == nil || identity.PublicKey() == nil || seq == 0 || at.IsZero() || !validNativeAuditRecipientFingerprint(recipientFingerprint) {
		return nativeAuditHeader{}, nil, fmt.Errorf("invalid native audit header arguments")
	}
	h := nativeAuditHeader{
		Version: 1, ProducerId: [32]byte(identity.ProducerId()), PublicKey: identity.journalPublicKey(),
		Sequence: seq, PreviousSegmentHash: [32]byte(prevSegmentHash), PreviousRecordHash: [32]byte(prevRecordHash),
		CreatedAt: nativeformat.TimestampOf(at), Recipient: recipientFingerprint,
	}
	if recipientFingerprint != "" {
		h.Encryption = 1
	}
	unsigned, err := nativeformat.Marshal(nativeAuditHeaderFields(h), nativeformat.MaxMetadataPayload)
	if err != nil {
		return nativeAuditHeader{}, nil, err
	}
	h.Signature, err = identity.sign(append([]byte(nativeAuditHeaderSignatureDomain), unsigned...))
	if err != nil {
		return nativeAuditHeader{}, nil, err
	}
	payload, err := nativeformat.Marshal(h, nativeformat.MaxMetadataPayload)
	return h, payload, err
}

func decodeNativeAuditHeader(payload []byte, identity journalIdentity, seq uint64, prevSegmentHash, prevRecordHash journalHash, recipientFingerprint string) (nativeAuditHeader, error) {
	return evidence.DecodeAuditHeader(payload, asPortableJournalIdentity(identity), seq, prevSegmentHash, prevRecordHash, recipientFingerprint)
}

func newNativeAuditRecord(identity *Identity, previousHash journalHash, event Event, id uuid.UUID, recordedAt time.Time, recipient *bfcrypto.AgeSshRecipient) (nativeAuditRecord, []byte, journalHash, error) {
	if identity == nil || id.Version() != 4 || id.Variant() != uuid.RFC4122 || recordedAt.IsZero() {
		return nativeAuditRecord{}, nil, journalHash{}, fmt.Errorf("invalid native audit record arguments")
	}
	if err := validateAuditEvent(event); err != nil {
		return nativeAuditRecord{}, nil, journalHash{}, err
	}
	private, err := nativeformat.Marshal(nativeAuditPrivateFromEvent(event), nativeformat.MaxAuditEventPayload)
	if err != nil {
		return nativeAuditRecord{}, nil, journalHash{}, err
	}
	stored, err := nativeformat.EncodeStoredPayload(private, recipient, nativeAuditPayloadLimits)
	if err != nil {
		return nativeAuditRecord{}, nil, journalHash{}, err
	}
	r := nativeAuditRecord{
		Id: [16]byte(id), RecordedAt: nativeformat.TimestampOf(recordedAt),
		PreviousRecordHash: [32]byte(previousHash),
		PublicEvent:        nativeAuditPublicEvent{Name: event.Name, Domain: string(event.Domain), Outcome: string(event.Outcome)},
		PrivatePayload:     stored,
	}
	unsigned, err := nativeformat.Marshal(nativeAuditRecordFields(r), nativeformat.MaxAuditRecordPayload)
	if err != nil {
		return nativeAuditRecord{}, nil, journalHash{}, err
	}
	r.Signature, err = identity.sign(append([]byte(nativeAuditRecordSignatureDomain), unsigned...))
	if err != nil {
		return nativeAuditRecord{}, nil, journalHash{}, err
	}
	payload, err := nativeformat.Marshal(r, nativeformat.MaxAuditRecordPayload)
	if err != nil {
		return nativeAuditRecord{}, nil, journalHash{}, err
	}
	return r, payload, hashJournalBytes(nativeAuditRecordHashDomain, payload), nil
}

func decodeNativeAuditRecord(payload []byte, identity journalIdentity, previousHash journalHash, expectedRecipient string, identities *bfcrypto.AgeSshIdentities, withSensitive bool) (nativeAuditRecord, Event, journalHash, error) {
	return evidence.DecodeAuditRecord(payload, asPortableJournalIdentity(identity), previousHash, expectedRecipient, identities, withSensitive)
}

func newNativeAuditSeal(identity *Identity, seq, count, contentBytes uint64, contentHash, lastRecordHash journalHash, at time.Time) (nativeAuditSeal, []byte, error) {
	if identity == nil || seq == 0 || contentBytes == 0 || at.IsZero() {
		return nativeAuditSeal{}, nil, fmt.Errorf("invalid native audit seal arguments")
	}
	s := nativeAuditSeal{Sequence: seq, RecordCount: count, ContentBytes: contentBytes, ContentHash: [32]byte(contentHash), LastRecordHash: [32]byte(lastRecordHash), SealedAt: nativeformat.TimestampOf(at)}
	unsigned, err := nativeformat.Marshal(nativeAuditSealFields(s), nativeformat.MaxMetadataPayload)
	if err != nil {
		return nativeAuditSeal{}, nil, err
	}
	s.Signature, err = identity.sign(append([]byte(nativeAuditSealSignatureDomain), unsigned...))
	if err != nil {
		return nativeAuditSeal{}, nil, err
	}
	payload, err := nativeformat.Marshal(s, nativeformat.MaxMetadataPayload)
	return s, payload, err
}

func decodeNativeAuditSeal(payload []byte, identity journalIdentity, seq, count, contentBytes uint64, contentHash, lastRecordHash journalHash) (nativeAuditSeal, error) {
	return evidence.DecodeAuditSeal(payload, asPortableJournalIdentity(identity), seq, count, contentBytes, contentHash, lastRecordHash)
}

func hashNativeAuditContent(content []byte) journalHash {
	return evidence.HashAuditContent(content)
}

func hashNativeAuditSegment(segment []byte) journalHash {
	return evidence.HashAuditSegment(segment)
}
