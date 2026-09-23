package audit

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

const (
	nativeAuditHeaderSignatureDomain = "BIFROEST-BAUDIT-HEADER-SIGNATURE/v1\x00"
	nativeAuditRecordSignatureDomain = "BIFROEST-BAUDIT-RECORD-SIGNATURE/v1\x00"
	nativeAuditSealSignatureDomain   = "BIFROEST-BAUDIT-SEAL-SIGNATURE/v1\x00"
	nativeAuditRecordHashDomain      = "BIFROEST-BAUDIT-RECORD-HASH/v1\x00"
	nativeAuditContentHashDomain     = "BIFROEST-BAUDIT-CONTENT-HASH/v1\x00"
	nativeAuditSegmentHashDomain     = "BIFROEST-BAUDIT-SEGMENT-HASH/v1\x00"
)

var nativeAuditPayloadLimits = nativeformat.PayloadLimits{
	MaxDecoded: nativeformat.MaxAuditEventPayload,
	MaxStored:  nativeformat.MaxAuditRecordPayload,
}

const nativeAuditAgePrefix = "age-encryption.org/v1\n"

func validNativeAuditRecipientFingerprint(fingerprint string) bool {
	if fingerprint == "" {
		return true
	}
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		return false
	}
	encoded := strings.TrimPrefix(fingerprint, "SHA256:")
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	return err == nil && len(decoded) == 32 && base64.RawStdEncoding.EncodeToString(decoded) == encoded
}

func nativeAuditHeaderFields(h nativeAuditHeader) map[uint64]any {
	fields := map[uint64]any{
		1: h.Version, 2: h.Encryption, 3: h.ProducerId, 4: h.PublicKey,
		5: h.Sequence, 6: h.PreviousSegmentHash, 7: h.PreviousRecordHash, 8: h.CreatedAt,
	}
	if h.Recipient != "" {
		fields[9] = h.Recipient
	}
	return fields
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
	h, err := nativeformat.Unmarshal[nativeAuditHeader](payload, nativeformat.MaxMetadataPayload)
	if err != nil {
		return nativeAuditHeader{}, err
	}
	if identity == nil || h.Version != 1 || h.Encryption > 1 || (h.Encryption == 1) != (h.Recipient != "") || !validNativeAuditRecipientFingerprint(h.Recipient) ||
		seq == 0 || h.Sequence != seq || h.PreviousSegmentHash != [32]byte(prevSegmentHash) ||
		h.PreviousRecordHash != [32]byte(prevRecordHash) || h.Recipient != recipientFingerprint ||
		h.ProducerId != [32]byte(identity.ProducerId()) || !bytes.Equal(h.PublicKey, identity.journalPublicKey()) {
		return nativeAuditHeader{}, fmt.Errorf("native audit header identity, mode or chain mismatch")
	}
	if at, err := h.CreatedAt.Time(); err != nil || at.IsZero() {
		return nativeAuditHeader{}, fmt.Errorf("invalid native audit header time")
	}
	unsigned, err := nativeformat.Marshal(nativeAuditHeaderFields(h), nativeformat.MaxMetadataPayload)
	if err != nil {
		return nativeAuditHeader{}, err
	}
	if err := identity.verify(append([]byte(nativeAuditHeaderSignatureDomain), unsigned...), h.Signature); err != nil {
		return nativeAuditHeader{}, err
	}
	return h, nil
}

func nativeAuditRecordFields(r nativeAuditRecord) map[uint64]any {
	return map[uint64]any{1: r.Id, 2: r.RecordedAt, 3: r.PreviousRecordHash, 4: r.PublicEvent, 5: r.PrivatePayload}
}

func nativeAuditPrivateFromEvent(e Event) nativeAuditPrivateEvent {
	p := nativeAuditPrivateEvent{
		Flow: e.Flow, ConnectionId: e.ConnectionId, SessionId: e.SessionId, OperationId: e.OperationId,
		RecordingId: e.RecordingId, RecordingDigest: e.RecordingDigest, Target: string(e.Target),
		AuthenticationMethod: string(e.AuthenticationMethod), AuthenticationPhase: string(e.AuthenticationPhase),
		AuthorizationKind: e.AuthorizationKind, SessionTask: string(e.SessionTask), Reason: e.Reason,
		ErrorCategory: string(e.ErrorCategory), BytesRead: e.BytesRead, BytesWritten: e.BytesWritten,
		DurationMillis: e.DurationMillis, Count: e.Count, Pty: e.Pty, AgentForwarding: e.AgentForwarding,
		ForcedCommand: e.ForcedCommand,
	}
	if e.ExitCode != nil {
		value := int64(*e.ExitCode)
		p.ExitCode = &value
	}
	return p
}

func nativeAuditEventFromPrivate(e Event, p nativeAuditPrivateEvent) (Event, error) {
	e.Flow, e.ConnectionId, e.SessionId, e.OperationId = p.Flow, p.ConnectionId, p.SessionId, p.OperationId
	e.RecordingId, e.RecordingDigest = p.RecordingId, p.RecordingDigest
	e.Target = configuration.AuditlogTargetName(p.Target)
	e.AuthenticationMethod, e.AuthenticationPhase = AuthenticationMethod(p.AuthenticationMethod), AuthenticationPhase(p.AuthenticationPhase)
	e.AuthorizationKind, e.SessionTask, e.Reason = p.AuthorizationKind, SessionTask(p.SessionTask), p.Reason
	e.ErrorCategory = ErrorCategory(p.ErrorCategory)
	if p.ExitCode != nil {
		if *p.ExitCode < math.MinInt || *p.ExitCode > math.MaxInt {
			return Event{}, fmt.Errorf("native audit exit code exceeds host int range")
		}
		value := int(*p.ExitCode)
		e.ExitCode = &value
	}
	e.BytesRead, e.BytesWritten, e.DurationMillis, e.Count = p.BytesRead, p.BytesWritten, p.DurationMillis, p.Count
	e.Pty, e.AgentForwarding, e.ForcedCommand = p.Pty, p.AgentForwarding, p.ForcedCommand
	return e, nil
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

func decodeNativeAuditRecord(payload []byte, identity journalIdentity, previousHash journalHash, expectedRecipient string, decryptionIdentities *bfcrypto.AgeSshIdentities, withSensitive bool) (nativeAuditRecord, Event, journalHash, error) {
	r, err := nativeformat.Unmarshal[nativeAuditRecord](payload, nativeformat.MaxAuditRecordPayload)
	if err != nil {
		return nativeAuditRecord{}, Event{}, journalHash{}, err
	}
	id := uuid.UUID(r.Id)
	if identity == nil || id.Version() != 4 || id.Variant() != uuid.RFC4122 || r.PreviousRecordHash != [32]byte(previousHash) || len(r.PrivatePayload) == 0 {
		return nativeAuditRecord{}, Event{}, journalHash{}, fmt.Errorf("invalid native audit record ID, chain or private payload")
	}
	if at, err := r.RecordedAt.Time(); err != nil || at.IsZero() {
		return nativeAuditRecord{}, Event{}, journalHash{}, fmt.Errorf("invalid native audit record time")
	}
	public := Event{Name: r.PublicEvent.Name, Domain: EventDomain(r.PublicEvent.Domain), Outcome: EventOutcome(r.PublicEvent.Outcome)}
	if err := validateAuditEvent(public); err != nil {
		return nativeAuditRecord{}, Event{}, journalHash{}, err
	}
	unsigned, err := nativeformat.Marshal(nativeAuditRecordFields(r), nativeformat.MaxAuditRecordPayload)
	if err != nil {
		return nativeAuditRecord{}, Event{}, journalHash{}, err
	}
	if err := identity.verify(append([]byte(nativeAuditRecordSignatureDomain), unsigned...), r.Signature); err != nil {
		return nativeAuditRecord{}, Event{}, journalHash{}, err
	}
	if expectedRecipient != "" && !bytes.HasPrefix(r.PrivatePayload, []byte(nativeAuditAgePrefix)) {
		return nativeAuditRecord{}, Event{}, journalHash{}, fmt.Errorf("native audit record has no age ciphertext")
	}
	if expectedRecipient == "" || withSensitive {
		privateBytes, err := nativeformat.DecodeStoredPayload(r.PrivatePayload, decryptionIdentities, expectedRecipient, nativeAuditPayloadLimits)
		if err != nil {
			return nativeAuditRecord{}, Event{}, journalHash{}, err
		}
		private, err := nativeformat.Unmarshal[nativeAuditPrivateEvent](privateBytes, nativeformat.MaxAuditEventPayload)
		if err != nil {
			return nativeAuditRecord{}, Event{}, journalHash{}, err
		}
		full, err := nativeAuditEventFromPrivate(public, private)
		if err != nil {
			return nativeAuditRecord{}, Event{}, journalHash{}, err
		}
		if err := validateAuditEventForWrite(full); err != nil {
			return nativeAuditRecord{}, Event{}, journalHash{}, err
		}
		if withSensitive {
			public = full
		}
	}
	return r, public, hashJournalBytes(nativeAuditRecordHashDomain, payload), nil
}

func nativeAuditSealFields(s nativeAuditSeal) map[uint64]any {
	return map[uint64]any{1: s.Sequence, 2: s.RecordCount, 3: s.ContentBytes, 4: s.ContentHash, 5: s.LastRecordHash, 6: s.SealedAt}
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
	s, err := nativeformat.Unmarshal[nativeAuditSeal](payload, nativeformat.MaxMetadataPayload)
	if err != nil {
		return nativeAuditSeal{}, err
	}
	if identity == nil || seq == 0 || contentBytes == 0 || s.Sequence != seq || s.RecordCount != count || s.ContentBytes != contentBytes || s.ContentHash != [32]byte(contentHash) || s.LastRecordHash != [32]byte(lastRecordHash) {
		return nativeAuditSeal{}, fmt.Errorf("native audit seal content or chain mismatch")
	}
	if at, err := s.SealedAt.Time(); err != nil || at.IsZero() {
		return nativeAuditSeal{}, fmt.Errorf("invalid native audit seal time")
	}
	unsigned, err := nativeformat.Marshal(nativeAuditSealFields(s), nativeformat.MaxMetadataPayload)
	if err != nil {
		return nativeAuditSeal{}, err
	}
	if err := identity.verify(append([]byte(nativeAuditSealSignatureDomain), unsigned...), s.Signature); err != nil {
		return nativeAuditSeal{}, err
	}
	return s, nil
}

// Hash the exact physical bytes: magic through last committed record, or the entire sealed file.
func hashNativeAuditContent(content []byte) journalHash {
	return hashJournalBytes(nativeAuditContentHashDomain, content)
}

func hashNativeAuditSegment(segment []byte) journalHash {
	return hashJournalBytes(nativeAuditSegmentHashDomain, segment)
}
