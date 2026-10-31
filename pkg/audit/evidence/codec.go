package evidence

import (
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto/keydata"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

const (
	AuditHeaderSignatureDomain = nativeAuditHeaderSignatureDomain
	AuditRecordSignatureDomain = nativeAuditRecordSignatureDomain
	AuditSealSignatureDomain   = nativeAuditSealSignatureDomain
	AuditHeadSignatureDomain   = nativeAuditHeadSignatureDomain
	AuditRecordHashDomain      = nativeAuditRecordHashDomain
	AuditContentHashDomain     = nativeAuditContentHashDomain
	AuditSegmentHashDomain     = nativeAuditSegmentHashDomain
)

type NativeAuditHead = nativeAuditHead
type NativeAuditHeader = nativeAuditHeader
type NativeAuditPublicEvent = nativeAuditPublicEvent
type NativeAuditPrivateEvent = nativeAuditPrivateEvent
type NativeAuditRecord = nativeAuditRecord
type NativeAuditSeal = nativeAuditSeal
type PublicIdentity = journalPublicIdentity

// JournalIdentity is a read-only signature verification capability, never a
// signer or a private-file loader. Declared producer/key consistency is not trust.
type JournalIdentity interface {
	ProducerId() ProducerId
	PublicKeyBytes() []byte
	VerifySignature([]byte, []byte) error
}

func NewPublicIdentity(id ProducerId, key []byte) (*PublicIdentity, error) {
	return newJournalPublicIdentity(id, key)
}
func (this *journalPublicIdentity) PublicKeyBytes() []byte {
	if this == nil {
		return nil
	}
	return append([]byte(nil), this.encodedKey...)
}
func (this *journalPublicIdentity) VerifySignature(message, signature []byte) error {
	return this.verify(message, signature)
}

func KnownEventNames() []EventName     { return append([]EventName(nil), knownEventNames[:]...) }
func KnownEventReasons() []EventReason { return append([]EventReason(nil), knownEventReasons[:]...) }

func AuditPayloadLimits() nativeformat.PayloadLimits { return nativeAuditPayloadLimits }
func ValidAuditRecipientFingerprint(value string) bool {
	return validNativeAuditRecipientFingerprint(value)
}

// The signing-field codecs are shared with native writers, but no signer or
// private-file loader is exposed by this package.
func AuditHeaderFields(value NativeAuditHeader) map[uint64]any {
	return nativeAuditHeaderFields(value)
}

func AuditRecordFields(value NativeAuditRecord) map[uint64]any {
	return nativeAuditRecordFields(value)
}

func AuditSealFields(value NativeAuditSeal) map[uint64]any {
	return nativeAuditSealFields(value)
}

func AuditHeadFields(value NativeAuditHead) map[uint64]any {
	return nativeAuditHeadFields(value)
}

func AuditPrivateFromEvent(value Event) NativeAuditPrivateEvent {
	return nativeAuditPrivateFromEvent(value)
}

func DecodeAuditHeader(payload []byte, identity JournalIdentity, sequence uint64, previousSegment, previousRecord Hash, recipient string) (NativeAuditHeader, error) {
	return decodeNativeAuditHeader(payload, identity, sequence, previousSegment, previousRecord, recipient)
}

// DecodeAuditRecord checks one record, not its segment, journal or trust root.
// Without sensitive output, a clear private payload is still validated, while
// an encrypted private payload remains outer-only. A caller holding decryption
// keys may request private validation and must separately redact its output.
func DecodeAuditRecord(payload []byte, identity JournalIdentity, previous Hash, recipient string, identities *bfcrypto.AgeSshIdentities, withSensitive bool) (NativeAuditRecord, Event, Hash, error) {
	return decodeNativeAuditRecord(payload, identity, previous, recipient, identities, withSensitive)
}

func DecodeAuditSeal(payload []byte, identity JournalIdentity, sequence, count, contentBytes uint64, contentHash, lastRecord Hash) (NativeAuditSeal, error) {
	return decodeNativeAuditSeal(payload, identity, sequence, count, contentBytes, contentHash, lastRecord)
}

func DecodeAuditHead(payload []byte, identity JournalIdentity) (NativeAuditHead, error) {
	return decodeNativeAuditHead(payload, identity)
}

func HashAuditContent(content []byte) Hash { return hashNativeAuditContent(content) }
func HashAuditSegment(segment []byte) Hash { return hashNativeAuditSegment(segment) }
