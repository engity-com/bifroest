package audit

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func nativeTestRecipient(t *testing.T) (*bfcrypto.AgeSshRecipient, *bfcrypto.AgeSshIdentities) {
	t.Helper()
	key, err := auditIdentityKeyRequirement.GenerateKey(nil)
	require.NoError(t, err)
	recipient, err := bfcrypto.NewAgeSshRecipient(key.PublicKey().ToSsh())
	require.NoError(t, err)
	identities, err := bfcrypto.NewAgeSshIdentities([]bfcrypto.PrivateKey{key})
	require.NoError(t, err)
	return recipient, identities
}

func nativeTestIdentity(t *testing.T) *Identity {
	t.Helper()
	key, err := auditIdentityKeyRequirement.GenerateKey(nil)
	require.NoError(t, err)
	identity, err := NewIdentity(key)
	require.NoError(t, err)
	return identity
}

func nativeTestEvent() Event {
	return Event{
		Name: "custom.event", Domain: EventDomainSession, Outcome: EventOutcomeSuccess,
		Flow: "flow", ConnectionId: uuid.NewString(), SessionId: uuid.NewString(), OperationId: uuid.NewString(),
		RecordingId: uuid.NewString(), RecordingDigest: strings.Repeat("a", 64), Target: "target",
		AuthenticationMethod: AuthenticationMethodPublicKey, AuthenticationPhase: AuthenticationPhaseVerified,
		AuthorizationKind: "policy", SessionTask: SessionTaskExec, Reason: "reason", ErrorCategory: ErrorCategorySystem,
		ExitCode: new(int), BytesRead: new(int64), BytesWritten: new(int64), DurationMillis: new(int64),
		Count: new(uint64), Pty: new(bool), AgentForwarding: new(bool), ForcedCommand: new(bool),
	}
}

func TestNativeAuditEventFieldsAreClassified(t *testing.T) {
	event := reflect.TypeOf(Event{})
	public := reflect.TypeOf(nativeAuditPublicEvent{})
	private := reflect.TypeOf(nativeAuditPrivateEvent{})
	require.Equal(t, event.NumField(), public.NumField()+private.NumField())
	for index := range event.NumField() {
		field := event.Field(index)
		_, exposed := public.FieldByName(field.Name)
		_, protected := private.FieldByName(field.Name)
		require.NotEqual(t, exposed, protected, "audit field %s must be classified exactly once", field.Name)
	}
}

func TestNativeAuditRecordRoundTripAndRedaction(t *testing.T) {
	identity := nativeTestIdentity(t)
	publicIdentity, err := newJournalPublicIdentity(identity.ProducerId(), identity.journalPublicKey())
	require.NoError(t, err)
	event := nativeTestEvent()
	event.SessionTask = SessionTaskSubsystem
	event.SessionSubsystem = "netconf"
	*event.Count = 1
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{true: "encrypted", false: "clear"}[encrypted], func(t *testing.T) {
			var recipient *bfcrypto.AgeSshRecipient
			var identities *bfcrypto.AgeSshIdentities
			fingerprint := ""
			if encrypted {
				recipient, identities = nativeTestRecipient(t)
				fingerprint = recipient.Fingerprint()
			}
			prev := journalHash{1}
			record, payload, hash, err := newNativeAuditRecord(identity, prev, event, uuid.New(), time.Now(), recipient)
			require.NoError(t, err)
			require.NotContains(t, payload, []byte("flow"))
			if encrypted {
				require.NotContains(t, record.PrivatePayload, []byte("flow"))
			}
			decoded, redacted, decodedHash, err := decodeNativeAuditRecord(payload, publicIdentity, prev, fingerprint, nil, false)
			require.NoError(t, err)
			require.Equal(t, record, decoded)
			require.Equal(t, hash, decodedHash)
			require.Equal(t, Event{Name: event.Name, Domain: event.Domain, Outcome: event.Outcome}, redacted)
			_, full, _, err := decodeNativeAuditRecord(payload, publicIdentity, prev, fingerprint, identities, true)
			require.NoError(t, err)
			require.Equal(t, event, full)
			require.NotNil(t, full.ExitCode)
			require.Zero(t, *full.ExitCode)
			require.NotNil(t, full.Pty)
			require.False(t, *full.Pty)
			require.NotNil(t, full.AgentForwarding)
			require.False(t, *full.AgentForwarding)
			require.NotNil(t, full.ForcedCommand)
			require.False(t, *full.ForcedCommand)
			_, _, _, err = decodeNativeAuditRecord(payload, publicIdentity, journalHash{2}, fingerprint, identities, true)
			require.Error(t, err)
		})
	}
}

func TestNativeAuditRecordTamperingAndKeys(t *testing.T) {
	identity := nativeTestIdentity(t)
	recipient, identities := nativeTestRecipient(t)
	_, wrongIdentities := nativeTestRecipient(t)
	_, payload, _, err := newNativeAuditRecord(identity, journalHash{3}, Event{Name: "custom.event", Flow: "private-secret"}, uuid.New(), time.Now(), recipient)
	require.NoError(t, err)
	_, _, _, err = decodeNativeAuditRecord(payload, identity, journalHash{3}, recipient.Fingerprint(), wrongIdentities, true)
	require.Error(t, err)
	_, _, _, err = decodeNativeAuditRecord(payload, identity, journalHash{3}, "wrong-fingerprint", identities, true)
	require.Error(t, err)
	_, _, _, err = decodeNativeAuditRecord(payload, identity, journalHash{3}, recipient.Fingerprint(), nil, true)
	require.Error(t, err)
	record, err := nativeformat.Unmarshal[nativeAuditRecord](payload, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	for _, change := range []func(*nativeAuditRecord){
		func(r *nativeAuditRecord) { r.PublicEvent.Name = "changed" },
		func(r *nativeAuditRecord) { r.PrivatePayload[0] ^= 1 },
		func(r *nativeAuditRecord) { r.Signature[0] ^= 1 },
	} {
		mutated := record
		mutated.PrivatePayload = bytes.Clone(record.PrivatePayload)
		mutated.Signature = bytes.Clone(record.Signature)
		change(&mutated)
		malicious, err := nativeformat.Marshal(mutated, nativeformat.MaxAuditRecordPayload)
		require.NoError(t, err)
		unit, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, malicious, nativeformat.MaxAuditRecordPayload)
		require.NoError(t, err)
		read, _, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(unit), 0, int64(len(unit)), nativeformat.MaxAuditRecordPayload)
		require.NoError(t, err)
		require.False(t, tail)
		_, _, _, err = decodeNativeAuditRecord(read.Payload, identity, journalHash{3}, recipient.Fingerprint(), nil, false)
		require.Error(t, err, "recomputed CRC does not repair a broken signature")
	}
}

func TestNativeAuditClearRecordValidatesPrivateWithoutExport(t *testing.T) {
	identity := nativeTestIdentity(t)
	private, err := nativeformat.Marshal(nativeAuditPrivateEvent{Count: new(uint64)}, nativeformat.MaxAuditEventPayload)
	require.NoError(t, err)
	stored, err := nativeformat.EncodeStoredPayload(private, nil, nativeAuditPayloadLimits)
	require.NoError(t, err)
	r := nativeAuditRecord{Id: [16]byte(uuid.New()), RecordedAt: nativeformat.TimestampOf(time.Now()), PublicEvent: nativeAuditPublicEvent{Name: "custom.event"}, PrivatePayload: stored}
	unsigned, err := nativeformat.Marshal(nativeAuditRecordFields(r), nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	r.Signature, err = identity.sign(append([]byte(nativeAuditRecordSignatureDomain), unsigned...))
	require.NoError(t, err)
	payload, err := nativeformat.Marshal(r, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	_, _, _, err = decodeNativeAuditRecord(payload, identity, journalHash{}, "", nil, false)
	require.Error(t, err, "valid signature must not mask semantically invalid cleartext")

	private, err = nativeformat.Marshal(nativeAuditPrivateEvent{Pty: new(bool)}, nativeformat.MaxAuditEventPayload)
	require.NoError(t, err)
	r.PrivatePayload, err = nativeformat.EncodeStoredPayload(private, nil, nativeAuditPayloadLimits)
	require.NoError(t, err)
	unsigned, err = nativeformat.Marshal(nativeAuditRecordFields(r), nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	r.Signature, err = identity.sign(append([]byte(nativeAuditRecordSignatureDomain), unsigned...))
	require.NoError(t, err)
	payload, err = nativeformat.Marshal(r, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	_, redacted, _, err := decodeNativeAuditRecord(payload, identity, journalHash{}, "", nil, false)
	require.NoError(t, err)
	require.Nil(t, redacted.Pty)
	_, _, _, err = decodeNativeAuditRecord(payload, identity, journalHash{}, "SHA256:pretend", nil, false)
	require.Error(t, err, "cleartext cannot be accepted as an encrypted record without a key")
}

func TestNativeAuditVerifierRejectsSemanticallyInvalidRecordingEvent(t *testing.T) {
	identity := nativeTestIdentity(t)
	private, err := nativeformat.Marshal(nativeAuditPrivateEvent{}, nativeformat.MaxAuditEventPayload)
	require.NoError(t, err)
	for _, name := range []string{EventNameSessionRecordingCompleted, EventNameSessionRecordingDeliverySucceeded} {
		for _, encrypted := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/clear", true: "/encrypted"}[encrypted], func(t *testing.T) {
				var recipient *bfcrypto.AgeSshRecipient
				var identities *bfcrypto.AgeSshIdentities
				fingerprint := ""
				if encrypted {
					recipient, identities = nativeTestRecipient(t)
					fingerprint = recipient.Fingerprint()
				}
				stored, err := nativeformat.EncodeStoredPayload(private, recipient, nativeAuditPayloadLimits)
				require.NoError(t, err)
				r := nativeAuditRecord{
					Id: [16]byte(uuid.New()), RecordedAt: nativeformat.TimestampOf(time.Now()),
					PublicEvent:    nativeAuditPublicEvent{Name: name, Domain: string(EventDomainSession), Outcome: string(EventOutcomeSuccess)},
					PrivatePayload: stored,
				}
				unsigned, err := nativeformat.Marshal(nativeAuditRecordFields(r), nativeformat.MaxAuditRecordPayload)
				require.NoError(t, err)
				r.Signature, err = identity.sign(append([]byte(nativeAuditRecordSignatureDomain), unsigned...))
				require.NoError(t, err)
				payload, err := nativeformat.Marshal(r, nativeformat.MaxAuditRecordPayload)
				require.NoError(t, err)
				_, _, _, err = decodeNativeAuditRecord(payload, identity, journalHash{}, fingerprint, identities, true)
				require.ErrorContains(t, err, "lacks required")
				_, _, _, err = decodeNativeAuditRecord(payload, identity, journalHash{}, fingerprint, nil, false)
				if encrypted {
					require.NoError(t, err, "outer-only verification cannot claim private semantics")
				} else {
					require.ErrorContains(t, err, "lacks required")
				}
			})
		}
	}
}

func TestNativeAuditRecordRejectsMalformedInputs(t *testing.T) {
	identity := nativeTestIdentity(t)
	_, _, _, err := newNativeAuditRecord(identity, journalHash{}, Event{Name: ""}, uuid.New(), time.Now(), nil)
	require.Error(t, err)
	_, _, _, err = newNativeAuditRecord(identity, journalHash{}, Event{Name: "custom.event"}, uuid.Nil, time.Now(), nil)
	require.Error(t, err)
	_, _, _, err = newNativeAuditRecord(identity, journalHash{}, Event{Name: "custom.event", Flow: strings.Repeat("x", nativeformat.MaxAuditEventPayload)}, uuid.New(), time.Now(), nil)
	require.Error(t, err)
	_, payload, _, err := newNativeAuditRecord(identity, journalHash{}, Event{Name: "custom.event"}, uuid.New(), time.Now(), nil)
	require.NoError(t, err)
	_, _, _, err = decodeNativeAuditRecord(append(bytes.Clone(payload), 0), identity, journalHash{}, "", nil, false)
	require.Error(t, err)
	// A canonical but unknown CBOR key fails even if the framing CRC is valid.
	m, err := nativeformat.Unmarshal[map[uint64]any](payload, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	m[7] = uint64(1)
	unknown, err := nativeformat.Marshal(m, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	frame, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, unknown, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	unit, _, _, err := nativeformat.ReadUnitAt(bytes.NewReader(frame), 0, int64(len(frame)), nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	_, _, _, err = decodeNativeAuditRecord(unit.Payload, identity, journalHash{}, "", nil, false)
	require.Error(t, err)
}

func TestNativeAuditHeaderSealAndDomains(t *testing.T) {
	identity := nativeTestIdentity(t)
	other := nativeTestIdentity(t)
	recipient, _ := nativeTestRecipient(t)
	segment, previous := journalHash{1}, journalHash{2}
	for _, fingerprint := range []string{"", recipient.Fingerprint()} {
		h, payload, err := newNativeAuditHeader(identity, 2, segment, previous, time.Now(), fingerprint)
		require.NoError(t, err)
		decoded, err := decodeNativeAuditHeader(payload, identity, 2, segment, previous, fingerprint)
		require.NoError(t, err)
		require.Equal(t, h, decoded)
		_, err = decodeNativeAuditHeader(payload, identity, 2, segment, previous, "different")
		require.Error(t, err)
		_, err = decodeNativeAuditHeader(payload, identity, 2, journalHash{9}, previous, fingerprint)
		require.Error(t, err)
		_, err = decodeNativeAuditHeader(payload, other, 2, segment, previous, fingerprint)
		require.Error(t, err)
		h.Signature[0] ^= 1
		tampered, err := nativeformat.Marshal(h, nativeformat.MaxMetadataPayload)
		require.NoError(t, err)
		_, err = decodeNativeAuditHeader(tampered, identity, 2, segment, previous, fingerprint)
		require.Error(t, err)
	}
	_, _, err := newNativeAuditHeader(identity, 2, segment, previous, time.Now(), "not-an-SSH-fingerprint")
	require.Error(t, err)
	content := []byte(nativeformat.AuditMagic + "physical-content")
	contentHash := hashNativeAuditContent(content)
	segmentHash := hashNativeAuditSegment(content)
	require.NotEqual(t, contentHash, segmentHash)
	s, payload, err := newNativeAuditSeal(identity, 2, 1, uint64(len(content)), contentHash, previous, time.Now())
	require.NoError(t, err)
	decoded, err := decodeNativeAuditSeal(payload, identity, 2, 1, uint64(len(content)), contentHash, previous)
	require.NoError(t, err)
	require.Equal(t, s, decoded)
	_, err = decodeNativeAuditSeal(payload, identity, 2, 1, uint64(len(content)), contentHash, journalHash{9})
	require.Error(t, err)
	_, err = decodeNativeAuditSeal(payload, identity, 2, 1, uint64(len(content))+1, contentHash, previous)
	require.Error(t, err)
	s.Signature[0] ^= 1
	tampered, err := nativeformat.Marshal(s, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	_, err = decodeNativeAuditSeal(tampered, identity, 2, 1, uint64(len(content)), contentHash, previous)
	require.Error(t, err)
}
