package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func TestNativeAuditWireSchemas(t *testing.T) {
	now := nativeformat.TimestampOf(time.Unix(1000, 123).UTC())
	header := nativeAuditHeader{
		Version:    1,
		ProducerId: [32]byte{1},
		PublicKey:  []byte("test-public-key"),
		Sequence:   1,
		CreatedAt:  now,
		Signature:  bytes.Repeat([]byte{2}, 64),
	}
	headerBytes, err := nativeformat.Marshal(header, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	decodedHeader, err := nativeformat.Unmarshal[nativeAuditHeader](headerBytes, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.Equal(t, header, decodedHeader)

	public := nativeAuditPublicEvent{Name: EventNameAuthenticationCompleted, Domain: string(EventDomainAuthentication), Outcome: string(EventOutcomeSuccess)}
	publicBytes, err := nativeformat.Marshal(public, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	decodedPublic, err := nativeformat.Unmarshal[nativeAuditPublicEvent](publicBytes, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.Equal(t, public, decodedPublic)
	private := nativeAuditPrivateEvent{Flow: "secret-flow", ConnectionId: "secret-connection", Pty: new(false)}
	privateBytes, err := nativeformat.Marshal(private, nativeformat.MaxAuditEventPayload)
	require.NoError(t, err)
	require.NotContains(t, privateBytes, []byte("authentication.completed"))
	decodedPrivate, err := nativeformat.Unmarshal[nativeAuditPrivateEvent](privateBytes, nativeformat.MaxAuditEventPayload)
	require.NoError(t, err)
	require.Equal(t, private, decodedPrivate)
	_, err = nativeformat.Marshal(nativeAuditPrivateEvent{Flow: strings.Repeat("a", nativeformat.MaxAuditEventPayload-10)}, nativeformat.MaxAuditEventPayload)
	require.NoError(t, err)
	oversizedEvent, err := nativeformat.Marshal(nativeAuditPrivateEvent{Flow: strings.Repeat("a", nativeformat.MaxAuditEventPayload)}, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	_, err = nativeformat.Unmarshal[nativeAuditPrivateEvent](oversizedEvent, nativeformat.MaxAuditEventPayload)
	require.Error(t, err)
	_, err = nativeformat.Marshal(nativeAuditPrivateEvent{Flow: strings.Repeat("a", nativeformat.MaxAuditEventPayload)}, nativeformat.MaxAuditEventPayload)
	require.Error(t, err)

	record := nativeAuditRecord{Id: [16]byte{4}, RecordedAt: now, PublicEvent: public, PrivatePayload: []byte{9}, Signature: bytes.Repeat([]byte{5}, 64)}
	recordBytes, err := nativeformat.Marshal(record, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	require.NotContains(t, recordBytes, []byte("secret-flow"))
	decodedRecord, err := nativeformat.Unmarshal[nativeAuditRecord](recordBytes, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	require.Equal(t, record, decodedRecord)
	record.PublicEvent.Name = strings.Repeat("n", nativeformat.MaxMetadataPayload)
	_, err = nativeformat.Marshal(record, nativeformat.MaxAuditRecordPayload)
	require.Error(t, err, "the nested public event must respect its own 4 KiB limit")
	oversizedPublicRecord, err := nativeformat.Marshal(map[uint64]any{
		1: [16]byte{4}, 2: [2]any{int64(1000), uint64(123)}, 3: [32]byte{},
		4: map[uint64]any{1: strings.Repeat("n", nativeformat.MaxMetadataPayload)},
		5: []byte{9}, 6: bytes.Repeat([]byte{5}, 64),
	}, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	_, err = nativeformat.Unmarshal[nativeAuditRecord](oversizedPublicRecord, nativeformat.MaxAuditRecordPayload)
	require.Error(t, err)
	_, err = nativeformat.Unmarshal[nativeAuditPublicEvent]([]byte{0xa1, 0x09, 0x01}, nativeformat.MaxMetadataPayload)
	require.Error(t, err, "unknown public event fields must fail closed")

	seal := nativeAuditSeal{Sequence: 1, RecordCount: 1, ContentBytes: 256, ContentHash: [32]byte{6}, LastRecordHash: [32]byte{7}, SealedAt: now, Signature: bytes.Repeat([]byte{8}, 64)}
	sealBytes, err := nativeformat.Marshal(seal, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	decodedSeal, err := nativeformat.Unmarshal[nativeAuditSeal](sealBytes, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.Equal(t, seal, decodedSeal)
}
