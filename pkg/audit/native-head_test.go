package audit

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func TestNativeAuditHeadSignatureAndIdentity(t *testing.T) {
	identity := nativeTestIdentity(t)
	other := nativeTestIdentity(t)
	h, payload, err := newNativeAuditHead(identity, journalHash{4})
	require.NoError(t, err)
	decoded, err := decodeNativeAuditHead(payload, identity)
	require.NoError(t, err)
	require.Equal(t, h, decoded)
	_, err = decodeNativeAuditHead(payload, other)
	require.Error(t, err)
	h.LastRecordHash[0] ^= 1
	tampered, err := nativeformat.Marshal(h, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	_, err = decodeNativeAuditHead(tampered, identity)
	require.Error(t, err)
}
