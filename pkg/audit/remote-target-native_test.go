package audit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func nativeRemoteTestSegment(t *testing.T, encrypted bool) (SealedSegment, auditVectorSet, string) {
	t.Helper()
	identity, err := NewIdentity(auditVectorKey(t, auditVectorSigningSeed))
	require.NoError(t, err)
	vector := frozenAuditVector(t, encrypted)
	fingerprint := ""
	if encrypted {
		recipient, err := bfcrypto.NewAgeSshRecipient(auditVectorKey(t, auditVectorRecipientSeed).PublicKey().ToSsh())
		require.NoError(t, err)
		fingerprint = recipient.Fingerprint()
	}
	segment, err := newSealedSegment(identity.ProducerId(), 1, SegmentHash(hashNativeAuditSegment(vector.segment)), int64(len(vector.segment)), bytes.NewReader(vector.segment))
	require.NoError(t, err)
	segment.encrypted = encrypted
	require.NoError(t, segment.Validate())
	return segment, vector, fingerprint
}

func verifyRetrievedNativeRemoteTestSegment(t *testing.T, segment SealedSegment, vector auditVectorSet, fingerprint string, retrieved []byte) {
	t.Helper()
	require.Equal(t, vector.segment, retrieved)
	root := t.TempDir()
	producer := filepath.Join(root, segment.ProducerId().String())
	require.NoError(t, os.Mkdir(producer, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(producer, nativeHeadFileName), vector.head, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(producer, segment.FileName()), retrieved, 0o600))
	source := JournalSource{Name: "retrieved-remote", Directory: root, ExpectedProducerId: segment.ProducerId(), ExpectedEncryptionRecipient: fingerprint}
	require.NoError(t, VerifyJournalIntegrity(context.Background(), []JournalSource{source}))
	verified, err := VerifyJournals(context.Background(), []JournalSource{source})
	require.NoError(t, err)
	require.Len(t, verified.Journals, 1)
	require.EqualValues(t, 1, verified.Journals[0].SegmentCount)
	require.EqualValues(t, 2, verified.Journals[0].RecordCount)
}
