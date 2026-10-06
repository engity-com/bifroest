package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/management"
)

func TestManagementAuditSnapshotCanBeVerifiedAndExportedOffline(t *testing.T) {
	directory := t.TempDir()
	configured := createAuditCliTestJournal(t, directory, "default", "test.snapshot")
	expected := auditCliTestProducerId(t, configured.IdentityFile)
	source, err := configuredAuditJournalSource(&configured, nil, expected)
	require.NoError(t, err)
	snapshot, err := management.SnapshotAudit(t.Context(), source)
	require.NoError(t, err)
	defer func() { require.NoError(t, snapshot.Close()) }()
	var wire bytes.Buffer
	require.NoError(t, snapshot.WriteTo(&wire))
	copyRoot := t.TempDir()
	header, err := management.ReadAuditSnapshot(&wire, copyRoot)
	require.NoError(t, err)
	require.Equal(t, expected.String(), header.Producer)
	verification, err := audit.VerifyJournals(t.Context(), []audit.JournalSource{{
		Name: "default", Directory: filepath.Join(copyRoot, "journal"), ExpectedProducerId: expected, WithSensitive: true,
	}})
	require.NoError(t, err)
	records := verification.Records()
	require.Len(t, records, 1)
	require.Equal(t, "confidential-flow-default", records[0].Event.Flow)
}

func TestManagementEncryptedAuditSnapshotNeedsOnlyLocalPrivateKey(t *testing.T) {
	directory := t.TempDir()
	recordingFixture := newRecordingExportTestFixture(t)
	private, err := loadAuditPrivateKey(recordingFixture.identityPath)
	require.NoError(t, err)
	public := bfcrypto.PublicKeys(strings.TrimSpace(string(bfcrypto.MarshalPublicKey(private.PublicKey()))))
	configured := createAuditCliTestJournalWithEncryption(t, directory, "encrypted", "test.private", public)
	expected := auditCliTestProducerId(t, configured.IdentityFile)
	source, err := configuredAuditJournalSource(&configured, nil, expected)
	require.NoError(t, err)
	snapshot, err := management.SnapshotAudit(t.Context(), source)
	require.NoError(t, err)
	defer func() { require.NoError(t, snapshot.Close()) }()
	var wire bytes.Buffer
	require.NoError(t, snapshot.WriteTo(&wire))
	root := t.TempDir()
	header, err := management.ReadAuditSnapshot(&wire, root)
	require.NoError(t, err)
	require.Equal(t, source.ExpectedEncryptionRecipient, header.Recipient)
	verification, err := audit.VerifyJournals(t.Context(), []audit.JournalSource{{
		Name: "encrypted", Directory: filepath.Join(root, "journal"), ExpectedProducerId: expected,
		ExpectedEncryptionRecipient: header.Recipient, DecryptionIdentities: []bfcrypto.PrivateKey{private}, WithSensitive: true,
	}})
	require.NoError(t, err)
	require.Equal(t, "confidential-flow-encrypted", verification.Records()[0].Event.Flow)
}
