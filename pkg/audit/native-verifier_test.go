package audit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestNativeVerifierRedactsByDefaultAndRequiresOptInForPrivateData(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted], func(t *testing.T) {
			conf, id := nativeRecorderTestConfig(t, false)
			var key bfcrypto.PrivateKey
			if encrypted {
				var err error
				key, err = auditIdentityKeyRequirement.GenerateKey(nil)
				require.NoError(t, err)
				conf.EncryptionPublicKey = bfcrypto.PublicKeys(string(ssh.MarshalAuthorizedKey(key.PublicKey().ToSsh())))
			}
			r := nativeTestOpen(t, &conf, id)
			event := Event{Name: "custom.event", Flow: "private-flow", Reason: "private-reason"}
			require.NoError(t, r.Record(context.Background(), event))
			require.NoError(t, r.Seal())
			require.NoError(t, r.Record(context.Background(), event))
			require.NoError(t, r.Close())
			source := JournalSource{Name: "test", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
			if encrypted {
				source.ExpectedEncryptionRecipient = r.fingerprint
			}
			before := snapshotJournalTestTree(t, conf.Directory)
			require.NoError(t, VerifyJournalIntegrity(context.Background(), []JournalSource{source}))
			verified, err := VerifyJournals(context.Background(), []JournalSource{source})
			require.NoError(t, err)
			require.EqualValues(t, 2, verified.Journals[0].RecordCount)
			require.EqualValues(t, 3, verified.Journals[0].SegmentCount)
			require.Len(t, verified.Records(), 2)
			var output bytes.Buffer
			require.NoError(t, verified.ExportJSONLines(&output, RecordOrderChain))
			require.NotContains(t, output.String(), "private-flow")
			require.NotContains(t, output.String(), "private-reason")
			require.Equal(t, Event{Name: event.Name}, verified.Records()[0].Event)
			require.Equal(t, before, snapshotJournalTestTree(t, conf.Directory))
			if encrypted {
				source.DecryptionIdentities = []bfcrypto.PrivateKey{key}
				verified, err = VerifyJournals(context.Background(), []JournalSource{source})
				require.NoError(t, err)
				require.Empty(t, verified.Records()[0].Event.Flow)
				source.DecryptionIdentities = nil
			}

			source.WithSensitive = true
			if encrypted {
				require.ErrorContains(t, VerifyJournalIntegrity(context.Background(), []JournalSource{source}), "decryption identity")
				_, err := VerifyJournals(context.Background(), []JournalSource{source})
				require.ErrorContains(t, err, "decryption identity")
				wrong, err := auditIdentityKeyRequirement.GenerateKey(nil)
				require.NoError(t, err)
				source.DecryptionIdentities = []bfcrypto.PrivateKey{wrong}
				require.Error(t, VerifyJournalIntegrity(context.Background(), []JournalSource{source}))
				_, err = VerifyJournals(context.Background(), []JournalSource{source})
				require.Error(t, err)
				source.DecryptionIdentities = []bfcrypto.PrivateKey{key}
			}
			require.NoError(t, VerifyJournalIntegrity(context.Background(), []JournalSource{source}))
			verified, err = VerifyJournals(context.Background(), []JournalSource{source})
			require.NoError(t, err)
			require.Equal(t, event.Flow, verified.Records()[0].Event.Flow)
			output.Reset()
			require.NoError(t, verified.ExportJSONLines(&output, RecordOrderChain))
			require.Contains(t, output.String(), "private-flow")
		})
	}
}

func TestNativeVerifierRejectsCorruptionAndUnexpectedProducer(t *testing.T) {
	for _, change := range []string{"head", "segment", "foreign", "recipient"} {
		t.Run(change, func(t *testing.T) {
			conf, id := nativeRecorderTestConfig(t, false)
			r := nativeTestOpen(t, &conf, id)
			require.NoError(t, r.Record(context.Background(), Event{Name: "custom.event"}))
			require.NoError(t, r.Close())
			source := JournalSource{Name: "test", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
			dir := filepath.Join(conf.Directory, id.ProducerId().String())
			switch change {
			case "head":
				path := filepath.Join(dir, nativeHeadFileName)
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				data[len(data)-1] ^= 1
				require.NoError(t, os.WriteFile(path, data, 0600))
			case "segment":
				segments, _, _, err := nativeInventory(dir, nativeActiveClear, false)
				require.NoError(t, err)
				path := segments[0].path
				file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
				require.NoError(t, err)
				_, err = file.Write([]byte{1})
				require.NoError(t, err)
				require.NoError(t, file.Close())
			case "foreign":
				require.NoError(t, os.WriteFile(filepath.Join(dir, "foreign"), []byte("data"), 0600))
			case "recipient":
				source.ExpectedEncryptionRecipient = "SHA256:wrong"
			}
			verified, err := VerifyJournals(context.Background(), []JournalSource{source})
			require.Error(t, err)
			require.Nil(t, verified)
			require.Error(t, VerifyJournalIntegrity(context.Background(), []JournalSource{source}))
		})
	}
}

func TestNativeVerifierReadsActiveWithoutModifyingItAndRejectsUncommittedTail(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	require.NoError(t, r.Record(context.Background(), Event{Name: "custom.event"}))
	source := JournalSource{Name: "active", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
	before := snapshotJournalTestTree(t, conf.Directory)
	verified, err := VerifyJournals(context.Background(), []JournalSource{source})
	require.NoError(t, err)
	require.Len(t, verified.Records(), 1)
	require.Equal(t, before, snapshotJournalTestTree(t, conf.Directory))
	_, err = r.file.WriteAt([]byte{0}, r.state.fileBytes)
	require.NoError(t, err)
	require.NoError(t, r.file.Sync())
	verified, err = VerifyJournals(context.Background(), []JournalSource{source})
	require.Error(t, err)
	require.Nil(t, verified)
	// Preserve the interrupted tail as evidence rather than recovering it in this test.
	require.NoError(t, r.file.Close())
	require.NoError(t, r.lock.Close())
}

func TestNativeExportRedactsPrivateFieldsUnlessVerifiedForSensitiveOutput(t *testing.T) {
	verification := &Verification{records: []VerifiedRecord{{Event: Event{Name: "custom.event", Flow: "private-flow"}}}}
	var output bytes.Buffer
	require.NoError(t, verification.ExportJSONLines(&output, RecordOrderChain))
	require.NotContains(t, output.String(), "private-flow")
	verification.withSensitive = true
	output.Reset()
	require.NoError(t, verification.ExportJSONLines(&output, RecordOrderChain))
	require.Contains(t, output.String(), "private-flow")
}

func TestNativeVerifierUsesOnlyExternalWorkspaceForLargeJournals(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted], func(t *testing.T) {
			conf, id := nativeRecorderTestConfig(t, encrypted)
			r := nativeTestOpen(t, &conf, id)
			nativeTestWriteSealedChain(t, r, journalSegmentSortChunkSize+1)
			source := JournalSource{Name: "native", Directory: conf.Directory, ExpectedProducerId: id.ProducerId(), ExpectedEncryptionRecipient: r.fingerprint}
			require.NoError(t, VerifyJournalIntegrity(context.Background(), []JournalSource{source}))
			verification, err := VerifyJournals(context.Background(), []JournalSource{source})
			require.NoError(t, err)
			require.EqualValues(t, journalSegmentSortChunkSize+1, verification.Journals[0].RecordCount)
			require.Len(t, verification.Records(), journalSegmentSortChunkSize+1)
			if encrypted {
				unusable := filepath.Join(t.TempDir(), "not-a-directory")
				require.NoError(t, os.WriteFile(unusable, nil, 0600))
				for _, variable := range []string{"TMPDIR", "TMP", "TEMP"} {
					t.Setenv(variable, unusable)
				}
				before := snapshotJournalTestTree(t, conf.Directory)
				require.ErrorContains(t, VerifyJournalIntegrity(context.Background(), []JournalSource{source}), "workspace")
				verification, err = VerifyJournals(context.Background(), []JournalSource{source})
				require.ErrorContains(t, err, "workspace")
				require.Nil(t, verification)
				require.Equal(t, before, snapshotJournalTestTree(t, conf.Directory))
				require.NoDirExists(t, filepath.Join(conf.Directory, journalWorkDirectoryName))
			}
		})
	}
}

func TestNativeVerifierNeedsNoWorkspaceAtInMemoryLimit(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	nativeTestWriteSealedChain(t, r, journalSegmentSortChunkSize)
	unusable := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(unusable, nil, 0600))
	for _, variable := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(variable, unusable)
	}
	source := JournalSource{Name: "native", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
	require.NoError(t, VerifyJournalIntegrity(context.Background(), []JournalSource{source}))
	verification, err := VerifyJournals(context.Background(), []JournalSource{source})
	require.NoError(t, err)
	require.EqualValues(t, journalSegmentSortChunkSize, verification.Journals[0].RecordCount)
	require.NoDirExists(t, filepath.Join(conf.Directory, journalWorkDirectoryName))
}

func TestNativeVerifierRejectsTempDirectoriesInsideSelectedJournals(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	nativeTestWriteSealedChain(t, r, journalSegmentSortChunkSize+1)
	otherConf, otherId := nativeRecorderTestConfig(t, false)
	other := nativeTestOpen(t, &otherConf, otherId)
	require.NoError(t, other.Record(context.Background(), Event{Name: "test.other"}))
	type testCase struct {
		name      string
		temporary string
		sources   []JournalSource
	}
	tests := []testCase{
		{"journal root", conf.Directory, []JournalSource{{Name: "first", Directory: conf.Directory}}},
		{"producer directory", r.headDirectory, []JournalSource{{Name: "first", Directory: conf.Directory}}},
		{"later source", otherConf.Directory, []JournalSource{{Name: "first", Directory: conf.Directory}, {Name: "second", Directory: otherConf.Directory}}},
	}
	alias := filepath.Join(t.TempDir(), "journal-alias")
	if err := os.Symlink(conf.Directory, alias); err == nil {
		tests = append(tests, testCase{"symlink alias", alias, []JournalSource{{Name: "first", Directory: conf.Directory}}})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, variable := range []string{"TMPDIR", "TMP", "TEMP"} {
				t.Setenv(variable, test.temporary)
			}
			beforeFirst := snapshotJournalTestTree(t, conf.Directory)
			beforeSecond := snapshotJournalTestTree(t, otherConf.Directory)
			require.ErrorContains(t, VerifyJournalIntegrity(context.Background(), test.sources), "inside selected journal")
			verification, err := VerifyJournals(context.Background(), test.sources)
			require.ErrorContains(t, err, "inside selected journal")
			require.Nil(t, verification)
			require.Equal(t, beforeFirst, snapshotJournalTestTree(t, conf.Directory))
			require.Equal(t, beforeSecond, snapshotJournalTestTree(t, otherConf.Directory))
		})
	}
}

func TestNativeInventoryRejectsGapAndDuplicate(t *testing.T) {
	for _, scenario := range []string{"gap", "duplicate"} {
		t.Run(scenario, func(t *testing.T) {
			conf, id := nativeRecorderTestConfig(t, false)
			r := nativeTestOpen(t, &conf, id)
			nativeTestWriteSealedChain(t, r, 2)
			entries, _, _, err := nativeInventory(r.headDirectory, nativeActiveClear, false)
			require.NoError(t, err)
			seq := uint64(3)
			if scenario == "duplicate" {
				seq = 1
			}
			require.NoError(t, os.Rename(entries[1].path, filepath.Join(r.headDirectory, nativeSegmentName(seq, entries[1].hash, false))))
			_, err = newNativeRecorder(&conf, id)
			require.Error(t, err)
			source := JournalSource{Name: "native", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
			require.Error(t, VerifyJournalIntegrity(context.Background(), []JournalSource{source}))
		})
	}
}

func TestNativeVerifierRejectsActiveAliasOfEarlierPublishedSegment(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	nativeTestWriteSealedChain(t, r, 2)
	entries, _, _, err := nativeInventory(r.headDirectory, nativeActiveClear, false)
	require.NoError(t, err)
	active := filepath.Join(r.headDirectory, nativeActiveClear)
	if err := os.Link(entries[0].path, active); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	source := JournalSource{Name: "native", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
	require.ErrorContains(t, VerifyJournalIntegrity(context.Background(), []JournalSource{source}), "aliases an earlier published segment")
	require.FileExists(t, entries[0].path)
}
