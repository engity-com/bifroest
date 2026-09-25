package audit

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func TestNativeLiveCapturedHeadSurvivesAppendAndRotation(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted], func(t *testing.T) {
			conf, id := nativeRecorderTestConfig(t, encrypted)
			r := nativeTestOpen(t, &conf, id)
			require.NoError(t, r.Record(context.Background(), Event{Name: "first"}))
			source := JournalSource{Name: "live", Directory: conf.Directory, ExpectedProducerId: id.ProducerId(), ExpectedEncryptionRecipient: r.fingerprint}
			headPath := filepath.Join(r.headDirectory, nativeHeadFileName)
			original, snapshot, err := readVerifierFile(headPath, nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			head, err := decodeNativeAuditHead(original, id)
			require.NoError(t, err)
			checkpoint := journalHash(head.LastRecordHash)
			assertCaptured := func() {
				t.Helper()
				budget := &verifierBudget{}
				records, _, err := verifyLiveProducer(context.Background(), source, r.headDirectory, id, nil, checkpoint, snapshot, true, budget, []string{conf.Directory})
				require.NoError(t, err)
				require.Len(t, records, 1)
				require.Equal(t, "first", records[0].Event.Name)
			}
			require.NoError(t, r.Record(context.Background(), Event{Name: "second"}))
			assertCaptured()
			require.NoError(t, r.Seal())
			assertCaptured()
			require.NoError(t, r.Record(context.Background(), Event{Name: "third"}))
			assertCaptured()
			verification, err := VerifyLiveJournals(context.Background(), []JournalSource{source})
			require.NoError(t, err)
			require.Len(t, verification.Records(), 3)
			require.NoError(t, VerifyLiveJournalIntegrity(context.Background(), []JournalSource{source}))
			require.NoError(t, r.Close())
		})
	}
}

func TestNativeLiveRejectsDamagedPublishedSegmentAfterCapturedHead(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, damage := range []string{"truncated seal", "corrupt seal", "wrong filename hash", "later segment seal"} {
			t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted]+"/"+damage, func(t *testing.T) {
				conf, id := nativeRecorderTestConfig(t, encrypted)
				r := nativeTestOpen(t, &conf, id)
				require.NoError(t, r.Record(context.Background(), Event{Name: "captured"}))
				headPath := filepath.Join(r.headDirectory, nativeHeadFileName)
				capturedHead, err := os.ReadFile(headPath)
				require.NoError(t, err)
				if damage == "later segment seal" {
					require.NoError(t, r.Seal())
				}
				require.NoError(t, r.Record(context.Background(), Event{Name: "later"}))
				require.NoError(t, r.Seal())
				require.NoError(t, r.Close())
				// Restore the captured signed head to exercise the public API with a
				// fixed upper bound in the middle of a subsequently sealed file.
				require.NoError(t, os.WriteFile(headPath, capturedHead, journalFileMode))
				source := JournalSource{Name: "live", Directory: conf.Directory, ExpectedProducerId: id.ProducerId(), ExpectedEncryptionRecipient: r.fingerprint}
				verification, err := VerifyLiveJournals(context.Background(), []JournalSource{source})
				require.NoError(t, err)
				require.EqualValues(t, 1, verification.Journals[0].RecordCount)
				require.Len(t, verification.Records(), 1)
				require.Equal(t, "captured", verification.Records()[0].Event.Name)
				require.NoError(t, VerifyLiveJournalIntegrity(context.Background(), []JournalSource{source}))
				activeName := nativeActiveClear
				if encrypted {
					activeName = nativeActiveEncrypted
				}
				segments, _, _, err := nativeInventory(r.headDirectory, activeName, encrypted)
				require.NoError(t, err)
				expectedSegments := 1
				if damage == "later segment seal" {
					expectedSegments = 2
				}
				require.Len(t, segments, expectedSegments)
				segment := segments[expectedSegments-1]
				data, err := os.ReadFile(segment.path)
				require.NoError(t, err)
				switch damage {
				case "truncated seal":
					require.NoError(t, os.Truncate(segment.path, int64(len(data)-1)))
				case "later segment seal":
					require.NoError(t, os.Truncate(segment.path, int64(len(data)-1)))
				case "corrupt seal":
					data[len(data)-len(nativeformat.CommitMarker)-5] ^= 1
					require.NoError(t, os.WriteFile(segment.path, data, journalFileMode))
				case "wrong filename hash":
					require.NoError(t, os.Rename(segment.path, filepath.Join(r.headDirectory, nativeSegmentName(segment.seq, journalHash{1}, encrypted))))
				}
				before := snapshotJournalTestTree(t, conf.Directory)
				verification, err = VerifyLiveJournals(context.Background(), []JournalSource{source})
				require.Error(t, err)
				require.Nil(t, verification)
				require.Error(t, VerifyLiveJournalIntegrity(context.Background(), []JournalSource{source}))
				require.Equal(t, before, snapshotJournalTestTree(t, conf.Directory))
				var output bytes.Buffer
				require.NoError(t, verification.ExportJSONLines(&output, RecordOrderChain))
				require.Empty(t, output.String())
			})
		}
	}
}

func TestNativeLiveIgnoresOnlyPostHeadTail(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	require.NoError(t, r.Record(context.Background(), Event{Name: "first"}))
	source := JournalSource{Name: "live", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
	_, err := r.file.WriteAt([]byte{0}, r.state.fileBytes)
	require.NoError(t, err)
	require.NoError(t, r.file.Sync())
	verification, err := VerifyLiveJournals(context.Background(), []JournalSource{source})
	require.NoError(t, err)
	require.Len(t, verification.Records(), 1)
	require.NoError(t, VerifyLiveJournalIntegrity(context.Background(), []JournalSource{source}))
	require.Error(t, VerifyJournalIntegrity(context.Background(), []JournalSource{source}))
	require.NoError(t, r.file.Close())
	require.NoError(t, r.lock.Close())
}

func TestNativeLiveRejectsInvalidPrefixWithoutExport(t *testing.T) {
	for _, change := range []string{"head", "record", "active-record", "missing", "recipient", "producer", "alias"} {
		t.Run(change, func(t *testing.T) {
			conf, id := nativeRecorderTestConfig(t, false)
			r := nativeTestOpen(t, &conf, id)
			require.NoError(t, r.Record(context.Background(), Event{Name: "first"}))
			require.NoError(t, r.Seal())
			require.NoError(t, r.Record(context.Background(), Event{Name: "second"}))
			source := JournalSource{Name: "live", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
			segments, _, _, err := nativeInventory(r.headDirectory, nativeActiveClear, false)
			require.NoError(t, err)
			switch change {
			case "head":
				path := filepath.Join(r.headDirectory, nativeHeadFileName)
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				data[len(data)-1] ^= 1
				require.NoError(t, os.WriteFile(path, data, 0600))
			case "record":
				file, err := os.OpenFile(segments[0].path, os.O_WRONLY, 0600)
				require.NoError(t, err)
				_, err = file.WriteAt([]byte{0}, int64(len(nativeformat.AuditMagic)))
				require.NoError(t, err)
				require.NoError(t, file.Close())
			case "active-record":
				file, err := os.OpenFile(r.activePath, os.O_RDWR, 0600)
				require.NoError(t, err)
				header, next, tail, err := nativeformat.ReadUnitAt(file, int64(len(nativeformat.AuditMagic)), r.state.fileBytes, nativeformat.MaxMetadataPayload)
				require.NoError(t, err)
				require.False(t, tail)
				require.Equal(t, nativeformat.HeaderUnit, header.Type)
				_, err = file.WriteAt([]byte{0}, next)
				require.NoError(t, err)
				require.NoError(t, file.Close())
			case "missing":
				require.NoError(t, os.Remove(segments[0].path))
			case "recipient":
				source.ExpectedEncryptionRecipient = "SHA256:wrong"
			case "producer":
				source.ExpectedProducerId = ProducerId{}
			case "alias":
				require.NoError(t, r.file.Close())
				require.NoError(t, os.Remove(r.activePath))
				if err := os.Link(segments[0].path, r.activePath); err != nil {
					t.Skipf("hard links unavailable: %v", err)
				}
			}
			before := snapshotJournalTestTree(t, conf.Directory)
			verification, err := VerifyLiveJournals(context.Background(), []JournalSource{source})
			require.Error(t, err)
			require.Nil(t, verification)
			require.Error(t, VerifyLiveJournalIntegrity(context.Background(), []JournalSource{source}))
			require.Equal(t, before, snapshotJournalTestTree(t, conf.Directory))
			var output bytes.Buffer
			require.NoError(t, verification.ExportJSONLines(&output, RecordOrderChain))
			require.Empty(t, output.String())
			if change != "alias" {
				require.NoError(t, r.file.Close())
			}
			require.NoError(t, r.lock.Close())
		})
	}
}

func TestNativeLiveReaderDoesNotPreventRotationOrHeadReplacement(t *testing.T) {
	for _, test := range []struct {
		name         string
		active, head bool
	}{
		{"head", false, true},
		{"active", true, false},
		{"both", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			conf, id := nativeRecorderTestConfig(t, false)
			r := nativeTestOpen(t, &conf, id)
			defer func() { require.NoError(t, r.CloseAfterAcceptedFailure()) }()
			require.NoError(t, r.Record(context.Background(), Event{Name: "first"}))
			var head *os.File
			var oldHead []byte
			if test.active {
				active, err := openVerifierPath(r.activePath)
				require.NoError(t, err)
				defer func() { require.NoError(t, active.Close()) }()
			}
			if test.head {
				var err error
				head, err = openVerifierPath(filepath.Join(r.headDirectory, nativeHeadFileName))
				require.NoError(t, err)
				defer func() { require.NoError(t, head.Close()) }()
				oldHead, err = io.ReadAll(head)
				require.NoError(t, err)
			}
			require.NoError(t, r.Record(context.Background(), Event{Name: "second"}))
			require.NoError(t, r.Seal())
			require.NoError(t, r.Record(context.Background(), Event{Name: "third"}))
			if head != nil {
				_, err := head.Seek(0, io.SeekStart)
				require.NoError(t, err)
				stillOld, err := io.ReadAll(head)
				require.NoError(t, err)
				require.Equal(t, oldHead, stillOld)
				current, err := os.ReadFile(filepath.Join(r.headDirectory, nativeHeadFileName))
				require.NoError(t, err)
				require.NotEqual(t, oldHead, current)
			}
			source := JournalSource{Name: "live", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
			verified, err := VerifyLiveJournals(context.Background(), []JournalSource{source})
			require.NoError(t, err)
			require.Len(t, verified.Records(), 3)
		})
	}
}

func TestNativeLiveEmptyHeadStillChecksRecipient(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	source := JournalSource{Name: "empty", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
	verified, err := VerifyLiveJournals(context.Background(), []JournalSource{source})
	require.NoError(t, err)
	require.Empty(t, verified.Records())
	source.ExpectedEncryptionRecipient = "SHA256:wrong"
	verified, err = VerifyLiveJournals(context.Background(), []JournalSource{source})
	require.Error(t, err)
	require.Nil(t, verified)
	require.NoError(t, r.Close())
}
