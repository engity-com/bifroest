package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
)

func TestNativeProducerSnapshotRejectsRealHeadTreeAndHandleChangesWithoutResults(t *testing.T) {
	for _, change := range []string{"head", "extra entry", "replaced segment", "close error"} {
		t.Run(change, func(t *testing.T) {
			conf, id := nativeRecorderTestConfig(t, false)
			recorder := nativeTestOpen(t, &conf, id)
			require.NoError(t, recorder.Record(t.Context(), Event{Name: "first", Flow: "private-flow"}))
			require.NoError(t, recorder.Record(t.Context(), Event{Name: "second"}))
			require.NoError(t, recorder.Close())
			source := JournalSource{Name: "native", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
			options, err := nativeAuditSnapshotOptions(source, evidence.AuditProducerComplete)
			require.NoError(t, err)
			directory := filepath.Join(conf.Directory, id.ProducerId().String())
			segments, _, _, err := nativeInventory(directory, nativeActiveClear, false)
			require.NoError(t, err)
			require.Len(t, segments, 1)
			capture := newNativeAuditProducerSnapshot(source, directory, id.ProducerId(), []string{conf.Directory}, false)
			changed := false
			verified, err := evidence.SelectAuditProducerRecords(t.Context(), capture, options, evidence.RecordSelection{
				Limit: 1,
				Matches: func(record evidence.VerifiedRecord) bool {
					require.Empty(t, record.Event.Flow)
					if changed {
						return true
					}
					changed = true
					switch change {
					case "head":
						path := filepath.Join(directory, nativeHeadFileName)
						data, err := os.ReadFile(path)
						require.NoError(t, err)
						data[len(data)-1] ^= 1
						require.NoError(t, os.WriteFile(path, data, journalFileMode))
					case "extra entry":
						require.NoError(t, os.WriteFile(filepath.Join(directory, "foreign-entry"), []byte("not evidence"), journalFileMode))
					case "replaced segment":
						data, err := os.ReadFile(segments[0].path)
						require.NoError(t, err)
						temporary := filepath.Join(directory, "replacement")
						require.NoError(t, os.WriteFile(temporary, data, journalFileMode))
						require.NoError(t, os.Rename(temporary, segments[0].path))
					case "close error":
						// Fault injection uses the actual retained native head handle,
						// not an os.FileInfo shim or a fake filesystem implementation.
						require.NotNil(t, capture.headFile)
						require.NoError(t, capture.headFile.Close())
					}
					return true
				},
			})
			require.Error(t, err)
			require.Nil(t, verified)
			require.True(t, changed)
			require.True(t, capture.closed)
			require.Nil(t, capture.headFile)
			if change == "close error" {
				require.Positive(t, capture.after.entries, "full tree revalidation passed, but real handle-close failure must still prevent success")
			}
		})
	}
}

func TestNativeProducerSnapshotKeepsPhysicalAliasRulesInsteadOfByteEquality(t *testing.T) {
	for _, linked := range []bool{false, true} {
		conf, id := nativeRecorderTestConfig(t, false)
		recorder := nativeTestOpen(t, &conf, id)
		require.NoError(t, recorder.Record(t.Context(), Event{Name: "first"}))
		require.NoError(t, recorder.Close())
		directory := filepath.Join(conf.Directory, id.ProducerId().String())
		segments, _, _, err := nativeInventory(directory, nativeActiveClear, false)
		require.NoError(t, err)
		require.Len(t, segments, 1)
		active := filepath.Join(directory, nativeActiveClear)
		require.NoError(t, os.Remove(active))
		if linked {
			if err := os.Link(segments[0].path, active); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
		} else {
			data, err := os.ReadFile(segments[0].path)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(active, data, journalFileMode))
		}
		source := JournalSource{Name: "native", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
		verified, err := VerifyJournals(t.Context(), []JournalSource{source})
		if linked {
			require.NoError(t, err)
			require.Len(t, verified.Records(), 1)
			require.EqualValues(t, 1, verified.Journals[0].SegmentCount)
		} else {
			require.Error(t, err, "identical bytes in another inode must not be treated as a physical active alias")
			require.Nil(t, verified)
		}
		live, err := VerifyLiveJournals(t.Context(), []JournalSource{source})
		if linked {
			require.Error(t, err, "live inventory retains its stricter physical active/published alias refusal")
			require.Nil(t, live)
		} else {
			require.NoError(t, err, "an independent active body after an already reached head is outside the captured live prefix")
			require.Len(t, live.Records(), 1)
		}
	}
}
