package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func TestRecordSelectionKeepsNewestMatchesAcrossSegments(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, sensitive := range []bool{false, true} {
			t.Run(fmt.Sprintf("encrypted=%t/sensitive=%t", encrypted, sensitive), func(t *testing.T) {
				conf, id := nativeRecorderTestConfig(t, false)
				var key bfcrypto.PrivateKey
				if encrypted {
					var err error
					key, err = auditIdentityKeyRequirement.GenerateKey(nil)
					require.NoError(t, err)
					conf.EncryptionPublicKey = bfcrypto.PublicKeys(string(ssh.MarshalAuthorizedKey(key.PublicKey().ToSsh())))
				}
				r := nativeTestOpen(t, &conf, id)
				t.Cleanup(func() { require.NoError(t, r.Close()) })
				for i := range 10 {
					name := fmt.Sprintf("skip.%d", i)
					if i%2 == 0 {
						name = fmt.Sprintf("match.%d", i)
					}
					require.NoError(t, r.Record(t.Context(), Event{Name: name, Flow: "private-flow"}))
					if i == 3 || i == 7 {
						require.NoError(t, r.Seal())
					}
				}
				source := JournalSource{
					Name: "selected", Directory: conf.Directory, ExpectedProducerId: id.ProducerId(),
					ExpectedEncryptionRecipient: r.fingerprint, WithSensitive: sensitive,
				}
				if encrypted && sensitive {
					source.DecryptionIdentities = []bfcrypto.PrivateKey{key}
				}
				for _, verify := range []struct {
					name string
					run  func(context.Context, []JournalSource, RecordSelection) (*Verification, error)
				}{{"live", SelectLiveJournalRecords}, {"snapshot", SelectJournalRecords}} {
					for _, limit := range []uint{0, 2, ^uint(0)} {
						t.Run(fmt.Sprintf("%s/limit=%d", verify.name, limit), func(t *testing.T) {
							verified, err := verify.run(t.Context(), []JournalSource{source}, RecordSelection{
								Limit: limit,
								Matches: func(record VerifiedRecord) bool {
									if sensitive {
										require.Equal(t, "private-flow", record.Event.Flow)
									} else {
										require.Empty(t, record.Event.Flow)
									}
									return strings.HasPrefix(record.Event.Name, "match.")
								},
							})
							require.NoError(t, err)
							require.EqualValues(t, 10, verified.Journals[0].RecordCount)
							var names []string
							for _, record := range verified.Records() {
								names = append(names, record.Event.Name)
							}
							want := []string{"match.0", "match.2", "match.4", "match.6", "match.8"}
							if limit == 2 {
								want = want[3:]
							}
							require.Equal(t, want, names)
						})
					}
				}
			})
		}
	}
}

func TestRecordSelectionRejectsDamageOutsideMatchingRecords(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	require.NoError(t, r.Record(t.Context(), Event{Name: "wanted"}))
	require.NoError(t, r.Seal())
	require.NoError(t, r.Record(t.Context(), Event{Name: "excluded"}))
	require.NoError(t, r.Close())
	segments, _, _, err := nativeInventory(r.headDirectory, nativeActiveClear, false)
	require.NoError(t, err)
	require.Len(t, segments, 2)
	info, err := os.Stat(segments[1].path)
	require.NoError(t, err)
	require.NoError(t, os.Truncate(segments[1].path, info.Size()-1))
	source := JournalSource{Name: "damaged", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
	selection := RecordSelection{Limit: 1, Matches: func(record VerifiedRecord) bool { return record.Event.Name == "wanted" }}
	for _, verify := range []func(context.Context, []JournalSource, RecordSelection) (*Verification, error){SelectLiveJournalRecords, SelectJournalRecords} {
		verified, err := verify(t.Context(), []JournalSource{source}, selection)
		require.Error(t, err)
		require.Nil(t, verified)
	}
}

func TestRecordSelectionLimitIsSharedAcrossJournals(t *testing.T) {
	var sources []JournalSource
	for _, name := range []string{"first", "second"} {
		conf, id := nativeRecorderTestConfig(t, false)
		r := nativeTestOpen(t, &conf, id)
		for i := range 3 {
			require.NoError(t, r.Record(t.Context(), Event{Name: fmt.Sprintf("%s.%d", name, i)}))
		}
		require.NoError(t, r.Close())
		sources = append(sources, JournalSource{Name: name, Directory: conf.Directory, ExpectedProducerId: id.ProducerId()})
	}
	for _, verify := range []func(context.Context, []JournalSource, RecordSelection) (*Verification, error){SelectLiveJournalRecords, SelectJournalRecords} {
		verified, err := verify(t.Context(), sources, RecordSelection{Limit: 2})
		require.NoError(t, err)
		require.Len(t, verified.Journals, 2)
		for _, journal := range verified.Journals {
			require.EqualValues(t, 3, journal.RecordCount)
		}
		records := verified.Records()
		require.Len(t, records, 2)
		require.Equal(t, "second.1", records[0].Event.Name)
		require.Equal(t, "second.2", records[1].Event.Name)
	}
}

func TestLiveRecordSelectionDiscardsFailedRotationAttempt(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	t.Cleanup(func() { require.NoError(t, r.Close()) })
	require.NoError(t, r.Record(t.Context(), Event{Name: "first"}))
	require.NoError(t, r.Seal())
	require.NoError(t, r.Record(t.Context(), Event{Name: "second"}))
	require.NoError(t, r.Record(t.Context(), Event{Name: "third"}))
	source := JournalSource{Name: "rotating", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
	rotated := false
	verified, err := SelectLiveJournalRecords(t.Context(), []JournalSource{source}, RecordSelection{
		Limit: 2,
		Matches: func(record VerifiedRecord) bool {
			if !rotated {
				rotated = true
				require.NoError(t, r.Seal())
			}
			return record.Event.Name == "first"
		},
	})
	require.NoError(t, err)
	require.True(t, rotated)
	require.EqualValues(t, 3, verified.Journals[0].RecordCount)
	require.Len(t, verified.Records(), 1)
	require.Equal(t, "first", verified.Records()[0].Event.Name)
}

func TestRecordSelectionContinuesBeyondFullHistoryBudget(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	require.NoError(t, r.Record(t.Context(), Event{Name: "wanted"}))
	require.NoError(t, r.Close())
	source := JournalSource{Name: "large", Directory: conf.Directory, ExpectedProducerId: id.ProducerId()}
	budget := &verifierBudget{
		records:   maxMaterializedVerifiedRecords,
		selection: &verifiedRecordSelection{selection: RecordSelection{Limit: 1}},
	}
	headBytes, _, err := readVerifierFile(filepath.Join(r.headDirectory, nativeHeadFileName), nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	head, err := evidence.CaptureAuditProducerHead(headBytes, id.ProducerId(), false)
	require.NoError(t, err)
	require.Equal(t, r.state.lastRecord, head.Checkpoint())
	_, _, err = verifyLiveProducer(t.Context(), source, r.headDirectory, head, nil, true, budget, []string{conf.Directory})
	require.NoError(t, err)
	require.EqualValues(t, maxMaterializedVerifiedRecords+1, budget.records)
	require.Len(t, budget.selection.materialize(), 1)
	require.Equal(t, "wanted", budget.selection.materialize()[0].Event.Name)
}

func TestRecordSelectionBudgetChargesOnlyRetainedMatches(t *testing.T) {
	selection := &verifiedRecordSelection{selection: RecordSelection{
		Limit: 2, Matches: func(record VerifiedRecord) bool { return record.Event.Name == "keep" },
	}}
	require.NoError(t, selection.add(VerifiedRecord{Event: Event{Name: "skip"}}, maxMaterializedVerifiedBytes+1))
	for _, name := range []string{"first", "second", "third"} {
		require.NoError(t, selection.add(VerifiedRecord{Event: Event{Name: "keep", Flow: name}}, maxMaterializedVerifiedBytes/2))
	}
	records := selection.materialize()
	require.Len(t, records, 2)
	require.Equal(t, "second", records[0].Event.Flow)
	require.Equal(t, "third", records[1].Event.Flow)
	require.ErrorContains(t, selection.add(VerifiedRecord{Event: Event{Name: "keep"}}, maxMaterializedVerifiedBytes/2+1), "materialization limit")
	require.Equal(t, records, selection.materialize())

	unbounded := &verifiedRecordSelection{}
	require.NoError(t, unbounded.add(VerifiedRecord{}, maxMaterializedVerifiedBytes))
	require.ErrorContains(t, unbounded.add(VerifiedRecord{}, 1), "materialization limit")
}
