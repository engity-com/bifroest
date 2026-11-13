package audit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/engity-com/bifroest/pkg/nativeformat"
	"github.com/stretchr/testify/require"
)

func TestAuditOverviewDoesNotVerifyUnselectedRecordSignatures(t *testing.T) {
	conf, identity := nativeRecorderTestConfig(t, false)
	writer := nativeTestOpen(t, &conf, identity)
	for index := 0; index < 25; index++ {
		require.NoError(t, writer.Record(t.Context(), Event{Name: "operational"}))
	}
	require.NoError(t, writer.Close())
	segments, _, _, err := nativeInventory(writer.headDirectory, nativeActiveClear, false)
	require.NoError(t, err)
	require.Len(t, segments, 1)
	original, err := os.ReadFile(segments[0].path)
	require.NoError(t, err)
	var rewritten bytes.Buffer
	rewritten.WriteString(nativeformat.AuditMagic)
	offset := int64(len(nativeformat.AuditMagic))
	records := 0
	var changed journalHash
	for offset < int64(len(original)) {
		unit, next, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(original), offset, int64(len(original)), nativeformat.MaxAuditRecordPayload)
		require.NoError(t, err)
		require.False(t, tail)
		payload := unit.Payload
		if unit.Type == nativeformat.ContentUnit {
			records++
			if records == 25 {
				record, err := nativeformat.Unmarshal[nativeAuditRecord](payload, nativeformat.MaxAuditRecordPayload)
				require.NoError(t, err)
				record.Signature[0] ^= 1
				payload, err = nativeformat.Marshal(record, nativeformat.MaxAuditRecordPayload)
				require.NoError(t, err)
				changed = hashJournalBytes(nativeAuditRecordHashDomain, payload)
			}
		}
		if unit.Type == nativeformat.SealUnit {
			seal, err := nativeformat.Unmarshal[nativeAuditSeal](payload, nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			at, err := seal.SealedAt.Time()
			require.NoError(t, err)
			_, payload, err = newNativeAuditSeal(identity, seal.Sequence, seal.RecordCount, uint64(rewritten.Len()), hashNativeAuditContent(rewritten.Bytes()), changed, at)
			require.NoError(t, err)
		}
		frame, err := nativeformat.EncodeUnit(unit.Type, payload, nativeformat.MaxAuditRecordPayload)
		require.NoError(t, err)
		rewritten.Write(frame)
		offset = next
	}
	// Re-sign only the checkpoint/seal around an invalid last record signature.
	// Framing, chain hashes and inventories stay valid: an accidental complete
	// record-signature scan would fail this normal operational page.
	replacement := filepath.Join(writer.headDirectory, nativeSegmentName(1, hashNativeAuditSegment(rewritten.Bytes()), false))
	require.NoError(t, os.WriteFile(replacement, rewritten.Bytes(), 0600))
	require.NoError(t, os.Remove(segments[0].path))
	_, head, err := newNativeAuditHead(identity, changed)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(writer.headDirectory, nativeHeadFileName), head, 0600))
	reader := NewOverviewReader(conf.Directory)
	defer func() { require.NoError(t, reader.Close()) }()
	source := JournalSource{Name: "operational", Directory: conf.Directory, ExpectedProducerId: identity.ProducerId()}
	checked := 0
	visited := 0
	require.NoError(t, reader.Walk(t.Context(), source, func(row OverviewRecord) error {
		visited++
		if checked < 20 {
			_, err := row.ReadRecord(t.Context(), false)
			if err != nil {
				return err
			}
			checked++
		}
		return nil
	}, nil))
	require.Equal(t, 25, visited)
	require.Equal(t, 20, checked)
	_, err = VerifyJournals(t.Context(), []JournalSource{source})
	require.Error(t, err, "the existing full verifier must still reject the invalid unselected signature")
}

func TestAuditOverviewReadsPublicPagesWithoutPrivateKeysAndKeepsFullVerificationSeparate(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted], func(t *testing.T) {
			conf, identity := nativeRecorderTestConfig(t, encrypted)
			writer := nativeTestOpen(t, &conf, identity)
			defer func() { require.NoError(t, writer.Close()) }()
			for index := 0; index < 25; index++ {
				require.NoError(t, writer.Record(t.Context(), Event{Name: "session.task.completed", Domain: EventDomainSession, Outcome: EventOutcomeSuccess, Flow: "private-flow", Reason: EventReasonDisconnected}))
			}
			source := JournalSource{Name: "overview", Directory: conf.Directory, ExpectedProducerId: identity.ProducerId(), ExpectedEncryptionRecipient: writer.fingerprint}
			reader := NewOverviewReader(conf.Directory)
			defer func() { require.NoError(t, reader.Close()) }()
			var selected []OverviewRecord
			count := 0
			err := reader.Walk(t.Context(), source, func(row OverviewRecord) error {
				count++
				if len(selected) < 20 {
					require.NoError(t, row.Retain())
					selected = append(selected, row)
				}
				return nil
			}, nil)
			require.NoError(t, err)
			require.Equal(t, 25, count)
			require.Len(t, selected, 20)
			for _, row := range selected {
				event, err := row.ReadRecord(t.Context(), false)
				require.NoError(t, err)
				require.Equal(t, "session.task.completed", event.Name)
				require.Empty(t, event.Flow)
				if encrypted {
					_, err = row.MetadataContext(t.Context())
					require.Error(t, err)
				} else {
					event, err := row.MetadataContext(t.Context())
					require.NoError(t, err)
					require.Equal(t, "private-flow", event.Flow)
					event, err = row.ReadRecord(t.Context(), true)
					require.NoError(t, err)
					require.Equal(t, "private-flow", event.Flow)
				}
				require.NoError(t, row.Release())
			}
			require.NoError(t, writer.Seal())
			require.NoError(t, writer.Record(t.Context(), Event{Name: "next"}))
			count = 0
			require.NoError(t, reader.Walk(t.Context(), source, func(OverviewRecord) error { count++; return nil }, nil))
			require.Equal(t, 26, count)
		})
	}
}

func TestAuditOverviewRetainedRecordsSurviveAppendAndRotation(t *testing.T) {
	conf, identity := nativeRecorderTestConfig(t, false)
	writer := nativeTestOpen(t, &conf, identity)
	defer func() { require.NoError(t, writer.Close()) }()
	require.NoError(t, writer.Record(t.Context(), Event{Name: "captured"}))
	source := JournalSource{Name: "overview", Directory: conf.Directory, ExpectedProducerId: identity.ProducerId()}
	reader := NewOverviewReader(conf.Directory)
	defer func() { require.NoError(t, reader.Close()) }()
	var selected OverviewRecord
	require.NoError(t, reader.Walk(t.Context(), source, func(row OverviewRecord) error { require.NoError(t, row.Retain()); selected = row; return nil }, nil))
	require.NoError(t, writer.Record(t.Context(), Event{Name: "later"}))
	require.NoError(t, writer.Seal())
	require.NoError(t, writer.Record(t.Context(), Event{Name: "new-active"}))
	event, err := selected.ReadRecord(t.Context(), false)
	require.NoError(t, err)
	require.Equal(t, "captured", event.Name)
	require.NoError(t, selected.Release())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, reader.Walk(ctx, source, func(OverviewRecord) error { t.Fatal("canceled metadata walk must not visit"); return nil }, nil), context.Canceled)
}
