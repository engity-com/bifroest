package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/crypto/keydata"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func frozenProducerSnapshot(t *testing.T, encrypted bool) (*AuditByteSnapshot, AuditProducerOptions, string) {
	t.Helper()
	data, identity, segment, hashes := scanCodecVector(t, encrypted)
	name := "baudit-v1"
	if encrypted {
		name = "beaudit-v1"
	}
	var hash Hash
	require.NoError(t, hash.UnmarshalText([]byte(hashes.SegmentHash)))
	snapshot, err := NewAuditByteSnapshot(readCodecVector(t, name+"-head.cbor"), []AuditPublishedSegment{{Sequence: 1, Hash: hash, Image: scanVectorImage(t, data)}}, nil)
	require.NoError(t, err)
	return snapshot, AuditProducerOptions{Auditlog: "vector", ExpectedProducerId: identity.ProducerId(), ExpectedEncryptionRecipient: segment.ExpectedEncryptionRecipient}, name
}

func TestPortableAuditProducerSnapshotExportsExactFrozenJSONL(t *testing.T) {
	manifest := codecManifest(t)
	keys, err := keydata.NewAgeSshIdentities([]keydata.PrivateKey{codecPrivateKey(t, manifest.AgeRecipientSeedHex)})
	require.NoError(t, err)
	for _, encrypted := range []bool{false, true} {
		for _, sensitive := range []bool{false, true} {
			for _, suppliedKeys := range []bool{false, true} {
				snapshot, options, name := frozenProducerSnapshot(t, encrypted)
				options.WithSensitive = sensitive
				if suppliedKeys {
					options.DecryptionIdentities = keys
				}
				verified, err := VerifyAuditProducerSnapshot(t.Context(), snapshot, options)
				require.True(t, snapshot.closed)
				if encrypted && sensitive && !suppliedKeys {
					require.Error(t, err)
					require.Nil(t, verified)
					continue
				}
				require.NoError(t, err)
				require.True(t, verified.Summary.Trusted)
				require.Equal(t, options.ExpectedProducerId, verified.Summary.ProducerId)
				require.Equal(t, AuditProducerComplete, verified.Summary.Mode)
				require.EqualValues(t, 1, verified.Summary.SegmentCount)
				require.EqualValues(t, 2, verified.Summary.RecordCount)
				if encrypted && !suppliedKeys {
					require.Zero(t, verified.Summary.PrivateRecordCount, "outer authentication does not attest private semantics")
				} else {
					require.EqualValues(t, 2, verified.Summary.PrivateRecordCount)
				}
				var output bytes.Buffer
				require.NoError(t, verified.ExportJSONLines(&output, RecordOrderChain))
				suffix := "-redacted.jsonl"
				if sensitive {
					suffix = "-with-sensitive.jsonl"
				}
				require.Equal(t, readCodecVector(t, name+suffix), output.Bytes())
				require.Len(t, verified.Records(), 2)
			}
		}
	}
}

func TestPortableAuditProducerRequiresIndependentTrustAndRecipientPolicy(t *testing.T) {
	for _, change := range []string{"missing pin", "wrong pin", "untrusted", "wrong recipient", "wrong keys"} {
		snapshot, options, _ := frozenProducerSnapshot(t, true)
		switch change {
		case "missing pin":
			options.ExpectedProducerId = ProducerId{}
		case "wrong pin":
			options.ExpectedProducerId[0] ^= 1
		case "untrusted":
			options.ExpectedProducerId, options.AllowUntrusted = ProducerId{}, true
		case "wrong recipient":
			options.ExpectedEncryptionRecipient = ""
		case "wrong keys":
			var err error
			options.DecryptionIdentities, err = keydata.NewAgeSshIdentities([]keydata.PrivateKey{codecPrivateKey(t, codecManifest(t).SigningSeedHex)})
			require.NoError(t, err)
		}
		verified, err := VerifyAuditProducerSnapshot(t.Context(), snapshot, options)
		require.True(t, snapshot.closed)
		if change == "untrusted" {
			require.NoError(t, err)
			require.False(t, verified.Summary.Trusted)
		} else {
			require.Error(t, err, change)
			require.Nil(t, verified, change)
		}
	}
}

type producerFixture struct {
	head     []byte
	segments []AuditPublishedSegment
	hashes   []Hash
	identity *PublicIdentity
	options  AuditProducerOptions
}

func signProducerTestMap(t *testing.T, key keydata.PrivateKey, domain string, fields map[uint64]any) []byte {
	t.Helper()
	unsigned, err := nativeformat.Marshal(fields, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	private, ok := key.ToSdk().(ed25519.PrivateKey)
	require.True(t, ok)
	return ed25519.Sign(private, append([]byte(domain), unsigned...))
}

// Synthetic negative/multi-segment fixtures use test-only SDK signing. Frozen
// interop assets above independently protect the production wire-field codecs.
func producerChain(t *testing.T, events [][]Event, encrypted bool, checkpointIndex int) producerFixture {
	t.Helper()
	manifest := codecManifest(t)
	key := codecPrivateKey(t, manifest.SigningSeedHex)
	identity := codecPublicIdentity(t, key)
	result := producerFixture{identity: identity, options: AuditProducerOptions{Auditlog: "vector", ExpectedProducerId: identity.ProducerId()}}
	var recipient *keydata.AgeSshRecipient
	if encrypted {
		var err error
		recipient, err = keydata.NewAgeSshRecipient(codecPrivateKey(t, manifest.AgeRecipientSeedHex).PublicKey().ToSsh())
		require.NoError(t, err)
		result.options.ExpectedEncryptionRecipient = recipient.Fingerprint()
	}
	at := time.Date(2026, 9, 13, 12, 34, 50, 0, time.UTC)
	var previousSegment, previousRecord Hash
	for index, batch := range events {
		sequence := uint64(index + 1)
		header := NativeAuditHeader{
			Version: 1, ProducerId: [32]byte(identity.ProducerId()), PublicKey: identity.PublicKeyBytes(),
			Sequence: sequence, PreviousSegmentHash: [32]byte(previousSegment), PreviousRecordHash: [32]byte(previousRecord),
			CreatedAt: nativeformat.TimestampOf(at), Recipient: result.options.ExpectedEncryptionRecipient,
		}
		if encrypted {
			header.Encryption = 1
		}
		header.Signature = signProducerTestMap(t, key, AuditHeaderSignatureDomain, AuditHeaderFields(header))
		payload, err := nativeformat.Marshal(header, nativeformat.MaxMetadataPayload)
		require.NoError(t, err)
		frame, err := nativeformat.EncodeUnit(nativeformat.HeaderUnit, payload, nativeformat.MaxMetadataPayload)
		require.NoError(t, err)
		data := append([]byte(nativeformat.AuditMagic), frame...)
		for _, event := range batch {
			private, err := nativeformat.Marshal(AuditPrivateFromEvent(event), nativeformat.MaxAuditEventPayload)
			require.NoError(t, err)
			stored, err := nativeformat.EncodeStoredPayload(private, recipient, AuditPayloadLimits())
			require.NoError(t, err)
			record := NativeAuditRecord{
				Id: [16]byte(uuid.New()), RecordedAt: nativeformat.TimestampOf(at), PreviousRecordHash: [32]byte(previousRecord),
				PublicEvent: NativeAuditPublicEvent{Name: event.Name, Domain: string(event.Domain), Outcome: string(event.Outcome)}, PrivatePayload: stored,
			}
			payload = signCodecTestRecord(t, key, record)
			frame, err = nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxAuditRecordPayload)
			require.NoError(t, err)
			data = append(data, frame...)
			previousRecord = HashBytes(AuditRecordHashDomain, payload)
			result.hashes = append(result.hashes, previousRecord)
			at = at.Add(time.Second)
		}
		seal := NativeAuditSeal{Sequence: sequence, RecordCount: uint64(len(batch)), ContentBytes: uint64(len(data)), ContentHash: [32]byte(HashAuditContent(data)), LastRecordHash: [32]byte(previousRecord), SealedAt: nativeformat.TimestampOf(at)}
		seal.Signature = signProducerTestMap(t, key, AuditSealSignatureDomain, AuditSealFields(seal))
		payload, err = nativeformat.Marshal(seal, nativeformat.MaxMetadataPayload)
		require.NoError(t, err)
		frame, err = nativeformat.EncodeUnit(nativeformat.SealUnit, payload, nativeformat.MaxMetadataPayload)
		require.NoError(t, err)
		data = append(data, frame...)
		previousSegment = HashAuditSegment(data)
		result.segments = append(result.segments, AuditPublishedSegment{Sequence: sequence, Hash: previousSegment, Image: scanVectorImage(t, data)})
	}
	checkpoint := previousRecord
	if checkpointIndex >= 0 {
		checkpoint = result.hashes[checkpointIndex]
	}
	head := NativeAuditHead{Version: 1, ProducerId: [32]byte(identity.ProducerId()), PublicKey: identity.PublicKeyBytes(), LastRecordHash: [32]byte(checkpoint)}
	head.Signature = signProducerTestMap(t, key, AuditHeadSignatureDomain, AuditHeadFields(head))
	var err error
	result.head, err = nativeformat.Marshal(head, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	return result
}

func (f producerFixture) snapshot(t *testing.T, active *AuditActiveSegment) *AuditByteSnapshot {
	t.Helper()
	snapshot, err := NewAuditByteSnapshot(f.head, f.segments, active)
	require.NoError(t, err)
	return snapshot
}

func TestPortableAuditProducerVerifiesEntireChainBeyondSelectionAndCheckpoint(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		fixture := producerChain(t, [][]Event{{{Name: "first", Flow: "secret"}}, {{Name: "second"}}, {{Name: "third"}}}, encrypted, -1)
		seen := 0
		selected, err := SelectAuditProducerRecords(t.Context(), fixture.snapshot(t, nil), fixture.options, RecordSelection{
			Limit: 1, Matches: func(record VerifiedRecord) bool {
				seen++
				require.Empty(t, record.Event.Flow)
				return record.Event.Name != "second"
			},
		})
		require.NoError(t, err)
		require.Equal(t, 3, seen)
		require.EqualValues(t, 3, selected.Summary.RecordCount)
		require.EqualValues(t, 3, selected.Summary.SegmentCount)
		require.Len(t, selected.Records(), 1)
		require.Equal(t, "third", selected.Records()[0].Event.Name)
		// A corrupt unselected suffix must still fail the complete proof.
		bad := bytes.Clone(fixture.segments[2].Image.data)
		bad[len(bad)-1] ^= 1
		fixture.segments[2].Image = scanVectorImage(t, bad)
		selected, err = SelectAuditProducerRecords(t.Context(), fixture.snapshot(t, nil), fixture.options, RecordSelection{Limit: 1, Matches: func(record VerifiedRecord) bool { return record.Event.Name == "first" }})
		require.Error(t, err)
		require.Nil(t, selected)

		prefix := producerChain(t, [][]Event{{{Name: "captured"}, {Name: "later"}}, {{Name: "last"}}}, encrypted, 0)
		prefix.options.Mode = AuditProducerCapturedPrefix
		verified, err := VerifyAuditProducerSnapshot(t.Context(), prefix.snapshot(t, nil), prefix.options)
		require.NoError(t, err)
		require.EqualValues(t, 2, verified.Summary.SegmentCount)
		require.EqualValues(t, 1, verified.Summary.RecordCount)
		require.Len(t, verified.Records(), 1)
		require.Equal(t, "captured", verified.Records()[0].Event.Name)
		prefix.options.Mode = AuditProducerComplete
		verified, err = VerifyAuditProducerSnapshot(t.Context(), prefix.snapshot(t, nil), prefix.options)
		require.Error(t, err, "complete mode cannot silently accept a stale signed head")
		require.Nil(t, verified)
		prefix.options.Mode = AuditProducerCapturedPrefix
		bad = bytes.Clone(prefix.segments[1].Image.data)
		bad[len(bad)-1] ^= 1
		prefix.segments[1].Image = scanVectorImage(t, bad)
		verified, err = VerifyAuditProducerSnapshot(t.Context(), prefix.snapshot(t, nil), prefix.options)
		require.Error(t, err, "published segments after a captured checkpoint still require their full seal/hash")
		require.Nil(t, verified)
	}
}

func TestPortableAuditProducerValidatesPrivateSemanticsEvenWhenSelectionRejectsEveryRecord(t *testing.T) {
	fixture := producerChain(t, [][]Event{{{Name: EventNameSessionRecordingCompleted, Domain: EventDomainSession, Outcome: EventOutcomeSuccess}}}, true, -1)
	seen := 0
	selection := RecordSelection{Matches: func(VerifiedRecord) bool { seen++; return false }}
	outer, err := SelectAuditProducerRecords(t.Context(), fixture.snapshot(t, nil), fixture.options, selection)
	require.NoError(t, err)
	require.Equal(t, 1, seen)
	require.Zero(t, outer.Summary.PrivateRecordCount)
	keys, err := keydata.NewAgeSshIdentities([]keydata.PrivateKey{codecPrivateKey(t, codecManifest(t).AgeRecipientSeedHex)})
	require.NoError(t, err)
	fixture.options.DecryptionIdentities = keys
	seen = 0
	denied, err := SelectAuditProducerRecords(t.Context(), fixture.snapshot(t, nil), fixture.options, selection)
	require.Error(t, err)
	require.Nil(t, denied)
	require.Zero(t, seen, "selection must never bypass validation of a private recording lifecycle event")
}

type faultProducerSnapshot struct {
	*AuditByteSnapshot
	headErr, nextErr, activeErr, revalidateErr, closeErr error
	closeHook                                            func()
	nextCalls, revalidateCalls, closeCalls               int
}

func (s *faultProducerSnapshot) Head(ctx context.Context) ([]byte, error) {
	if s.headErr != nil {
		return nil, s.headErr
	}
	return s.AuditByteSnapshot.Head(ctx)
}

func (s *faultProducerSnapshot) NextPublished(ctx context.Context) (AuditPublishedSegment, bool, error) {
	s.nextCalls++
	if s.nextErr != nil && s.nextCalls == 2 {
		return AuditPublishedSegment{}, false, s.nextErr
	}
	return s.AuditByteSnapshot.NextPublished(ctx)
}

func (s *faultProducerSnapshot) Active(ctx context.Context) (AuditActiveSegment, bool, error) {
	if s.activeErr != nil {
		return AuditActiveSegment{}, false, s.activeErr
	}
	return s.AuditByteSnapshot.Active(ctx)
}

func (s *faultProducerSnapshot) Revalidate(ctx context.Context) error {
	s.revalidateCalls++
	return errors.Join(s.AuditByteSnapshot.Revalidate(ctx), s.revalidateErr)
}

func (s *faultProducerSnapshot) Close() error {
	s.closeCalls++
	err := s.AuditByteSnapshot.Close()
	if s.closeHook != nil {
		s.closeHook()
	}
	return errors.Join(err, s.closeErr)
}

func TestPortableAuditProducerRevalidationCloseAndCancellationNeverReleasePartialResults(t *testing.T) {
	for _, failure := range []string{"head", "iteration", "active", "revalidate", "close", "joined", "cancel before", "cancel in predicate", "cancel in close", "options"} {
		for _, mode := range []string{"all", "selected", "integrity"} {
			snapshot, options, _ := frozenProducerSnapshot(t, false)
			source := &faultProducerSnapshot{AuditByteSnapshot: snapshot}
			first, closing := errors.New("capture failure"), errors.New("close failure")
			ctx, cancel := context.WithCancel(t.Context())
			switch failure {
			case "head":
				source.headErr = first
			case "iteration":
				source.nextErr = first
			case "active":
				source.activeErr = first
			case "revalidate":
				source.revalidateErr = first
			case "close":
				source.closeErr = closing
			case "joined":
				source.revalidateErr, source.closeErr = first, closing
			case "cancel before":
				cancel()
			case "cancel in close":
				source.closeHook = cancel
			case "options":
				options.Mode = AuditProducerMode(255)
			}
			var verified *AuditProducerVerification
			var err error
			switch mode {
			case "all":
				if failure == "cancel in predicate" {
					source.closeHook = cancel
				}
				verified, err = VerifyAuditProducerSnapshot(ctx, source, options)
			case "selected":
				verified, err = SelectAuditProducerRecords(ctx, source, options, RecordSelection{Limit: 1, Matches: func(VerifiedRecord) bool {
					if failure == "cancel in predicate" {
						cancel()
					}
					return true
				}})
			case "integrity":
				if failure == "cancel in predicate" {
					source.closeHook = cancel
				}
				var summary AuditProducerSummary
				summary, err = VerifyAuditProducerIntegrity(ctx, source, options)
				require.Equal(t, AuditProducerSummary{}, summary)
			}
			require.Error(t, err, failure+"/"+mode)
			require.Nil(t, verified)
			require.Equal(t, 1, source.closeCalls)
			require.True(t, snapshot.closed)
			if failure == "joined" {
				require.ErrorIs(t, err, first)
				require.ErrorIs(t, err, closing)
			}
			if failure == "cancel before" || failure == "cancel in predicate" || failure == "cancel in close" {
				require.ErrorIs(t, err, context.Canceled)
			}
			cancel()
			var output bytes.Buffer
			require.NoError(t, verified.ExportJSONLines(&output, RecordOrderChain))
			require.Zero(t, output.Len())
		}
	}
}

func TestPortableAuditProducerHeadAndByteInventoryCannotBeChangedThroughInputs(t *testing.T) {
	fixture := producerChain(t, [][]Event{{{Name: "first"}}, {{Name: "second"}}}, false, -1)
	snapshot := fixture.snapshot(t, nil)
	head, err := CaptureAuditProducerHead(fixture.head, fixture.options.ExpectedProducerId, false)
	require.NoError(t, err)
	expected := head.Checkpoint()
	fixture.head[0] ^= 1
	fixture.segments[0].Hash[0] ^= 1
	raw, err := snapshot.Head(t.Context())
	require.NoError(t, err)
	raw[0] ^= 1
	verified, err := VerifyAuditProducerSnapshot(t.Context(), snapshot, fixture.options)
	require.NoError(t, err)
	require.Equal(t, expected, verified.Summary.Checkpoint)
	returned := head.Checkpoint()
	returned[0] ^= 1
	require.Equal(t, expected, head.Checkpoint())
	for _, invalid := range []*AuditProducerHead{nil, {}} {
		source, options, _ := frozenProducerSnapshot(t, false)
		options.Mode = AuditProducerCapturedPrefix
		result, err := InspectCapturedAuditProducer(t.Context(), source, invalid, options, nil)
		require.Error(t, err)
		require.Equal(t, AuditProducerSummary{}, result)
		require.True(t, source.closed)
	}
}

func TestPortableAuditProducerRejectsBadHeadAndProvisionalVisitorFailure(t *testing.T) {
	snapshot, options, _ := frozenProducerSnapshot(t, false)
	snapshot.head[len(snapshot.head)-1] ^= 1
	visits := 0
	summary, err := InspectAuditProducerSnapshot(t.Context(), snapshot, options, func(VerifiedRecord, int64) error {
		visits++
		return nil
	})
	require.Error(t, err)
	require.Zero(t, visits)
	require.Equal(t, AuditProducerSummary{}, summary)
	require.True(t, snapshot.closed)
	snapshot, options, _ = frozenProducerSnapshot(t, false)
	callbackErr, closeErr := errors.New("provisional visitor failed"), errors.New("close failed")
	source := &faultProducerSnapshot{AuditByteSnapshot: snapshot, closeErr: closeErr}
	summary, err = InspectAuditProducerSnapshot(t.Context(), source, options, func(VerifiedRecord, int64) error { return callbackErr })
	require.ErrorIs(t, err, callbackErr)
	require.ErrorIs(t, err, closeErr)
	require.Equal(t, AuditProducerSummary{}, summary)
	require.Equal(t, 1, source.closeCalls)
	require.Zero(t, source.revalidateCalls)
}

func TestPortableAuditProducerChecksActiveAliasAndSequenceBounds(t *testing.T) {
	fixture := producerChain(t, [][]Event{{{Name: "first"}}, {{Name: "second"}}}, false, -1)
	last := fixture.segments[1]
	verified, err := VerifyAuditProducerSnapshot(t.Context(), fixture.snapshot(t, &AuditActiveSegment{Image: last.Image, AliasOfPublished: last.Sequence}), fixture.options)
	require.NoError(t, err)
	require.EqualValues(t, 2, verified.Summary.SegmentCount, "the last published alias must not be counted twice")
	_, err = NewAuditByteSnapshot(fixture.head, fixture.segments, &AuditActiveSegment{Image: fixture.segments[0].Image, AliasOfPublished: 1})
	require.Error(t, err)
	fixture.segments[1].Sequence = 3
	verified, err = VerifyAuditProducerSnapshot(t.Context(), fixture.snapshot(t, nil), fixture.options)
	require.Error(t, err)
	require.Nil(t, verified)
	_, err = NewAuditByteSnapshot(fixture.head, []AuditPublishedSegment{{Sequence: 2, Image: last.Image}, {Sequence: 1, Image: last.Image}}, nil)
	require.Error(t, err)
	_, err = NewAuditByteSnapshot(bytes.Repeat([]byte{0}, nativeformat.MaxMetadataPayload+1), nil, nil)
	require.Error(t, err)
}

func TestPortableAuditProducerActivePrefixAndCapturedHeadRemainFixed(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		data, identity, segment, _ := scanCodecVector(t, encrypted)
		name := "baudit-v1"
		if encrypted {
			name = "beaudit-v1"
		}
		headBytes := readCodecVector(t, name+"-head.cbor")
		_, offsets := codecUnits(t, data)
		active := &AuditActiveSegment{Image: scanVectorImage(t, data[:offsets[3]])}
		options := AuditProducerOptions{Auditlog: "vector", ExpectedProducerId: identity.ProducerId(), ExpectedEncryptionRecipient: segment.ExpectedEncryptionRecipient}
		snapshot, err := NewAuditByteSnapshot(headBytes, nil, active)
		require.NoError(t, err)
		verified, err := VerifyAuditProducerSnapshot(t.Context(), snapshot, options)
		require.NoError(t, err)
		require.EqualValues(t, 2, verified.Summary.RecordCount)
		require.EqualValues(t, 1, verified.Summary.SegmentCount)
		active.Image = scanVectorImage(t, append(bytes.Clone(data[:offsets[3]]), 0))
		snapshot, err = NewAuditByteSnapshot(headBytes, nil, active)
		require.NoError(t, err)
		verified, err = VerifyAuditProducerSnapshot(t.Context(), snapshot, options)
		require.Error(t, err)
		require.Nil(t, verified)
		options.Mode = AuditProducerCapturedPrefix
		snapshot, err = NewAuditByteSnapshot(headBytes, nil, active)
		require.NoError(t, err)
		verified, err = VerifyAuditProducerSnapshot(t.Context(), snapshot, options)
		require.NoError(t, err)
		require.Len(t, verified.Records(), 2)
	}
	fixture := producerChain(t, [][]Event{{{Name: "captured"}, {Name: "newer"}}}, false, 0)
	head, err := CaptureAuditProducerHead(fixture.head, fixture.options.ExpectedProducerId, false)
	require.NoError(t, err)
	later := producerChain(t, [][]Event{{{Name: "different history"}}}, false, -1)
	// A new source head cannot substitute the opaque head already captured by
	// a live retry. The old checkpoint is absent in this unrelated signed chain.
	fixture.options.Mode = AuditProducerCapturedPrefix
	summary, err := InspectCapturedAuditProducer(t.Context(), later.snapshot(t, nil), head, fixture.options, nil)
	require.Error(t, err)
	require.Equal(t, AuditProducerSummary{}, summary)
}

func TestPortableAuditRecordBudgetsAndSelectionPreserveNativeBounds(t *testing.T) {
	count, size, err := ConsumeRecordBudget(MaxMaterializedAuditRecords-1, 0, 1, true)
	require.NoError(t, err)
	_, _, err = ConsumeRecordBudget(count, size, 1, true)
	require.ErrorContains(t, err, "materialization limit")
	count, size, err = ConsumeRecordBudget(MaxMaterializedAuditRecords, MaxMaterializedAuditBytes, 1, false)
	require.NoError(t, err)
	require.EqualValues(t, MaxMaterializedAuditRecords+1, count)
	require.EqualValues(t, MaxMaterializedAuditBytes, size)
	_, _, err = ConsumeRecordBudget(math.MaxUint64, 0, 1, false)
	require.Error(t, err)
	selected := NewSelectedRecords(RecordSelection{Limit: 2, Matches: func(record VerifiedRecord) bool { return record.Event.Name != "skip" }})
	require.NoError(t, selected.Add(VerifiedRecord{Event: Event{Name: "skip"}}, MaxMaterializedAuditBytes+1))
	for _, name := range []string{"first", "second", "third"} {
		require.NoError(t, selected.Add(VerifiedRecord{Event: Event{Name: name}}, MaxMaterializedAuditBytes/2))
	}
	records := selected.Records()
	require.Equal(t, "second", records[0].Event.Name)
	require.Equal(t, "third", records[1].Event.Name)
	require.Error(t, selected.Add(VerifiedRecord{}, MaxMaterializedAuditBytes/2+1))
	require.Equal(t, records, selected.Records())
	clone := selected.Clone()
	require.NoError(t, clone.Add(VerifiedRecord{Event: Event{Name: "fourth"}}, 1))
	require.Equal(t, records, selected.Records())
	var output bytes.Buffer
	require.NoError(t, ExportVerifiedRecords(&output, []VerifiedRecord{{Auditlog: "z"}, {Auditlog: "a"}}, RecordOrderChronological, false))
	decoder := json.NewDecoder(&output)
	var first VerifiedRecord
	require.NoError(t, decoder.Decode(&first))
	require.Equal(t, "a", first.Auditlog)
}
