package evidence

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/crypto/keydata"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func scanCodecVector(t *testing.T, encrypted bool) ([]byte, *PublicIdentity, AuditSegmentOptions, codecVectorHashes) {
	t.Helper()
	manifest := codecManifest(t)
	identity := codecPublicIdentity(t, codecPrivateKey(t, manifest.SigningSeedHex))
	options := AuditSegmentOptions{Sequence: 1}
	if !encrypted {
		return readCodecVector(t, "baudit-v1.baudit"), identity, options, manifest.Clear
	}
	options.ExpectedEncryptionRecipient = manifest.RecipientFingerprint
	return readCodecVector(t, "beaudit-v1.beaudit"), identity, options, manifest.Encrypted
}

func scanVectorImage(t *testing.T, data []byte) *AuditSegmentImage {
	t.Helper()
	image, err := NewAuditSegmentImage(data)
	require.NoError(t, err)
	return image
}

func TestPortableAuditSegmentImageOwnsBoundedImmutableBytes(t *testing.T) {
	data, identity, options, hashes := scanCodecVector(t, false)
	expected := bytes.Clone(data)
	image := scanVectorImage(t, data)
	require.EqualValues(t, len(data), image.Size())
	data[0] ^= 1
	output := make([]byte, image.Size())
	read, err := image.ReadAt(output, 0)
	require.NoError(t, err)
	require.Equal(t, len(expected), read)
	require.Equal(t, expected, output)
	output[0] ^= 1
	_, err = image.ReadAt(output, 0)
	require.NoError(t, err)
	require.Equal(t, expected, output)
	result, err := ScanAuditSegment(t.Context(), image, identity, options, nil)
	require.NoError(t, err)
	require.True(t, result.Sealed)
	require.Equal(t, hashes.SegmentHash, result.SegmentHash.String())
	denied, err := NewAuditSegmentImage(make([]byte, MaxAuditSegmentBytes+1))
	require.Error(t, err)
	require.Nil(t, denied)
	var missing *AuditSegmentImage
	require.Zero(t, missing.Size())
	_, err = missing.ReadAt(output, 0)
	require.ErrorIs(t, err, io.EOF)
	result, err = ScanAuditSegment(t.Context(), missing, identity, options, nil)
	require.Error(t, err)
	require.Equal(t, AuditSegmentScan{}, result)
}

func TestPortableAuditSegmentScansFrozenClearAndAgeWithIndependentPrivacyPolicy(t *testing.T) {
	manifest := codecManifest(t)
	identities, err := keydata.NewAgeSshIdentities([]keydata.PrivateKey{codecPrivateKey(t, manifest.AgeRecipientSeedHex)})
	require.NoError(t, err)
	for _, encrypted := range []bool{false, true} {
		data, identity, base, hashes := scanCodecVector(t, encrypted)
		image := scanVectorImage(t, data)
		for _, sensitive := range []bool{false, true} {
			for _, keys := range []*keydata.AgeSshIdentities{nil, identities} {
				options := base
				options.WithSensitive, options.DecryptionIdentities = sensitive, keys
				var records []AuditScannedRecord
				result, err := ScanAuditSegment(t.Context(), image, identity, options, func(record AuditScannedRecord) error {
					records = append(records, record)
					return nil
				})
				if encrypted && sensitive && keys == nil {
					require.Error(t, err)
					require.Empty(t, records)
					require.Equal(t, AuditSegmentScan{}, result)
					continue
				}
				require.NoError(t, err)
				require.True(t, result.Sealed)
				require.False(t, result.CheckpointReached)
				require.EqualValues(t, 2, result.RecordCount)
				require.Equal(t, hashes.SegmentHash, result.SegmentHash.String())
				require.Equal(t, hashes.RecordHashes[1], result.LastRecordHash.String())
				require.Len(t, records, 2)
				for index, record := range records {
					require.EqualValues(t, index, record.Index)
					require.Positive(t, record.PayloadBytes)
					require.Equal(t, hashes.RecordHashes[index], record.Hash.String())
					if sensitive {
						require.Equal(t, "fixture-flow", record.Event.Flow)
					} else {
						require.Equal(t, Event{Name: record.Event.Name, Domain: record.Event.Domain, Outcome: record.Event.Outcome}, record.Event)
					}
				}
			}
		}
	}
	data, identity, options, _ := scanCodecVector(t, true)
	wrong, err := keydata.NewAgeSshIdentities([]keydata.PrivateKey{codecPrivateKey(t, manifest.SigningSeedHex)})
	require.NoError(t, err)
	options.DecryptionIdentities = wrong
	visits := 0
	result, err := ScanAuditSegment(t.Context(), scanVectorImage(t, data), identity, options, func(AuditScannedRecord) error {
		visits++
		return nil
	})
	require.Error(t, err, "supplied keys must validate private semantics even when output is redacted")
	require.Zero(t, visits)
	require.Equal(t, AuditSegmentScan{}, result)
}

func TestPortableAuditSegmentCheckpointDoesNotSkipPublishedSuffixOrChargeIt(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		data, identity, options, hashes := scanCodecVector(t, encrypted)
		var checkpoint Hash
		require.NoError(t, checkpoint.UnmarshalText([]byte(hashes.RecordHashes[0])))
		options.Checkpoint = &checkpoint
		for _, published := range []bool{false, true} {
			options.Published = published
			visits := 0
			result, err := ScanAuditSegment(t.Context(), scanVectorImage(t, data), identity, options, func(record AuditScannedRecord) error {
				visits++
				// A quota sufficient for exactly the prefix must not be charged
				// for records after the captured checkpoint.
				require.EqualValues(t, 0, record.Index)
				return nil
			})
			require.NoError(t, err)
			require.Equal(t, 1, visits)
			require.True(t, result.CheckpointReached)
			require.Equal(t, published, result.Sealed)
			if published {
				require.EqualValues(t, 2, result.RecordCount)
				require.Equal(t, hashes.SegmentHash, result.SegmentHash.String())
			} else {
				require.EqualValues(t, 1, result.RecordCount)
				require.Equal(t, checkpoint, result.LastRecordHash)
				require.True(t, result.SegmentHash.IsZero())
			}
		}
		units, offsets := codecUnits(t, data)
		record, err := nativeformat.Unmarshal[NativeAuditRecord](units[2].Payload, nativeformat.MaxAuditRecordPayload)
		require.NoError(t, err)
		record.PrivatePayload[0] ^= 1
		payload, err := nativeformat.Marshal(record, nativeformat.MaxAuditRecordPayload)
		require.NoError(t, err)
		frame, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxAuditRecordPayload)
		require.NoError(t, err)
		badSuffix := append(bytes.Clone(data[:offsets[2]]), frame...)
		badSuffix = append(badSuffix, data[offsets[3]:]...)
		options.Published = false
		active, err := ScanAuditSegment(t.Context(), scanVectorImage(t, badSuffix), identity, options, nil)
		require.NoError(t, err, "active may stop at its valid signed checkpoint")
		require.True(t, active.CheckpointReached)
		options.Published = true
		published, err := ScanAuditSegment(t.Context(), scanVectorImage(t, badSuffix), identity, options, nil)
		require.Error(t, err, "published must still verify a later record with recomputed framing CRC")
		require.Equal(t, AuditSegmentScan{}, published)
		badSeal := bytes.Clone(data)
		badSeal[len(badSeal)-1] ^= 1
		published, err = ScanAuditSegment(t.Context(), scanVectorImage(t, badSeal), identity, options, nil)
		require.Error(t, err, "a checkpoint cannot bypass the published seal or its physical suffix")
		require.Equal(t, AuditSegmentScan{}, published)
	}
}

func TestPortableAuditSegmentCapturesCheckpointAndHandlesEmptyPrefix(t *testing.T) {
	data, identity, options, hashes := scanCodecVector(t, false)
	var expected Hash
	require.NoError(t, expected.UnmarshalText([]byte(hashes.RecordHashes[0])))
	checkpoint := expected
	options.Checkpoint = &checkpoint
	result, err := ScanAuditSegment(t.Context(), scanVectorImage(t, data), identity, options, func(AuditScannedRecord) error {
		checkpoint[0] ^= 1
		return nil
	})
	require.NoError(t, err)
	require.True(t, result.CheckpointReached)
	require.Equal(t, expected, result.LastRecordHash)
	require.EqualValues(t, 1, result.RecordCount)
	for _, published := range []bool{false, true} {
		checkpoint = Hash{}
		options.Checkpoint, options.Published = &checkpoint, published
		visits := 0
		result, err = ScanAuditSegment(t.Context(), scanVectorImage(t, data), identity, options, func(AuditScannedRecord) error {
			visits++
			return nil
		})
		require.NoError(t, err)
		require.Zero(t, visits)
		require.True(t, result.CheckpointReached)
		require.Equal(t, published, result.Sealed)
	}
	options.CheckpointReached = true
	options.Published = true
	visits := 0
	result, err = ScanAuditSegment(t.Context(), scanVectorImage(t, data), identity, options, func(AuditScannedRecord) error {
		visits++
		return nil
	})
	require.NoError(t, err)
	require.Zero(t, visits)
	require.True(t, result.Sealed)
	require.True(t, result.CheckpointReached)
	require.EqualValues(t, 2, result.RecordCount)
	options.Checkpoint = nil
	result, err = ScanAuditSegment(t.Context(), scanVectorImage(t, data), identity, options, nil)
	require.Error(t, err)
	require.Equal(t, AuditSegmentScan{}, result)
}

func TestPortableAuditSegmentReturnsZeroOnCancellationCallbackAndMalformedInput(t *testing.T) {
	data, identity, options, hashes := scanCodecVector(t, false)
	image := scanVectorImage(t, data)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, err := ScanAuditSegment(ctx, image, identity, options, nil)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, AuditSegmentScan{}, result)
	var checkpoint Hash
	require.NoError(t, checkpoint.UnmarshalText([]byte(hashes.RecordHashes[0])))
	options.Checkpoint = &checkpoint
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	result, err = ScanAuditSegment(ctx, image, identity, options, func(AuditScannedRecord) error {
		cancel()
		return nil
	})
	require.ErrorIs(t, err, context.Canceled, "cancellation from the checkpoint callback must not become early success")
	require.Equal(t, AuditSegmentScan{}, result)
	denied := errors.New("selected output quota exhausted")
	result, err = ScanAuditSegment(t.Context(), image, identity, options, func(AuditScannedRecord) error { return denied })
	require.ErrorIs(t, err, denied)
	require.Equal(t, AuditSegmentScan{}, result)
	options.Checkpoint = nil
	for _, malformed := range [][]byte{
		nil,
		[]byte(nativeformat.RecordingMagic),
		data[:len(data)-1],
		append(bytes.Clone(data), 0),
	} {
		result, err = ScanAuditSegment(t.Context(), scanVectorImage(t, malformed), identity, options, nil)
		require.Error(t, err)
		require.Equal(t, AuditSegmentScan{}, result)
	}
}
