package recording

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func TestNativeRecordingFrozenRegressionMatrix(t *testing.T) {
	seed, err := hex.DecodeString(recordingFormatVectorSigningSeedHex)
	require.NoError(t, err)
	signingKey := ed25519.NewKeyFromSeed(seed)
	_, ageIdentities := newBECastTestEncryption(t)
	otherKey, err := bfcrypto.PrivateKeyFromSdk(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x97}, ed25519.SeedSize)))
	require.NoError(t, err)
	otherIdentity, err := audit.NewIdentity(otherKey)
	require.NoError(t, err)
	magic := []byte(nativeformat.RecordingMagic)

	for _, mode := range []struct {
		name       string
		file       string
		encrypted  bool
		identities *bfcrypto.AgeSshIdentities
	}{
		{name: "clear", file: "bcast-v1.bcast"},
		{name: "age", file: "becast-v1.becast", encrypted: true, identities: ageIdentities},
	} {
		t.Run(mode.name, func(t *testing.T) {
			original := nativeRecordingVector(t, mode.file)
			require.True(t, bytes.HasPrefix(original, magic))
			var frames [4][]byte
			offset := int64(len(magic))
			for i, kind := range [...]nativeformat.UnitType{nativeformat.HeaderUnit, nativeformat.ContentUnit, nativeformat.ContentUnit, nativeformat.SealUnit} {
				maximum := nativeformat.MaxMetadataPayload
				if kind == nativeformat.ContentUnit {
					maximum = nativeformat.MaxRecordingChunkPayload
				}
				unit, next, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(original), offset, int64(len(original)), maximum)
				require.NoError(t, err)
				require.False(t, tail)
				require.Equal(t, kind, unit.Type)
				frames[i] = bytes.Clone(original[offset:next])
				offset = next
			}
			require.Equal(t, int64(len(original)), offset)

			options := NativeRecordingVerifyOptions{ExpectedProducerId: nativeVectorIdentity(t).ProducerId()}
			verified, err := VerifyNativeRecordingOuter(bytes.NewReader(original), int64(len(original)), options)
			require.NoError(t, err)
			require.True(t, verified.Trusted)
			require.Equal(t, mode.encrypted, verified.Header.Encryption == 1)
			var exported bytes.Buffer
			_, err = ExportNativeRecordingCast(bytes.NewReader(original), int64(len(original)), mode.identities, &exported, options)
			require.NoError(t, err)
			if mode.encrypted {
				require.Equal(t, nativeRecordingVector(t, "becast-v1.cast"), exported.Bytes())
			} else {
				require.Equal(t, nativeRecordingVector(t, "bcast-v1.cast"), exported.Bytes())
			}

			headerUnit, _, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(frames[0]), 0, int64(len(frames[0])), nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			require.False(t, tail)
			header, err := nativeformat.Unmarshal[nativeRecordingHeader](headerUnit.Payload, nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			// The generic CBOR map is canonical, but its typed header is not: an
			// empty optional field is omitted on re-encode, or an unknown field is rejected.
			fields, err := nativeformat.Unmarshal[map[uint64]any](headerUnit.Payload, nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			typedError := "canonically encoded"
			if mode.encrypted {
				fields[9] = uint64(0)
				typedError = "unknown field"
			} else {
				fields[7] = ""
			}
			typedPayload, err := nativeformat.Marshal(fields, nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			typedFrame, err := nativeformat.EncodeUnit(nativeformat.HeaderUnit, typedPayload, nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			typedUnit, _, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(typedFrame), 0, int64(len(typedFrame)), nativeformat.MaxMetadataPayload)
			require.NoError(t, err, "the altered header must have a valid frame and CRC")
			require.False(t, tail)
			require.Equal(t, typedPayload, typedUnit.Payload)
			_, err = nativeformat.Unmarshal[nativeRecordingHeader](typedPayload, nativeformat.MaxMetadataPayload)
			require.ErrorContains(t, err, typedError)

			// Sign the inconsistent mode so the failure is not just a stale signature.
			modeHeader := header
			modeHeader.Encryption ^= 1
			unsigned, err := nativeformat.Marshal(nativeRecordingHeaderFields(modeHeader), nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			modeHeader.Signature = ed25519.Sign(signingKey, append([]byte(nativeRecordingHeaderDomain), unsigned...))
			require.NoError(t, nativeRecordingVerify(signingKey.Public().(ed25519.PublicKey), nativeRecordingHeaderDomain, nativeRecordingHeaderFields(modeHeader), modeHeader.Signature, nativeformat.MaxMetadataPayload))
			modePayload, err := nativeformat.Marshal(modeHeader, nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			modeFrame, err := nativeformat.EncodeUnit(nativeformat.HeaderUnit, modePayload, nativeformat.MaxMetadataPayload)
			require.NoError(t, err)

			// The claimed public key and producer agree, but the old signer did the signing.
			signerHeader := header
			signerHeader.PublicKey = otherIdentity.PublicKey().Marshal()
			signerHeader.ProducerId = [32]byte(otherIdentity.ProducerId())
			unsigned, err = nativeformat.Marshal(nativeRecordingHeaderFields(signerHeader), nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			signerHeader.Signature = ed25519.Sign(signingKey, append([]byte(nativeRecordingHeaderDomain), unsigned...))
			signerPayload, err := nativeformat.Marshal(signerHeader, nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			signerFrame, err := nativeformat.EncodeUnit(nativeformat.HeaderUnit, signerPayload, nativeformat.MaxMetadataPayload)
			require.NoError(t, err)

			cases := []struct {
				name        string
				order       []int
				headerFrame []byte
				suffix      []byte
				validPrefix int
				want        string
			}{
				{name: "missing header", order: []int{1, 2, 3}, want: "invalid native recording header"},
				{name: "duplicate header", order: []int{0, 0, 1, 2, 3}, validPrefix: 1, want: "unexpected native recording unit type"},
				{name: "swapped header and continuation", order: []int{1, 0, 2, 3}, want: "invalid native recording header"},
				{name: "missing continuation chunk", order: []int{0, 2, 3}, validPrefix: 1, want: "invalid native recording chunk chain"},
				{name: "missing final chunk", order: []int{0, 1, 3}, validPrefix: 2, want: "native recording has trailing data"},
				{name: "duplicate continuation chunk", order: []int{0, 1, 1, 2, 3}, validPrefix: 2, want: "invalid native recording chunk chain"},
				{name: "duplicate final chunk", order: []int{0, 1, 2, 2, 3}, validPrefix: 3, want: "native recording exceeds chunk limit"},
				{name: "swapped continuation and final chunks", order: []int{0, 2, 1, 3}, validPrefix: 1, want: "invalid native recording chunk chain"},
				{name: "missing seal", order: []int{0, 1, 2}, validPrefix: 3, want: "native recording has no seal"},
				{name: "duplicate seal", order: []int{0, 1, 2, 3, 3}, validPrefix: 4, want: "native recording has trailing data"},
				{name: "swapped final chunk and seal", order: []int{0, 1, 3, 2}, validPrefix: 2, want: "native recording has trailing data"},
				{name: "trailing byte", order: []int{0, 1, 2, 3}, suffix: []byte{0}, validPrefix: 4, want: "native recording has trailing data"},
				{name: "noncanonical typed header with valid CRC", order: []int{0, 1, 2, 3}, headerFrame: typedFrame, want: typedError},
				{name: "signed header mode mismatch", order: []int{0, 1, 2, 3}, headerFrame: modeFrame, want: "invalid native recording header identity, version or mode"},
				{name: "signer and header key mismatch", order: []int{0, 1, 2, 3}, headerFrame: signerFrame, want: "invalid native recording signature"},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					input := bytes.Clone(magic)
					for _, index := range tc.order {
						frame := frames[index]
						if index == 0 && tc.headerFrame != nil {
							frame = tc.headerFrame
						}
						input = append(input, frame...)
					}
					input = append(input, tc.suffix...)
					prefixEnd := len(magic)
					for _, frame := range frames[:tc.validPrefix] {
						prefixEnd += len(frame)
					}
					require.Equal(t, original[:prefixEnd], input[:prefixEnd], "late failure must follow the unmodified valid prefix")
					snapshot := bytes.Clone(input)
					_, err := VerifyNativeRecordingOuter(bytes.NewReader(input), int64(len(input)), options)
					require.ErrorContains(t, err, tc.want)
					var output bytes.Buffer
					_, err = output.WriteString("sentinel")
					require.NoError(t, err)
					_, err = ExportNativeRecordingCast(bytes.NewReader(input), int64(len(input)), mode.identities, &output, options)
					require.Error(t, err)
					require.Equal(t, "sentinel", output.String(), "failed export must write no bytes")
					require.Equal(t, snapshot, input, "ReaderAt input must remain an immutable snapshot")
				})
			}
			require.Equal(t, nativeRecordingVector(t, mode.file), original, "published vector must remain unchanged")
		})
	}
}
