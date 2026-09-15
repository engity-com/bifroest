package recording

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"hash/crc32"
	"io"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
)

type beCastVerifierFixture struct {
	identity   *audit.Identity
	recipient  *bfcrypto.AgeSshRecipient
	identities *bfcrypto.AgeSshIdentities
	container  []byte
	plaintext  []byte
	summary    BECastSummary
}

func TestVerifyBECastOuterOnlySuccessAndTrust(t *testing.T) {
	fixture := newBECastVerifierFixture(t)
	trusted, err := VerifyBECast(bytes.NewReader(fixture.container), int64(len(fixture.container)), BECastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, fixture.summary, trusted.Summary)
	require.Equal(t, fixture.identity.ProducerId(), trusted.Header.ProducerId)
	require.Equal(t, fixture.recipient.Fingerprint(), trusted.Header.RecipientFingerprint)
	require.True(t, trusted.Trusted)
	require.Nil(t, trusted.Cast)

	untrusted, err := VerifyBECast(bytes.NewReader(fixture.container), int64(len(fixture.container)), BECastVerifyOptions{AllowUntrusted: true})
	require.NoError(t, err)
	require.False(t, untrusted.Trusted)
	require.Nil(t, untrusted.Cast)

	_, err = VerifyBECast(bytes.NewReader(fixture.container), int64(len(fixture.container)), BECastVerifyOptions{})
	require.ErrorContains(t, err, "expected producer ID")
	require.True(t, bferrors.Config.IsErr(err))
}

func TestDecryptBECastRoundTripAndSummary(t *testing.T) {
	fixture := newBECastVerifierFixture(t)
	var output bytes.Buffer
	verification, err := DecryptBECast(bytes.NewReader(fixture.container), int64(len(fixture.container)), fixture.identities, &output, BECastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, fixture.plaintext, output.Bytes())
	require.Equal(t, fixture.summary, verification.Summary)
	require.NotNil(t, verification.Cast)
	require.Equal(t, fixture.summary.Digest, verification.Cast.Digest)
	require.True(t, verification.Cast.Trusted)

	output.Reset()
	untrusted, err := DecryptBECast(bytes.NewReader(fixture.container), int64(len(fixture.container)), fixture.identities, &output, BECastVerifyOptions{AllowUntrusted: true})
	require.NoError(t, err)
	require.False(t, untrusted.Trusted)
	require.False(t, untrusted.Cast.Trusted)
}

func TestVerifyBECastRejectsBoundariesLimitsAndUnsupportedInput(t *testing.T) {
	fixture := newBECastVerifierFixture(t)
	parsed := parseBECastTestContainer(t, fixture.container)
	options := BECastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()}

	truncations := []int{
		0,
		len(castBECastFileMagic) - 1,
		len(castBECastFileMagic),
		len(castBECastFileMagic) + castBECastUnitPrefixSize,
		parsed.chunks[0].endOffset - 1,
		parsed.sealOffset + castBECastUnitPrefixSize,
		len(fixture.container) - 1,
	}
	for _, size := range truncations {
		t.Run("truncate-"+time.Duration(size).String(), func(t *testing.T) {
			_, err := VerifyBECast(bytes.NewReader(fixture.container[:size]), int64(size), options)
			require.Error(t, err)
			require.True(t, bferrors.System.IsErr(err))
		})
	}

	tests := map[string]struct {
		container []byte
		size      int64
		options   BECastVerifyOptions
		contains  string
		config    bool
	}{
		"trailing data": {
			container: append(append([]byte(nil), fixture.container...), 0),
			size:      int64(len(fixture.container) + 1),
			options:   options,
			contains:  "data after",
		},
		"container limit": {
			container: fixture.container,
			size:      int64(len(fixture.container)),
			options:   BECastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId(), MaximumContainerBytes: int64(len(fixture.container) - 1)},
			contains:  "outside the supported range",
		},
		"Cast limit": {
			container: fixture.container,
			size:      int64(len(fixture.container)),
			options:   BECastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId(), MaximumCastBytes: int64(fixture.summary.CastBytes - 1)},
			contains:  "plaintext exceeds",
		},
		"chunk limit": {
			container: fixture.container,
			size:      int64(len(fixture.container)),
			options:   BECastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId(), MaximumChunks: fixture.summary.ChunkCount - 1},
			contains:  "exceeds",
		},
		"negative container limit": {
			container: fixture.container,
			size:      int64(len(fixture.container)),
			options:   BECastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId(), MaximumContainerBytes: -1},
			contains:  "must be positive",
			config:    true,
		},
		"negative Cast limit": {
			container: fixture.container,
			size:      int64(len(fixture.container)),
			options:   BECastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId(), MaximumCastBytes: -1},
			contains:  "must be positive",
			config:    true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyBECast(bytes.NewReader(test.container), test.size, test.options)
			require.ErrorContains(t, err, test.contains)
			if test.config {
				require.True(t, bferrors.Config.IsErr(err))
			} else {
				require.True(t, bferrors.System.IsErr(err))
			}
		})
	}

	wrongMagic := append([]byte(nil), fixture.container...)
	wrongMagic[0] ^= 1
	_, err := VerifyBECast(bytes.NewReader(wrongMagic), int64(len(wrongMagic)), options)
	require.ErrorContains(t, err, "file magic")

	oversizedUnit := append([]byte(nil), fixture.container...)
	firstChunkOffset := parsed.chunks[0].endOffset - len(parsed.chunks[0].unit)
	binary.BigEndian.PutUint32(oversizedUnit[firstChunkOffset+8:], uint32(castBECastChunkDescriptorSize+MaximumBECastCiphertext+1))
	_, err = VerifyBECast(bytes.NewReader(oversizedUnit), int64(len(oversizedUnit)), options)
	require.ErrorContains(t, err, "invalid body size")

	otherIdentity, _, _ := castTestValuesWithSeed(t, true, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	_, err = VerifyBECast(bytes.NewReader(fixture.container), int64(len(fixture.container)), BECastVerifyOptions{ExpectedProducerId: otherIdentity.ProducerId()})
	require.ErrorContains(t, err, "instead of")

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = VerifyBECast(bytes.NewReader(fixture.container), int64(len(fixture.container)), BECastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId(), Context: canceled})
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, bferrors.System.IsErr(err))
}

func TestVerifyBECastRejectsUnsupportedAndInvalidHeaders(t *testing.T) {
	fixture := newBECastVerifierFixture(t)
	parsed := parseBECastTestContainer(t, fixture.container)
	options := BECastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()}

	invalidSignature := parsed.header
	invalidSignature.Signature[0] ^= 1
	invalidSignatureUnit, err := encodeBECastHeader(invalidSignature)
	require.NoError(t, err)
	invalidSignatureContainer := append([]byte(castBECastFileMagic), invalidSignatureUnit...)
	_, err = VerifyBECast(bytes.NewReader(invalidSignatureContainer), int64(len(invalidSignatureContainer)), options)
	require.Error(t, err)
	require.True(t, bferrors.System.IsErr(err))

	selfEncrypted, err := fixture.identity.NewSessionRecordingBECastHeader(castBECastFormatVersion, castVersion, castBECastCodec, castBECastEncryption, parsed.header.RecordingId, fixture.identity.Fingerprint())
	require.NoError(t, err)
	selfEncryptedUnit, err := encodeBECastHeader(selfEncrypted)
	require.NoError(t, err)
	selfEncryptedContainer := append([]byte(castBECastFileMagic), selfEncryptedUnit...)
	_, err = VerifyBECast(bytes.NewReader(selfEncryptedContainer), int64(len(selfEncryptedContainer)), options)
	require.ErrorContains(t, err, "encryption recipient matches its signing identity")
	require.True(t, bferrors.System.IsErr(err))

	tests := map[string][4]uint8{
		"format":     {castBECastFormatVersion + 1, castVersion, castBECastCodec, castBECastEncryption},
		"Cast":       {castBECastFormatVersion, castVersion + 1, castBECastCodec, castBECastEncryption},
		"codec":      {castBECastFormatVersion, castVersion, castBECastCodec + 1, castBECastEncryption},
		"encryption": {castBECastFormatVersion, castVersion, castBECastCodec, castBECastEncryption + 1},
	}
	for name, constants := range tests {
		t.Run(name, func(t *testing.T) {
			header, err := fixture.identity.NewSessionRecordingBECastHeader(constants[0], constants[1], constants[2], constants[3], parsed.header.RecordingId, parsed.header.RecipientFingerprint)
			require.NoError(t, err)
			headerUnit, err := encodeBECastHeader(header)
			require.NoError(t, err)
			container := rewriteBECastTestContainer(t, fixture.container, fixture.identity, headerUnit, nil, nil)
			_, err = VerifyBECast(bytes.NewReader(container), int64(len(container)), options)
			require.ErrorContains(t, err, "unsupported BECast header")
		})
	}

	headerAfterHeader := append([]byte(nil), fixture.container...)
	firstChunkOffset := parsed.chunks[0].endOffset - len(parsed.chunks[0].unit)
	headerAfterHeader[firstChunkOffset+4] = castBECastHeaderUnitType
	_, err = VerifyBECast(bytes.NewReader(headerAfterHeader), int64(len(headerAfterHeader)), options)
	require.ErrorContains(t, err, "unexpected BECast unit type")
}

func TestVerifyBECastRejectsUnitIntegrityAndSignatureCorruption(t *testing.T) {
	fixture := newBECastVerifierFixture(t)
	parsed := parseBECastTestContainer(t, fixture.container)
	options := BECastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()}
	chunkStart := parsed.chunks[0].endOffset - len(parsed.chunks[0].unit)
	chunkCRC := parsed.chunks[0].endOffset - castBECastUnitTrailerSize
	sealCRC := len(fixture.container) - castBECastUnitTrailerSize

	tests := map[string]func([]byte){
		"CRC": func(value []byte) {
			value[chunkCRC] ^= 1
		},
		"commit": func(value []byte) {
			value[chunkCRC+4] ^= 1
		},
		"ciphertext hash": func(value []byte) {
			value[chunkStart+castBECastUnitPrefixSize+castBECastChunkDescriptorSize] ^= 1
			refreshBECastTestCRC(value, chunkStart, chunkCRC)
		},
		"chunk signature": func(value []byte) {
			value[chunkStart+castBECastUnitPrefixSize+130] ^= 1
			refreshBECastTestCRC(value, chunkStart, chunkCRC)
		},
		"seal signature": func(value []byte) {
			value[parsed.sealOffset+castBECastUnitPrefixSize+162] ^= 1
			refreshBECastTestCRC(value, parsed.sealOffset, sealCRC)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			container := append([]byte(nil), fixture.container...)
			mutate(container)
			_, err := VerifyBECast(bytes.NewReader(container), int64(len(container)), options)
			require.Error(t, err)
			require.True(t, bferrors.System.IsErr(err))
			if name == "chunk signature" {
				require.ErrorContains(t, err, "illegal session recording signature")
			}
		})
	}
}

func TestVerifyBECastRejectsSignedChunkAndSealMismatches(t *testing.T) {
	fixture := newBECastVerifierFixture(t)
	options := BECastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()}
	parsed := parseBECastTestContainer(t, fixture.container)

	chunkTests := map[string]func(int, *audit.SessionRecordingBECastChunk, *[]byte){
		"sequence": func(index int, value *audit.SessionRecordingBECastChunk, _ *[]byte) {
			if index == 0 {
				value.Sequence++
			}
		},
		"chain": func(index int, value *audit.SessionRecordingBECastChunk, _ *[]byte) {
			if index == 1 {
				value.PreviousUnitHash[0] ^= 1
			}
		},
		"offset": func(index int, value *audit.SessionRecordingBECastChunk, _ *[]byte) {
			if index == 1 {
				value.PlaintextOffset++
			}
		},
		"non-final content count": func(index int, value *audit.SessionRecordingBECastChunk, _ *[]byte) {
			if index == 0 {
				value.ContentHashBytes += 64
			}
		},
		"plaintext chunk limit": func(index int, value *audit.SessionRecordingBECastChunk, _ *[]byte) {
			if index == 0 {
				value.PlaintextLength = MaximumBECastChunkPlaintext + 1
			}
		},
	}
	for name, mutate := range chunkTests {
		t.Run(name, func(t *testing.T) {
			container := rewriteBECastTestContainer(t, fixture.container, fixture.identity, parsed.headerUnit, mutate, nil)
			_, err := VerifyBECast(bytes.NewReader(container), int64(len(container)), options)
			require.Error(t, err)
		})
	}

	sealTests := map[string]func(*audit.SessionRecordingBECastSeal){
		"status":                 func(value *audit.SessionRecordingBECastSeal) { value.Status = 99 },
		"final status":           func(value *audit.SessionRecordingBECastSeal) { value.Status = 2 },
		"chunk count":            func(value *audit.SessionRecordingBECastSeal) { value.ChunkCount++ },
		"Cast bytes":             func(value *audit.SessionRecordingBECastSeal) { value.CastBytes++ },
		"ciphertext bytes":       func(value *audit.SessionRecordingBECastSeal) { value.CiphertextBytes++ },
		"prefix offset":          func(value *audit.SessionRecordingBECastSeal) { value.PrefixBytes++ },
		"header hash":            func(value *audit.SessionRecordingBECastSeal) { value.HeaderUnitHash[0] ^= 1 },
		"last chunk hash":        func(value *audit.SessionRecordingBECastSeal) { value.LastChunkUnitHash[0] ^= 1 },
		"Cast digest":            func(value *audit.SessionRecordingBECastSeal) { value.CastContentDigest[0] ^= 1 },
		"ciphertext stream hash": func(value *audit.SessionRecordingBECastSeal) { value.CiphertextStreamHash[0] ^= 1 },
	}
	for name, mutate := range sealTests {
		t.Run(name, func(t *testing.T) {
			container := rewriteBECastTestContainer(t, fixture.container, fixture.identity, parsed.headerUnit, nil, mutate)
			_, err := VerifyBECast(bytes.NewReader(container), int64(len(container)), options)
			require.Error(t, err)
		})
	}
}

func TestVerifyBECastRejectsFinalSentinelViolations(t *testing.T) {
	fixture := newBECastVerifierFixture(t)
	parsed := parseBECastTestContainer(t, fixture.container)
	options := BECastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()}

	tests := map[string]func(int, *audit.SessionRecordingBECastChunk, *[]byte){
		"continuation after final": func(index int, value *audit.SessionRecordingBECastChunk, _ *[]byte) {
			if index == 0 {
				value.FinalStatus = 1
				value.ContentHashBytes = 0
				value.ContentHashState[0] = 1
			}
		},
		"seal without final": func(index int, value *audit.SessionRecordingBECastChunk, _ *[]byte) {
			if index == len(parsed.chunks)-1 {
				value.FinalStatus = 0
				base := uint64(len(castContentHashDomain)) + value.PlaintextOffset
				length := uint64(64) - base%64
				value.PlaintextLength = uint32(length)
				value.ContentHashBytes = base + length
			}
		},
		"final digest mismatch": func(index int, value *audit.SessionRecordingBECastChunk, _ *[]byte) {
			if index == len(parsed.chunks)-1 {
				value.ContentHashState[0] ^= 1
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			container := rewriteBECastTestContainer(t, fixture.container, fixture.identity, parsed.headerUnit, mutate, nil)
			_, err := VerifyBECast(bytes.NewReader(container), int64(len(container)), options)
			require.Error(t, err)
		})
	}
}

func TestDecryptBECastWritesNothingBeforeOuterAndInnerVerification(t *testing.T) {
	fixture := newBECastVerifierFixture(t)
	parsed := parseBECastTestContainer(t, fixture.container)
	options := BECastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()}

	outerTamper := append([]byte(nil), fixture.container...)
	outerTamper[len(outerTamper)-1] ^= 1
	_ = assertBECastDecryptFailureWithoutOutput(t, outerTamper, fixture.identities, options)

	ageTamper := rewriteBECastTestContainer(t, fixture.container, fixture.identity, parsed.headerUnit, func(index int, _ *audit.SessionRecordingBECastChunk, ciphertext *[]byte) {
		if index == 0 {
			(*ciphertext)[len(*ciphertext)-1] ^= 1
		}
	}, nil)
	_ = assertBECastDecryptFailureWithoutOutput(t, ageTamper, fixture.identities, options)

	changedContinuationPlaintext := decryptBECastTestChunk(t, fixture.identities, parsed.chunks[0].ciphertext)
	changedContinuationPlaintext[0] ^= 1
	changedContinuation := encryptBECastTestPlaintext(t, fixture.recipient, changedContinuationPlaintext)
	changedContinuationContainer := rewriteBECastTestContainer(t, fixture.container, fixture.identity, parsed.headerUnit, func(index int, _ *audit.SessionRecordingBECastChunk, ciphertext *[]byte) {
		if index == 0 {
			*ciphertext = changedContinuation
		}
	}, nil)
	_ = assertBECastDecryptFailureWithoutOutput(t, changedContinuationContainer, fixture.identities, options)

	corruptFrame := encryptBECastTestFrame(t, fixture.recipient, []byte("not a Zstandard frame"))
	corruptCompressed := rewriteBECastTestContainer(t, fixture.container, fixture.identity, parsed.headerUnit, func(index int, _ *audit.SessionRecordingBECastChunk, ciphertext *[]byte) {
		if index == 0 {
			*ciphertext = corruptFrame
		}
	}, nil)
	_ = assertBECastDecryptFailureWithoutOutput(t, corruptCompressed, fixture.identities, options)

	last := len(parsed.chunks) - 1
	finalPlaintext := decryptBECastTestChunk(t, fixture.identities, parsed.chunks[last].ciphertext)
	signature := bytes.Index(finalPlaintext, []byte(castSignatureCommentPrefix))
	require.NotEqual(t, -1, signature)
	finalPlaintext[len(finalPlaintext)-2] ^= 1
	invalidInner := encryptBECastTestPlaintext(t, fixture.recipient, finalPlaintext)
	invalidInnerContainer := rewriteBECastTestContainer(t, fixture.container, fixture.identity, parsed.headerUnit, func(index int, _ *audit.SessionRecordingBECastChunk, ciphertext *[]byte) {
		if index == last {
			*ciphertext = invalidInner
		}
	}, nil)
	_ = assertBECastDecryptFailureWithoutOutput(t, invalidInnerContainer, fixture.identities, options)
}

func TestDecryptBECastRejectsWrongRecipientAndFingerprintMismatch(t *testing.T) {
	fixture := newBECastVerifierFixture(t)
	otherRecipient, otherIdentities := newBECastVerifierEncryption(t, 0x73)
	options := BECastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()}
	err := assertBECastDecryptFailureWithoutOutput(t, fixture.container, otherIdentities, options)
	require.True(t, bferrors.Config.IsErr(err))

	parsed := parseBECastTestContainer(t, fixture.container)
	wrongHeader, err := fixture.identity.NewSessionRecordingBECastHeader(castBECastFormatVersion, castVersion, castBECastCodec, castBECastEncryption, parsed.header.RecordingId, otherRecipient.Fingerprint())
	require.NoError(t, err)
	wrongHeaderUnit, err := encodeBECastHeader(wrongHeader)
	require.NoError(t, err)
	wrongFingerprint := rewriteBECastTestContainer(t, fixture.container, fixture.identity, wrongHeaderUnit, nil, nil)

	combined, err := newBECastVerifierCombinedIdentities(0x42, 0x73)
	require.NoError(t, err)
	err = assertBECastDecryptFailureWithoutOutput(t, wrongFingerprint, combined, options)
	require.True(t, bferrors.System.IsErr(err))
}

func TestDecryptBECastDetectsCiphertextChangeBetweenPlaintextPasses(t *testing.T) {
	fixture := newBECastVerifierFixture(t)
	parsed := parseBECastTestContainer(t, fixture.container)
	firstChunkStart := parsed.chunks[0].endOffset - len(parsed.chunks[0].unit)
	reader := &changingBECastTestReaderAt{
		data:         fixture.container,
		targetOffset: int64(firstChunkStart + castBECastUnitPrefixSize + castBECastChunkDescriptorSize),
		targetLength: len(parsed.chunks[0].ciphertext),
		changeOnCall: 2,
	}
	var output bytes.Buffer
	_, err := DecryptBECast(reader, int64(len(fixture.container)), fixture.identities, &output, BECastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()})
	require.ErrorContains(t, err, "input changed")
	require.Empty(t, output.Bytes())
	require.True(t, bferrors.System.IsErr(err))
}

func newBECastVerifierFixture(t *testing.T) beCastVerifierFixture {
	t.Helper()
	identity, header, metadata := castTestValues(t, true)
	recipient, identities := newBECastTestEncryption(t)
	var container bytes.Buffer
	writer, err := NewBECastWriter(&container, identity, recipient, header, metadata, 128)
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(time.Second, OutputStreamTerminal, bytes.Repeat([]byte("verified BECast output "), 32)))
	exitStatus := uint32(0)
	summary, err := writer.Seal(2*time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, &exitStatus)
	require.NoError(t, err)
	parsed := parseBECastTestContainer(t, container.Bytes())
	var plaintext bytes.Buffer
	for _, chunk := range parsed.chunks {
		_, err := plaintext.Write(decryptBECastTestChunk(t, identities, chunk.ciphertext))
		require.NoError(t, err)
	}
	return beCastVerifierFixture{
		identity:   identity,
		recipient:  recipient,
		identities: identities,
		container:  append([]byte(nil), container.Bytes()...),
		plaintext:  plaintext.Bytes(),
		summary:    summary,
	}
}

func rewriteBECastTestContainer(t *testing.T, original []byte, identity *audit.Identity, headerUnit []byte, mutateChunk func(int, *audit.SessionRecordingBECastChunk, *[]byte), mutateSeal func(*audit.SessionRecordingBECastSeal)) []byte {
	t.Helper()
	parsed := parseBECastTestContainer(t, original)
	header, err := decodeBECastHeader(headerUnit)
	require.NoError(t, err)
	result := append([]byte(castBECastFileMagic), headerUnit...)
	previousHash := hashBECastUnit(headerUnit)
	streamHash := hashSessionRecordingWriter(castBECastCiphertextStreamHashDomain)
	var castBytes, ciphertextBytes uint64
	for index, parsedChunk := range parsed.chunks {
		value := parsedChunk.value
		ciphertext := append([]byte(nil), parsedChunk.ciphertext...)
		value.RecordingId = header.RecordingId
		value.ProducerId = header.ProducerId
		value.PreviousUnitHash = previousHash
		if mutateChunk != nil {
			mutateChunk(index, &value, &ciphertext)
		}
		value.CiphertextLength = uint32(len(ciphertext))
		value.CiphertextHash = hashBECastCiphertext(ciphertext)
		value, err = identity.NewSessionRecordingBECastChunk(value)
		require.NoError(t, err)
		unit, err := encodeBECastChunk(value, ciphertext)
		require.NoError(t, err)
		result = append(result, unit...)
		previousHash = hashBECastUnit(unit)
		castBytes += uint64(value.PlaintextLength)
		ciphertextBytes += uint64(len(ciphertext))
		_, _ = streamHash.Write(ciphertext)
	}
	seal := *parsed.seal
	seal.RecordingId = header.RecordingId
	seal.ProducerId = header.ProducerId
	seal.ChunkCount = uint64(len(parsed.chunks))
	seal.CastBytes = castBytes
	seal.CiphertextBytes = ciphertextBytes
	seal.PrefixBytes = uint64(len(result))
	seal.HeaderUnitHash = hashBECastUnit(headerUnit)
	seal.LastChunkUnitHash = previousHash
	copy(seal.CiphertextStreamHash[:], streamHash.Sum(nil))
	if mutateSeal != nil {
		mutateSeal(&seal)
	}
	seal, err = identity.NewSessionRecordingBECastSeal(seal)
	require.NoError(t, err)
	sealUnit, err := encodeBECastSeal(seal)
	require.NoError(t, err)
	return append(result, sealUnit...)
}

func encryptBECastTestPlaintext(t *testing.T, recipient *bfcrypto.AgeSshRecipient, plaintext []byte) []byte {
	t.Helper()
	encoder, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderCRC(true),
		zstd.WithEncoderConcurrency(1),
		zstd.WithWindowSize(castZstdWindowSize),
		zstd.WithSingleSegment(true),
	)
	require.NoError(t, err)
	defer encoder.Close()
	return encryptBECastTestFrame(t, recipient, encoder.EncodeAll(plaintext, nil))
}

func encryptBECastTestFrame(t *testing.T, recipient *bfcrypto.AgeSshRecipient, frame []byte) []byte {
	t.Helper()
	var result bytes.Buffer
	writer, err := recipient.Encrypt(&result)
	require.NoError(t, err)
	_, err = writer.Write(frame)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return result.Bytes()
}

func assertBECastDecryptFailureWithoutOutput(t *testing.T, container []byte, identities *bfcrypto.AgeSshIdentities, options BECastVerifyOptions) error {
	t.Helper()
	var output bytes.Buffer
	_, err := DecryptBECast(bytes.NewReader(container), int64(len(container)), identities, &output, options)
	require.Error(t, err)
	require.Empty(t, output.Bytes())
	require.True(t, bferrors.System.IsErr(err) || bferrors.Config.IsErr(err))
	return err
}

func newBECastVerifierEncryption(t *testing.T, seedByte byte) (*bfcrypto.AgeSshRecipient, *bfcrypto.AgeSshIdentities) {
	t.Helper()
	privateKey, err := bfcrypto.PrivateKeyFromSdk(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)))
	require.NoError(t, err)
	recipient, err := bfcrypto.NewAgeSshRecipient(privateKey.PublicKey().ToSsh())
	require.NoError(t, err)
	identities, err := bfcrypto.NewAgeSshIdentities([]bfcrypto.PrivateKey{privateKey})
	require.NoError(t, err)
	return recipient, identities
}

func newBECastVerifierCombinedIdentities(seedBytes ...byte) (*bfcrypto.AgeSshIdentities, error) {
	keys := make([]bfcrypto.PrivateKey, 0, len(seedBytes))
	for _, seedByte := range seedBytes {
		key, err := bfcrypto.PrivateKeyFromSdk(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)))
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return bfcrypto.NewAgeSshIdentities(keys)
}

func refreshBECastTestCRC(container []byte, unitStart, crcOffset int) {
	binary.BigEndian.PutUint32(container[crcOffset:], crc32.Checksum(container[unitStart:crcOffset], castBECastCRC32CTable))
}

type changingBECastTestReaderAt struct {
	data         []byte
	targetOffset int64
	targetLength int
	changeOnCall int
	calls        int
}

func (this *changingBECastTestReaderAt) ReadAt(target []byte, offset int64) (int, error) {
	if offset < 0 || offset >= int64(len(this.data)) {
		return 0, io.EOF
	}
	read := copy(target, this.data[offset:])
	if offset == this.targetOffset && len(target) == this.targetLength {
		this.calls++
		if this.calls == this.changeOnCall {
			target[0] ^= 1
		}
	}
	if read != len(target) {
		return read, io.EOF
	}
	return read, nil
}

var _ io.Reader = (*beCastPlaintextStream)(nil)
