package recording

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"io"
	"math"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestBECastWriterRoundTripCheckpointAndSeal(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	recipient, identities := newBECastTestEncryption(t)
	secret := []byte("BECast distinctive encrypted terminal output")
	result := CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2104 * time.Millisecond)}
	exitStatus := uint32(0)

	var container bytes.Buffer
	writer, err := NewBECastWriter(&container, identity, recipient, header, metadata, 0)
	require.NoError(t, err)
	require.False(t, bytes.Contains(container.Bytes(), secret))
	require.Equal(t, []byte(castBECastFileMagic), container.Bytes()[:len(castBECastFileMagic)])

	initial := parseBECastTestContainer(t, container.Bytes())
	require.Len(t, initial.chunks, 1)
	require.Nil(t, initial.seal)
	require.Contains(t, string(decryptBECastTestChunk(t, identities, initial.chunks[0].ciphertext)), castMetadataCommentPrefix)
	require.Equal(t, recipient.Fingerprint(), initial.header.RecipientFingerprint)
	publicKey, err := audit.VerifySessionRecordingBECastHeader(initial.header)
	require.NoError(t, err)
	require.Equal(t, identity.PublicKey().Marshal(), publicKey.Marshal())

	initialHead, err := writer.Checkpoint()
	require.NoError(t, err)
	require.NoError(t, audit.VerifySessionRecordingBECastHead(publicKey, initialHead))
	require.Equal(t, uint8(castBECastOpenCastState), initialHead.CastState)
	require.Equal(t, metadata.StartedAt.Unix(), initialHead.StartedAtUnixSeconds)
	require.Equal(t, uint32(metadata.StartedAt.Nanosecond()), initialHead.StartedAtNanoseconds)
	require.Equal(t, initial.chunks[0].value.ContentHashState, initialHead.ContentHashState)
	require.Equal(t, initial.chunks[0].value.ContentHashBytes, initialHead.ContentHashBytes)
	require.NotZero(t, initialHead.ContentHashBytes)
	require.Zero(t, initialHead.ContentHashBytes%64)

	require.NoError(t, writer.WriteOutput(248*time.Millisecond, OutputStreamTerminal, secret))
	head, err := writer.Checkpoint()
	require.NoError(t, err)
	require.NoError(t, audit.VerifySessionRecordingBECastHead(publicKey, head))
	require.NotZero(t, head.ContentHashBytes)
	require.Zero(t, head.ContentHashBytes%64)
	require.NoError(t, writer.WriteOutput(500*time.Millisecond, OutputStreamTerminal, []byte{0xff, 0x00}))
	require.NoError(t, writer.WriteResize(1001*time.Millisecond, 132, 43))
	summary, err := writer.Seal(2104*time.Millisecond, result, &exitStatus)
	require.NoError(t, err)

	parsed := parseBECastTestContainer(t, container.Bytes())
	require.NotNil(t, parsed.seal)
	require.GreaterOrEqual(t, len(parsed.chunks), 3)
	require.Equal(t, uint64(len(parsed.chunks)), summary.ChunkCount)
	require.Equal(t, uint64(parsed.sealOffset), parsed.seal.PrefixBytes)
	require.Equal(t, recipient.Fingerprint(), summary.RecipientFingerprint)
	require.Equal(t, metadata.RecordingId, summary.RecordingId)
	require.Equal(t, metadata.ProducerId, summary.ProducerId)
	require.Equal(t, result.Status, summary.Status)
	require.Equal(t, hashBECastUnit(parsed.headerUnit), parsed.seal.HeaderUnitHash)
	require.Equal(t, hashBECastUnit(parsed.chunks[len(parsed.chunks)-1].unit), parsed.seal.LastChunkUnitHash)
	require.Equal(t, head.LastUnitHash, hashBECastUnit(parsed.chunks[1].unit))
	require.Equal(t, head.PrefixBytes, uint64(parsed.chunks[1].endOffset))

	var decryptedCast bytes.Buffer
	var ciphertexts bytes.Buffer
	var castBytes, ciphertextBytes uint64
	previousHash := hashBECastUnit(parsed.headerUnit)
	for index, chunk := range parsed.chunks {
		require.NoError(t, audit.VerifySessionRecordingBECastChunk(publicKey, chunk.value))
		require.Equal(t, uint64(index+1), chunk.value.Sequence)
		require.Equal(t, previousHash, chunk.value.PreviousUnitHash)
		require.Equal(t, castBytes, chunk.value.PlaintextOffset)
		plaintext := decryptBECastTestChunk(t, identities, chunk.ciphertext)
		require.Equal(t, uint32(len(plaintext)), chunk.value.PlaintextLength)
		_, err := decryptedCast.Write(plaintext)
		require.NoError(t, err)
		_, err = ciphertexts.Write(chunk.ciphertext)
		require.NoError(t, err)
		castBytes += uint64(len(plaintext))
		ciphertextBytes += uint64(len(chunk.ciphertext))
		previousHash = hashBECastUnit(chunk.unit)
		if index == len(parsed.chunks)-1 {
			require.Equal(t, uint8(1), chunk.value.FinalStatus)
			require.Zero(t, chunk.value.ContentHashBytes)
			require.Equal(t, audit.SessionRecordingHash(summary.Digest), chunk.value.ContentHashState)
		} else {
			require.Zero(t, chunk.value.FinalStatus)
			require.NotZero(t, chunk.value.ContentHashBytes)
			require.Zero(t, chunk.value.ContentHashBytes%64)
		}
	}
	require.NoError(t, audit.VerifySessionRecordingBECastSeal(publicKey, *parsed.seal))
	require.Equal(t, castBytes, summary.CastBytes)
	require.Equal(t, castBytes, parsed.seal.CastBytes)
	require.Equal(t, ciphertextBytes, summary.CiphertextBytes)
	require.Equal(t, ciphertextBytes, parsed.seal.CiphertextBytes)
	require.Equal(t, hashSessionRecording(castBECastCiphertextStreamHashDomain, ciphertexts.Bytes()), summary.CiphertextStreamHash)
	require.Equal(t, summary.CiphertextStreamHash, parsed.seal.CiphertextStreamHash)
	require.Equal(t, audit.SessionRecordingHash(summary.Digest), parsed.seal.CastContentDigest)
	require.False(t, bytes.Contains(container.Bytes(), secret))

	var expected bytes.Buffer
	expectedWriter, err := NewCastWriter(&expected, identity, header, metadata)
	require.NoError(t, err)
	_, err = padCastForSha256Checkpoint(expectedWriter)
	require.NoError(t, err)
	require.NoError(t, expectedWriter.WriteOutput(248*time.Millisecond, OutputStreamTerminal, secret))
	_, err = padCastForSha256Checkpoint(expectedWriter)
	require.NoError(t, err)
	require.NoError(t, expectedWriter.WriteOutput(500*time.Millisecond, OutputStreamTerminal, []byte{0xff, 0x00}))
	require.NoError(t, expectedWriter.WriteResize(1001*time.Millisecond, 132, 43))
	expectedDigest, err := expectedWriter.Seal(2104*time.Millisecond, result, &exitStatus)
	require.NoError(t, err)
	require.Equal(t, expected.Bytes(), decryptedCast.Bytes())
	require.Equal(t, expectedDigest, summary.Digest)
	_, err = VerifyCast(bytes.NewReader(decryptedCast.Bytes()), CastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
}

func TestBECastWriterLargeOutputFlushesCompleteAtomicGroups(t *testing.T) {
	identity, header, metadata := castTestValues(t, false)
	recipient, identities := newBECastTestEncryption(t)
	var container bytes.Buffer
	writer, err := NewBECastWriter(&container, identity, recipient, header, metadata, 128)
	require.NoError(t, err)

	data := bytes.Repeat([]byte("large-stderr-payload-"), MaximumOutputEventBytes/8)
	require.Greater(t, len(data), 2*MaximumOutputEventBytes)
	require.NoError(t, writer.WriteOutput(time.Second, OutputStreamStderr, data))
	active := parseBECastTestContainer(t, container.Bytes())
	require.Greater(t, len(active.chunks), 3)

	exitStatus := uint32(0)
	_, err = writer.Seal(2*time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, &exitStatus)
	require.NoError(t, err)
	sealed := parseBECastTestContainer(t, container.Bytes())
	for _, chunk := range sealed.chunks {
		plaintext := decryptBECastTestChunk(t, identities, chunk.ciphertext)
		lines := bytes.Split(bytes.TrimSuffix(plaintext, []byte{'\n'}), []byte{'\n'})
		for index, line := range lines {
			if bytes.HasPrefix(line, []byte(castEventCommentPrefix)) {
				require.Less(t, index+1, len(lines), "atomic Cast group was split")
				require.True(t, bytes.HasPrefix(lines[index+1], []byte{'['}))
			}
			if bytes.HasPrefix(line, []byte(castResultCommentPrefix)) {
				require.Less(t, index+1, len(lines), "atomic Cast group was split")
				require.True(t, bytes.HasPrefix(lines[index+1], []byte(castSignatureCommentPrefix)))
			}
		}
	}
}

func TestBECastWriterUsesIndependentRandomizedEncryption(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	recipient, _ := newBECastTestEncryption(t)
	var first, second bytes.Buffer
	firstWriter, err := NewBECastWriter(&first, identity, recipient, header, metadata, 0)
	require.NoError(t, err)
	secondWriter, err := NewBECastWriter(&second, identity, recipient, header, metadata, 0)
	require.NoError(t, err)
	firstChunk := parseBECastTestContainer(t, first.Bytes()).chunks[0].ciphertext
	secondChunk := parseBECastTestContainer(t, second.Bytes()).chunks[0].ciphertext
	require.NotEqual(t, firstChunk, secondChunk)

	exitStatus := uint32(0)
	result := CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Millisecond)}
	_, err = firstWriter.Seal(time.Millisecond, result, &exitStatus)
	require.NoError(t, err)
	_, err = secondWriter.Seal(time.Millisecond, result, &exitStatus)
	require.NoError(t, err)
}

func TestBECastWriterRejectsNilAndInvalidArguments(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	recipient, _ := newBECastTestEncryption(t)
	var output bytes.Buffer

	_, err := NewBECastWriter(nil, identity, recipient, header, metadata, 0)
	require.ErrorContains(t, err, "nil BECast output")
	_, err = NewBECastWriter(&output, nil, recipient, header, metadata, 0)
	require.ErrorContains(t, err, "nil BECast signing identity")
	_, err = NewBECastWriter(&output, identity, nil, header, metadata, 0)
	require.ErrorContains(t, err, "nil BECast age SSH recipient")
	signingRecipient, err := bfcrypto.NewAgeSshRecipient(identity.PublicKey().ToSsh())
	require.NoError(t, err)
	_, err = NewBECastWriter(&output, identity, signingRecipient, header, metadata, 0)
	require.ErrorContains(t, err, "must differ from the signing identity")
	require.True(t, bferrors.Config.IsErr(err))
	_, err = NewBECastWriter(&output, identity, recipient, header, metadata, -1)
	require.ErrorContains(t, err, "plaintext chunk target")
	_, err = NewBECastWriter(&output, identity, recipient, header, metadata, MaximumBECastChunkPlaintext+1)
	require.ErrorContains(t, err, "plaintext chunk target")

	invalidHeader := header
	invalidHeader.Version++
	_, err = NewBECastWriter(&output, identity, recipient, invalidHeader, metadata, 0)
	require.ErrorContains(t, err, "unsupported asciicast version")
	otherIdentity, _, _ := castTestValuesWithSeed(t, true, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	_, err = NewBECastWriter(&output, otherIdentity, recipient, header, metadata, 0)
	require.ErrorContains(t, err, "producer ID does not match")

	var nilWriter *BECastWriter
	require.Error(t, nilWriter.WriteOutput(0, OutputStreamTerminal, []byte("x")))
	require.Error(t, nilWriter.WriteResize(0, 1, 1))
	require.Error(t, nilWriter.WriteMarker(0, "x"))
	require.Error(t, nilWriter.Flush())
	_, err = nilWriter.Checkpoint()
	require.Error(t, err)
	_, err = nilWriter.Seal(0, CastResult{}, nil)
	require.Error(t, err)
}

func TestBECastWriterIsPoisonedAfterShortWrite(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	recipient, _ := newBECastTestEncryption(t)
	output := &limitedCastTestWriter{maximum: math.MaxInt}
	writer, err := NewBECastWriter(output, identity, recipient, header, metadata, 1)
	require.NoError(t, err)
	output.maximum = output.Len() + 10

	err = writer.WriteOutput(time.Millisecond, OutputStreamTerminal, []byte("cannot be committed"))
	require.ErrorIs(t, err, io.ErrShortWrite)
	require.True(t, bferrors.System.IsErr(err))
	written := output.Len()
	require.ErrorIs(t, writer.WriteMarker(2*time.Millisecond, "ignored"), io.ErrShortWrite)
	require.Equal(t, written, output.Len())
	require.ErrorIs(t, writer.Flush(), io.ErrShortWrite)
}

type beCastTestChunk struct {
	value      audit.SessionRecordingBECastChunk
	ciphertext []byte
	unit       []byte
	endOffset  int
}

type beCastTestContainer struct {
	header     audit.SessionRecordingBECastHeader
	headerUnit []byte
	chunks     []beCastTestChunk
	seal       *audit.SessionRecordingBECastSeal
	sealOffset int
}

func parseBECastTestContainer(t *testing.T, container []byte) beCastTestContainer {
	t.Helper()
	require.True(t, bytes.HasPrefix(container, []byte(castBECastFileMagic)))
	offset := len(castBECastFileMagic)
	headerUnit, next := nextBECastTestUnit(t, container, offset)
	header, err := decodeBECastHeader(headerUnit)
	require.NoError(t, err)
	result := beCastTestContainer{header: header, headerUnit: headerUnit}
	offset = next
	for offset < len(container) {
		unitOffset := offset
		unit, nextOffset := nextBECastTestUnit(t, container, offset)
		switch unit[4] {
		case castBECastChunkUnitType:
			value, ciphertext, err := decodeBECastChunk(unit, header.RecordingId, header.ProducerId)
			require.NoError(t, err)
			result.chunks = append(result.chunks, beCastTestChunk{value: value, ciphertext: ciphertext, unit: unit, endOffset: nextOffset})
		case castBECastSealUnitType:
			seal, err := decodeBECastSeal(unit, header.RecordingId, header.ProducerId)
			require.NoError(t, err)
			result.seal = &seal
			result.sealOffset = unitOffset
			require.Equal(t, len(container), nextOffset)
		default:
			require.FailNow(t, "unexpected BECast unit", "type %d", unit[4])
		}
		offset = nextOffset
	}
	return result
}

func nextBECastTestUnit(t *testing.T, container []byte, offset int) ([]byte, int) {
	t.Helper()
	require.LessOrEqual(t, offset+castBECastUnitPrefixSize, len(container))
	bodyLength := int(binary.BigEndian.Uint32(container[offset+8:]))
	end := offset + castBECastUnitPrefixSize + bodyLength + castBECastUnitTrailerSize
	require.LessOrEqual(t, end, len(container))
	return container[offset:end], end
}

func decryptBECastTestChunk(t *testing.T, identities *bfcrypto.AgeSshIdentities, ciphertext []byte) []byte {
	t.Helper()
	decrypted, err := identities.Decrypt(bytes.NewReader(ciphertext))
	require.NoError(t, err)
	frame, err := io.ReadAll(decrypted)
	require.NoError(t, err)
	decoder, err := zstd.NewReader(nil)
	require.NoError(t, err)
	defer decoder.Close()
	plaintext, err := decoder.DecodeAll(frame, nil)
	require.NoError(t, err)
	return plaintext
}

func newBECastTestEncryption(t *testing.T) (*bfcrypto.AgeSshRecipient, *bfcrypto.AgeSshIdentities) {
	t.Helper()
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey, err := bfcrypto.PrivateKeyFromSdk(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	recipient, err := bfcrypto.NewAgeSshRecipient(privateKey.PublicKey().ToSsh())
	require.NoError(t, err)
	identities, err := bfcrypto.NewAgeSshIdentities([]bfcrypto.PrivateKey{privateKey})
	require.NoError(t, err)
	return recipient, identities
}
