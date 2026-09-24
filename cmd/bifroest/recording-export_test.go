package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	goerrors "errors"
	"fmt"
	stdos "os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
	"github.com/engity-com/bifroest/pkg/recording"
)

func TestRecordingExportWritesExactCastForEveryFormat(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	for _, test := range []struct {
		name       string
		path       string
		identities []string
		expected   []byte
	}{
		{name: "cast", path: fixture.castPath, expected: fixture.cast},
		{name: "bcast", path: fixture.nativeClearPath, expected: fixture.nativeCast},
		{name: "becast-cbor", path: fixture.nativeEncryptedPath, identities: []string{fixture.identityPath}, expected: fixture.nativeCast},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			err := doRecordingExport(&recordingExportOpts{
				file: test.path, expectedProducerId: fixture.identity.ProducerId().String(), decryptionIdentityFiles: test.identities, withSensitive: true,
			}, &stdout)
			require.NoError(t, err)
			require.Equal(t, test.expected, stdout.Bytes())
		})
	}
}

func TestRecordingExportRequiresSensitiveConsentBeforeAccessingInput(t *testing.T) {
	for _, name := range []string{"missing.cast", "missing.bcast", "missing.becast"} {
		t.Run(name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "export.cast")
			var stdout bytes.Buffer
			err := doRecordingExport(&recordingExportOpts{file: filepath.Join(t.TempDir(), name), output: output, allowUntrusted: true}, &stdout)
			require.ErrorContains(t, err, "--with-sensitive")
			require.Empty(t, stdout.Bytes())
			_, err = stdos.Stat(output)
			require.ErrorIs(t, err, stdos.ErrNotExist)
		})
	}
}

func TestRecordingExportRejectsLegacyMagicWithoutOutput(t *testing.T) {
	for _, test := range []struct {
		name, file string
		magic      []byte
	}{
		{"binary-becast", "recording.becast", []byte("\x89BECAST\n")},
		{"cast-zstd", "recording.cast.zst", []byte{0x58, 0x2a, 0x4d, 0x18}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), test.file)
			require.NoError(t, stdos.WriteFile(path, test.magic, 0600))
			var stdout bytes.Buffer
			opts := recordingExportOpts{file: path, allowUntrusted: true, withSensitive: true}
			require.ErrorContains(t, doRecordingExport(&opts, &stdout), "unsupported Recording format")
			require.Empty(t, stdout.Bytes())
			opts.output = filepath.Join(t.TempDir(), "export.cast")
			require.ErrorContains(t, doRecordingExport(&opts, &stdout), "unsupported Recording format")
			_, err := stdos.Stat(opts.output)
			require.ErrorIs(t, err, stdos.ErrNotExist)
		})
	}
}

func TestRecordingExportRequiresExplicitTrustDecision(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	var stdout bytes.Buffer
	require.ErrorContains(t, doRecordingExport(&recordingExportOpts{file: fixture.castPath, withSensitive: true}, &stdout), "--expectedProducerId is required")
	require.Empty(t, stdout.Bytes())

	require.NoError(t, doRecordingExport(&recordingExportOpts{file: fixture.castPath, allowUntrusted: true, withSensitive: true}, &stdout))
	require.Equal(t, fixture.cast, stdout.Bytes())
	stdout.Reset()

	err := doRecordingExport(&recordingExportOpts{
		file: fixture.castPath, expectedProducerId: fixture.identity.ProducerId().String(), allowUntrusted: true, withSensitive: true,
	}, &stdout)
	require.ErrorContains(t, err, "mutually exclusive")
	require.Empty(t, stdout.Bytes())
}

func TestRecordingExportProducesNoOutputOnVerificationOrDecryptionFailure(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	otherIdentityPath := writeRecordingExportTestPrivateKey(t, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize)))
	for _, test := range []struct {
		name string
		opts recordingExportOpts
		want string
	}{
		{
			name: "wrong-producer",
			opts: recordingExportOpts{file: fixture.castPath, expectedProducerId: newRecordingExportTestIdentity(t).ProducerId().String(), withSensitive: true},
			want: "instead of",
		},
		{
			name: "missing-decryption-identity",
			opts: recordingExportOpts{file: fixture.nativeEncryptedPath, expectedProducerId: fixture.identity.ProducerId().String(), withSensitive: true},
			want: "requires at least one",
		},
		{name: "wrong-decryption-identity", opts: recordingExportOpts{file: fixture.nativeEncryptedPath, expectedProducerId: fixture.identity.ProducerId().String(), decryptionIdentityFiles: []string{otherIdentityPath}, withSensitive: true}, want: "cannot fully verify"},
		{name: "native-wrong-producer", opts: recordingExportOpts{file: fixture.nativeClearPath, expectedProducerId: newRecordingExportTestIdentity(t).ProducerId().String(), withSensitive: true}, want: "producer mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			err := doRecordingExport(&test.opts, &stdout)
			require.ErrorContains(t, err, test.want)
			require.Empty(t, stdout.Bytes())
		})
	}

	tampered := filepath.Join(t.TempDir(), "tampered.cast")
	require.NoError(t, stdos.WriteFile(tampered, append(append([]byte(nil), fixture.cast...), []byte("trailing data\n")...), 0600))
	var stdout bytes.Buffer
	err := doRecordingExport(&recordingExportOpts{file: tampered, allowUntrusted: true, withSensitive: true}, &stdout)
	require.Error(t, err)
	require.Empty(t, stdout.Bytes())
}

func TestRecordingExportNativeFailureDoesNotReplaceOutput(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	contents, err := stdos.ReadFile(fixture.nativeEncryptedPath)
	require.NoError(t, err)
	contents[len(contents)/2] ^= 1
	require.NoError(t, stdos.WriteFile(fixture.nativeEncryptedPath, contents, 0600))
	output := filepath.Join(t.TempDir(), "export.cast")
	require.NoError(t, stdos.WriteFile(output, []byte("keep"), 0600))
	err = doRecordingExport(&recordingExportOpts{file: fixture.nativeEncryptedPath, output: output, force: true, withSensitive: true, expectedProducerId: fixture.identity.ProducerId().String(), decryptionIdentityFiles: []string{fixture.identityPath}}, &bytes.Buffer{})
	require.Error(t, err)
	actual, err := stdos.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, "keep", string(actual))
}

func TestRecordingExportNativeDecryptionFailureDoesNotReplaceOutput(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	wrongKey := writeRecordingExportTestPrivateKey(t, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize)))
	output := filepath.Join(t.TempDir(), "export.cast")
	require.NoError(t, stdos.WriteFile(output, []byte("keep"), 0600))
	err := doRecordingExport(&recordingExportOpts{
		file: fixture.nativeEncryptedPath, output: output, force: true, withSensitive: true,
		expectedProducerId: fixture.identity.ProducerId().String(), decryptionIdentityFiles: []string{wrongKey},
	}, &bytes.Buffer{})
	require.ErrorContains(t, err, "cannot fully verify")
	actual, err := stdos.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, "keep", string(actual))
}

func TestRecordingExportSnapshotIsIndependentOfLaterInputMutation(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	input, info, err := openRecordingInput(fixture.castPath)
	require.NoError(t, err)
	snapshot, err := snapshotRecordingInput(input, info.Size())
	require.NoError(t, err)
	require.NoError(t, input.Close())
	t.Cleanup(func() {
		require.NoError(t, snapshot.Close())
		err := stdos.Remove(snapshot.Name())
		require.True(t, err == nil || goerrors.Is(err, stdos.ErrNotExist), err)
	})
	require.NoError(t, stdos.WriteFile(fixture.castPath, bytes.Repeat([]byte("x"), int(info.Size())), 0600))

	options := recording.InspectOptions{AllowUntrusted: true}
	inspection, err := recording.Inspect(snapshot, info.Size(), options)
	require.NoError(t, err)
	var output bytes.Buffer
	require.NoError(t, exportRecordingPayload(snapshot, info.Size(), &output, inspection, options, nil))
	require.Equal(t, fixture.cast, output.Bytes())
}

func TestRecordingExportRejectsOversizedCastBeforeSnapshot(t *testing.T) {
	err := validateRecordingSnapshotSize(recordingExportCastPrefix{}, recording.DefaultMaximumCastBytes+1)
	require.ErrorContains(t, err, "exceeds")
}

func TestRecordingExportRejectsOversizedNativeBeforeSnapshot(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	for _, path := range []string{fixture.nativeClearPath, fixture.nativeEncryptedPath} {
		contents, err := stdos.ReadFile(path)
		require.NoError(t, err)
		err = validateRecordingSnapshotSize(bytes.NewReader(contents), recording.DefaultMaximumNativeRecordingBytes+1)
		require.ErrorContains(t, err, "exceeds")
	}
}

type recordingExportCastPrefix struct{}

func (recordingExportCastPrefix) ReadAt(target []byte, _ int64) (int, error) {
	clear(target)
	target[0] = '{'
	return len(target), nil
}

func TestRecordingExportInstallsPrivateOutputWithoutClobbering(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	output := filepath.Join(t.TempDir(), "export.cast")
	opts := recordingExportOpts{file: fixture.castPath, output: output, expectedProducerId: fixture.identity.ProducerId().String(), withSensitive: true}
	require.NoError(t, doRecordingExport(&opts, &bytes.Buffer{}))
	raw, err := stdos.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, fixture.cast, raw)
	info, err := stdos.Stat(output)
	require.NoError(t, err)
	requireAuditOutputPrivate(t, output, info)

	require.NoError(t, stdos.WriteFile(output, []byte("preserve me"), 0600))
	require.Error(t, doRecordingExport(&opts, &bytes.Buffer{}))
	raw, err = stdos.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, "preserve me", string(raw))
	opts.force = true
	require.NoError(t, doRecordingExport(&opts, &bytes.Buffer{}))
	raw, err = stdos.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, fixture.cast, raw)
}

func TestRecordingExportNativeEncryptedInstallsPrivateOutput(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	output := filepath.Join(t.TempDir(), "export.cast")
	opts := recordingExportOpts{file: fixture.nativeEncryptedPath, output: output, withSensitive: true, expectedProducerId: fixture.identity.ProducerId().String(), decryptionIdentityFiles: []string{fixture.identityPath}}
	require.NoError(t, doRecordingExport(&opts, &bytes.Buffer{}))
	actual, err := stdos.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, fixture.nativeCast, actual)
	info, err := stdos.Stat(output)
	require.NoError(t, err)
	requireAuditOutputPrivate(t, output, info)
	keyBefore, err := stdos.ReadFile(fixture.identityPath)
	require.NoError(t, err)
	opts.output = fixture.identityPath
	opts.force = true
	require.ErrorContains(t, doRecordingExport(&opts, &bytes.Buffer{}), "must not replace private key")
	keyAfter, err := stdos.ReadFile(fixture.identityPath)
	require.NoError(t, err)
	require.Equal(t, keyBefore, keyAfter)
}

func TestRecordingExportNativeCastVerifiesIndependently(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	for _, test := range []struct {
		name       string
		path       string
		identities []string
	}{
		{name: "clear", path: fixture.nativeClearPath},
		{name: "encrypted", path: fixture.nativeEncryptedPath, identities: []string{fixture.identityPath}},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "signed.cast")
			err := doRecordingExport(&recordingExportOpts{
				file: test.path, output: output, expectedProducerId: fixture.identity.ProducerId().String(),
				decryptionIdentityFiles: test.identities, withSensitive: true,
			}, &bytes.Buffer{})
			require.NoError(t, err)
			castBytes, err := stdos.ReadFile(output)
			require.NoError(t, err)
			cast, err := recording.VerifyCast(bytes.NewReader(castBytes), recording.CastVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()})
			require.NoError(t, err)
			container, err := stdos.ReadFile(test.path)
			require.NoError(t, err)
			verified, err := recording.VerifyNativeRecordingOuter(bytes.NewReader(container), int64(len(container)), recording.NativeRecordingVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()})
			require.NoError(t, err)
			require.Equal(t, recording.CastDigest(verified.Seal.CastDigest), cast.Digest)
			require.Equal(t, verified.Seal.CastBytes, uint64(len(castBytes)))
			var inspected bytes.Buffer
			require.NoError(t, doRecordingInspect(&recordingInspectOpts{file: output, expectedProducerId: fixture.identity.ProducerId().String()}, &inspected))
			var result recordingInspectOutput
			require.NoError(t, json.Unmarshal(inspected.Bytes(), &result))
			require.Equal(t, recording.FormatCast, result.Format)
			require.Equal(t, cast.Digest.String(), result.CastDigest)
			require.True(t, result.Signature.Trusted)
			info, err := stdos.Stat(output)
			require.NoError(t, err)
			requireAuditOutputPrivate(t, output, info)
		})
	}
}

func TestRecordingExportRejectsCorruptLastNativeChunkWithoutOutput(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "clear"
		if encrypted {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newRecordingExportTestFixture(t)
			path := fixture.nativeClearPath
			identities := []string(nil)
			if encrypted {
				path, identities = fixture.nativeEncryptedPath, []string{fixture.identityPath}
			}
			container, err := stdos.ReadFile(path)
			require.NoError(t, err)
			reader := bytes.NewReader(container)
			offset := int64(len(nativeformat.RecordingMagic))
			var lastChunkOffset int64
			var chunkCount int
			for {
				unit, next, tail, err := nativeformat.ReadUnitAt(reader, offset, int64(len(container)), nativeformat.MaxRecordingChunkPayload)
				require.NoError(t, err)
				require.False(t, tail)
				if unit.Type == nativeformat.SealUnit {
					break
				}
				if unit.Type == nativeformat.ContentUnit {
					lastChunkOffset = offset
					chunkCount++
				}
				offset = next
			}
			require.Positive(t, lastChunkOffset)
			require.Greater(t, chunkCount, 1, "the corrupted chunk must follow an earlier valid chunk")
			container[lastChunkOffset+6] ^= 1 // Corrupt the final data unit, not its header or an earlier chunk.
			require.NoError(t, stdos.WriteFile(path, container, 0600))
			options := recordingExportOpts{file: path, expectedProducerId: fixture.identity.ProducerId().String(), decryptionIdentityFiles: identities, withSensitive: true}
			var stdout bytes.Buffer
			require.Error(t, doRecordingExport(&options, &stdout))
			require.Empty(t, stdout.Bytes())
			options.output = filepath.Join(t.TempDir(), "preserved.cast")
			require.NoError(t, stdos.WriteFile(options.output, []byte("preserved"), 0600))
			options.force = true
			require.Error(t, doRecordingExport(&options, &stdout))
			actual, err := stdos.ReadFile(options.output)
			require.NoError(t, err)
			require.Equal(t, "preserved", string(actual))
		})
	}
}

func TestRecordingExportRejectsSignedInvalidLastNativeEventWithoutOutput(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "clear"
		if encrypted {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newRecordingExportTestFixture(t)
			path := fixture.nativeClearPath
			identityFiles := []string(nil)
			var recipient *bfcrypto.AgeSshRecipient
			var identities *bfcrypto.AgeSshIdentities
			if encrypted {
				path, identityFiles = fixture.nativeEncryptedPath, []string{fixture.identityPath}
				key, err := loadAuditPrivateKey(fixture.identityPath)
				require.NoError(t, err)
				recipient, err = bfcrypto.NewAgeSshRecipient(key.PublicKey().ToSsh())
				require.NoError(t, err)
				identities, err = bfcrypto.NewAgeSshIdentities([]bfcrypto.PrivateKey{key})
				require.NoError(t, err)
			}
			container, err := stdos.ReadFile(path)
			require.NoError(t, err)
			verifyOptions := recording.NativeRecordingVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()}
			original, err := recording.VerifyNativeRecordingOuter(bytes.NewReader(container), int64(len(container)), verifyOptions)
			require.NoError(t, err)
			reader := bytes.NewReader(container)
			offset := int64(len(nativeformat.RecordingMagic))
			var lastOffset, sealOffset int64
			var lastChunk recording.NativeRecordingChunk
			for {
				unit, next, tail, err := nativeformat.ReadUnitAt(reader, offset, int64(len(container)), nativeformat.MaxRecordingChunkPayload)
				require.NoError(t, err)
				require.False(t, tail)
				if unit.Type == nativeformat.SealUnit {
					sealOffset = offset
					break
				}
				if unit.Type == nativeformat.ContentUnit {
					lastOffset = offset
					lastChunk, err = nativeformat.Unmarshal[recording.NativeRecordingChunk](unit.Payload, nativeformat.MaxRecordingChunkPayload)
					require.NoError(t, err)
				}
				offset = next
			}
			require.Positive(t, lastOffset)
			require.Greater(t, lastChunk.Sequence, uint64(1))
			decoded, err := nativeformat.DecodeStoredPayload(lastChunk.StoredPayload, identities, original.Header.Recipient, nativeformat.PayloadLimits{MaxDecoded: nativeformat.MaxRecordingDecodedChunk, MaxStored: nativeformat.MaxRecordingChunkPayload})
			require.NoError(t, err)
			group, err := nativeformat.Unmarshal[map[uint64]any](decoded, nativeformat.MaxRecordingDecodedChunk)
			require.NoError(t, err)
			events, ok := group[2].([]any)
			require.True(t, ok)
			result, ok := events[len(events)-1].(map[any]any)
			require.True(t, ok)
			result[uint64(2)] = uint64(10*365*24*time.Hour + time.Nanosecond) // Valid CBOR, invalid Cast event duration.
			decoded, err = nativeformat.Marshal(group, nativeformat.MaxRecordingDecodedChunk)
			require.NoError(t, err)
			stored, err := nativeformat.EncodeStoredPayload(decoded, recipient, nativeformat.PayloadLimits{MaxDecoded: nativeformat.MaxRecordingDecodedChunk, MaxStored: nativeformat.MaxRecordingChunkPayload})
			require.NoError(t, err)
			lastChunk.DecodedLength = uint32(len(decoded))
			lastChunk.StoredPayload = stored
			lastChunk.StoredHash = sha256.Sum256(stored)
			signer, err := recording.NewNativeRecordingSigner(fixture.identity)
			require.NoError(t, err)
			payload, err := signer.Chunk(lastChunk)
			require.NoError(t, err)
			frame, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxRecordingChunkPayload)
			require.NoError(t, err)
			prefix := append(bytes.Clone(container[:lastOffset]), frame...)
			seal := original.Seal
			seal.LastUnitHash = sha256.Sum256(append([]byte("BIFROEST-BCAST-UNIT-HASH/v1\x00"), frame...))
			seal.ContentHash = sha256.Sum256(append([]byte("BIFROEST-BCAST-CONTENT-HASH/v1\x00"), prefix...))
			payload, err = signer.Seal(seal, recording.Id(original.Header.RecordingId))
			require.NoError(t, err)
			sealFrame, err := nativeformat.EncodeUnit(nativeformat.SealUnit, payload, nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			require.Greater(t, sealOffset, lastOffset)
			forged := append(prefix, sealFrame...)
			_, err = recording.VerifyNativeRecordingOuter(bytes.NewReader(forged), int64(len(forged)), verifyOptions)
			require.NoError(t, err, "outer signatures and hashes remain valid")
			_, err = recording.VerifyNativeRecordingFull(bytes.NewReader(forged), int64(len(forged)), identities, verifyOptions)
			require.Error(t, err, "the inner event must fail full verification")
			require.NoError(t, stdos.WriteFile(path, forged, 0600))
			opts := recordingExportOpts{file: path, expectedProducerId: fixture.identity.ProducerId().String(), decryptionIdentityFiles: identityFiles, withSensitive: true}
			var stdout bytes.Buffer
			require.Error(t, doRecordingExport(&opts, &stdout))
			require.Empty(t, stdout.Bytes())
			opts.output = filepath.Join(t.TempDir(), "preserved.cast")
			require.NoError(t, stdos.WriteFile(opts.output, []byte("preserved"), 0600))
			opts.force = true
			require.Error(t, doRecordingExport(&opts, &stdout))
			actual, err := stdos.ReadFile(opts.output)
			require.NoError(t, err)
			require.Equal(t, "preserved", string(actual))
		})
	}
}

func TestRecordingExportNeverReplacesInputOrDecryptionIdentity(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	inputBefore, err := stdos.ReadFile(fixture.castPath)
	require.NoError(t, err)
	err = doRecordingExport(&recordingExportOpts{
		file: fixture.castPath, output: fixture.castPath, force: true, allowUntrusted: true, withSensitive: true,
	}, &bytes.Buffer{})
	require.ErrorContains(t, err, "must not replace Recording input")
	inputAfter, err := stdos.ReadFile(fixture.castPath)
	require.NoError(t, err)
	require.Equal(t, inputBefore, inputAfter)

	keyBefore, err := stdos.ReadFile(fixture.identityPath)
	require.NoError(t, err)
	err = doRecordingExport(&recordingExportOpts{
		file: fixture.nativeEncryptedPath, output: fixture.identityPath, force: true, allowUntrusted: true, withSensitive: true,
		decryptionIdentityFiles: []string{fixture.identityPath},
	}, &bytes.Buffer{})
	require.ErrorContains(t, err, "must not replace private key")
	keyAfter, err := stdos.ReadFile(fixture.identityPath)
	require.NoError(t, err)
	require.Equal(t, keyBefore, keyAfter)
}

func TestRecordingExportNeverWritesStandardOutputToInputOrDecryptionIdentity(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	inputBefore, err := stdos.ReadFile(fixture.castPath)
	require.NoError(t, err)
	inputOutput, err := stdos.OpenFile(fixture.castPath, stdos.O_WRONLY|stdos.O_APPEND, 0)
	require.NoError(t, err)
	err = doRecordingExport(&recordingExportOpts{file: fixture.castPath, allowUntrusted: true, withSensitive: true}, inputOutput)
	require.Error(t, err)
	require.NoError(t, inputOutput.Close())
	inputAfter, err := stdos.ReadFile(fixture.castPath)
	require.NoError(t, err)
	require.Equal(t, inputBefore, inputAfter)

	keyBefore, err := stdos.ReadFile(fixture.identityPath)
	require.NoError(t, err)
	keyOutput, err := stdos.OpenFile(fixture.identityPath, stdos.O_WRONLY|stdos.O_APPEND, 0)
	require.NoError(t, err)
	err = doRecordingExport(&recordingExportOpts{
		file: fixture.nativeEncryptedPath, allowUntrusted: true, decryptionIdentityFiles: []string{fixture.identityPath}, withSensitive: true,
	}, keyOutput)
	require.Error(t, err)
	require.NoError(t, keyOutput.Close())
	keyAfter, err := stdos.ReadFile(fixture.identityPath)
	require.NoError(t, err)
	require.Equal(t, keyBefore, keyAfter)
}

func TestRecordingExportReportsStdoutFailureAfterVerification(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	err := doRecordingExport(&recordingExportOpts{file: fixture.castPath, allowUntrusted: true, withSensitive: true}, recordingExportErrorWriter{})
	require.ErrorContains(t, err, "injected write failure")
}

type recordingExportErrorWriter struct{}

func (recordingExportErrorWriter) Write([]byte) (int, error) {
	return 0, fmt.Errorf("injected write failure")
}

type recordingExportTestFixture struct {
	castPath            string
	nativeClearPath     string
	nativeEncryptedPath string
	nativeCast          []byte
	identityPath        string
	cast                []byte
	identity            *audit.Identity
}

func newRecordingExportTestFixture(t *testing.T) recordingExportTestFixture {
	t.Helper()
	identity, header, metadata := newRecordingInspectTestValues(t)
	writeOutput := func(writer interface {
		WriteOutput(time.Duration, recording.OutputStream, []byte) error
	}) {
		t.Helper()
		require.NoError(t, writer.WriteOutput(time.Second, recording.OutputStreamStdout, []byte("sensitive terminal output\n")))
	}
	result := recording.CastResult{Status: recording.CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}
	exitStatus := uint32(0)

	var cast bytes.Buffer
	castWriter, err := recording.NewCastWriter(&cast, identity, header, metadata)
	require.NoError(t, err)
	writeOutput(castWriter)
	_, err = castWriter.Seal(2*time.Second, result, &exitStatus)
	require.NoError(t, err)

	encryptionPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, ed25519.SeedSize))
	encryptionKey, err := bfcrypto.PrivateKeyFromSdk(encryptionPrivate)
	require.NoError(t, err)
	recipient, err := bfcrypto.NewAgeSshRecipient(encryptionKey.PublicKey().ToSsh())
	require.NoError(t, err)
	root := t.TempDir()
	fixture := recordingExportTestFixture{
		castPath: filepath.Join(root, "recording.data"), cast: append([]byte(nil), cast.Bytes()...), identity: identity,
		identityPath: writeRecordingExportTestPrivateKey(t, encryptionPrivate),
	}
	for _, encrypted := range []bool{false, true} {
		var nativeRecipient *bfcrypto.AgeSshRecipient
		path := filepath.Join(root, "native.bcast")
		if encrypted {
			nativeRecipient = recipient
			path = filepath.Join(root, "native.becast")
		}
		var container bytes.Buffer
		nativeWriter, err := recording.NewNativeRecordingWriter(&container, identity, nativeRecipient, header, metadata, 300, recording.NativeRecordingWriterLimits{})
		require.NoError(t, err)
		writeOutput(nativeWriter)
		_, err = nativeWriter.Checkpoint()
		require.NoError(t, err)
		_, err = nativeWriter.Seal(2*time.Second, result, &exitStatus)
		require.NoError(t, err)
		require.NoError(t, stdos.WriteFile(path, container.Bytes(), 0600))
		if encrypted {
			fixture.nativeEncryptedPath = path
		} else {
			fixture.nativeClearPath = path
			var expected bytes.Buffer
			_, err = recording.ExportNativeRecordingCast(bytes.NewReader(container.Bytes()), int64(container.Len()), nil, &expected, recording.NativeRecordingVerifyOptions{ExpectedProducerId: identity.ProducerId()})
			require.NoError(t, err)
			fixture.nativeCast = expected.Bytes()
		}
	}
	require.NoError(t, stdos.WriteFile(fixture.castPath, cast.Bytes(), 0600))
	return fixture
}

func newRecordingExportTestIdentity(t *testing.T) *audit.Identity {
	t.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	key, err := bfcrypto.PrivateKeyFromSdk(private)
	require.NoError(t, err)
	identity, err := audit.NewIdentity(key)
	require.NoError(t, err)
	return identity
}

func writeRecordingExportTestPrivateKey(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(key, "Recording export test identity")
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "identity")
	require.NoError(t, bfcrypto.WriteBootstrapFile(path, pem.EncodeToMemory(block), false))
	return path
}
