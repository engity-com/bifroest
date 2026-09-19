package main

import (
	"bytes"
	"crypto/ed25519"
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
		{name: "cast-zstd", path: fixture.castZstdPath, expected: fixture.cast},
		{name: "becast", path: fixture.beCastPath, identities: []string{fixture.identityPath}, expected: fixture.beCastCast},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			err := doRecordingExport(&recordingExportOpts{
				file: test.path, expectedProducerId: fixture.identity.ProducerId().String(), decryptionIdentityFiles: test.identities,
			}, &stdout)
			require.NoError(t, err)
			require.Equal(t, test.expected, stdout.Bytes())
		})
	}
}

func TestRecordingExportRequiresExplicitTrustDecision(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	var stdout bytes.Buffer
	require.ErrorContains(t, doRecordingExport(&recordingExportOpts{file: fixture.castPath}, &stdout), "--expectedProducerId is required")
	require.Empty(t, stdout.Bytes())

	require.NoError(t, doRecordingExport(&recordingExportOpts{file: fixture.castPath, allowUntrusted: true}, &stdout))
	require.Equal(t, fixture.cast, stdout.Bytes())
	stdout.Reset()

	err := doRecordingExport(&recordingExportOpts{
		file: fixture.castPath, expectedProducerId: fixture.identity.ProducerId().String(), allowUntrusted: true,
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
			opts: recordingExportOpts{file: fixture.castPath, expectedProducerId: newRecordingExportTestIdentity(t).ProducerId().String()},
			want: "instead of",
		},
		{
			name: "missing-decryption-identity",
			opts: recordingExportOpts{file: fixture.beCastPath, expectedProducerId: fixture.identity.ProducerId().String()},
			want: "requires at least one",
		},
		{
			name: "wrong-decryption-identity",
			opts: recordingExportOpts{file: fixture.beCastPath, expectedProducerId: fixture.identity.ProducerId().String(), decryptionIdentityFiles: []string{otherIdentityPath}},
			want: "is not available",
		},
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
	err := doRecordingExport(&recordingExportOpts{file: tampered, allowUntrusted: true}, &stdout)
	require.Error(t, err)
	require.Empty(t, stdout.Bytes())
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

type recordingExportCastPrefix struct{}

func (recordingExportCastPrefix) ReadAt(target []byte, _ int64) (int, error) {
	clear(target)
	target[0] = '{'
	return len(target), nil
}

func TestRecordingExportInstallsPrivateOutputWithoutClobbering(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	output := filepath.Join(t.TempDir(), "export.cast")
	opts := recordingExportOpts{file: fixture.castZstdPath, output: output, expectedProducerId: fixture.identity.ProducerId().String()}
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

func TestRecordingExportNeverReplacesInputOrDecryptionIdentity(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	inputBefore, err := stdos.ReadFile(fixture.castPath)
	require.NoError(t, err)
	err = doRecordingExport(&recordingExportOpts{
		file: fixture.castPath, output: fixture.castPath, force: true, allowUntrusted: true,
	}, &bytes.Buffer{})
	require.ErrorContains(t, err, "must not replace Recording input")
	inputAfter, err := stdos.ReadFile(fixture.castPath)
	require.NoError(t, err)
	require.Equal(t, inputBefore, inputAfter)

	keyBefore, err := stdos.ReadFile(fixture.identityPath)
	require.NoError(t, err)
	err = doRecordingExport(&recordingExportOpts{
		file: fixture.beCastPath, output: fixture.identityPath, force: true, allowUntrusted: true,
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
	err = doRecordingExport(&recordingExportOpts{file: fixture.castPath, allowUntrusted: true}, inputOutput)
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
		file: fixture.beCastPath, allowUntrusted: true, decryptionIdentityFiles: []string{fixture.identityPath},
	}, keyOutput)
	require.Error(t, err)
	require.NoError(t, keyOutput.Close())
	keyAfter, err := stdos.ReadFile(fixture.identityPath)
	require.NoError(t, err)
	require.Equal(t, keyBefore, keyAfter)
}

func TestRecordingExportReportsStdoutFailureAfterVerification(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	err := doRecordingExport(&recordingExportOpts{file: fixture.castPath, allowUntrusted: true}, recordingExportErrorWriter{})
	require.ErrorContains(t, err, "injected write failure")
}

type recordingExportErrorWriter struct{}

func (recordingExportErrorWriter) Write([]byte) (int, error) {
	return 0, fmt.Errorf("injected write failure")
}

type recordingExportTestFixture struct {
	castPath     string
	castZstdPath string
	beCastPath   string
	identityPath string
	cast         []byte
	beCastCast   []byte
	identity     *audit.Identity
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

	var castZstd bytes.Buffer
	castZstdWriter, err := recording.NewCastZstdWriter(&castZstd, identity, header, metadata, 300)
	require.NoError(t, err)
	writeOutput(castZstdWriter)
	_, err = castZstdWriter.Seal(2*time.Second, result, &exitStatus)
	require.NoError(t, err)

	encryptionPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, ed25519.SeedSize))
	encryptionKey, err := bfcrypto.PrivateKeyFromSdk(encryptionPrivate)
	require.NoError(t, err)
	recipient, err := bfcrypto.NewAgeSshRecipient(encryptionKey.PublicKey().ToSsh())
	require.NoError(t, err)
	var beCast bytes.Buffer
	beCastWriter, err := recording.NewBECastWriter(&beCast, identity, recipient, header, metadata, 300)
	require.NoError(t, err)
	writeOutput(beCastWriter)
	_, err = beCastWriter.Seal(2*time.Second, result, &exitStatus)
	require.NoError(t, err)
	identities, err := bfcrypto.NewAgeSshIdentities([]bfcrypto.PrivateKey{encryptionKey})
	require.NoError(t, err)
	var beCastCast bytes.Buffer
	_, err = recording.DecryptBECast(bytes.NewReader(beCast.Bytes()), int64(beCast.Len()), identities, &beCastCast, recording.BECastVerifyOptions{AllowUntrusted: true})
	require.NoError(t, err)

	root := t.TempDir()
	fixture := recordingExportTestFixture{
		castPath: filepath.Join(root, "recording.data"), castZstdPath: filepath.Join(root, "compressed.data"),
		beCastPath: filepath.Join(root, "encrypted.data"), cast: append([]byte(nil), cast.Bytes()...), identity: identity,
		beCastCast:   append([]byte(nil), beCastCast.Bytes()...),
		identityPath: writeRecordingExportTestPrivateKey(t, encryptionPrivate),
	}
	require.NoError(t, stdos.WriteFile(fixture.castPath, cast.Bytes(), 0600))
	require.NoError(t, stdos.WriteFile(fixture.castZstdPath, castZstd.Bytes(), 0600))
	require.NoError(t, stdos.WriteFile(fixture.beCastPath, beCast.Bytes(), 0600))
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
