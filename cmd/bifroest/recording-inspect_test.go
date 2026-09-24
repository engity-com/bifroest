package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	stdos "os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestRecordingInspectVerifiesCastAndReportsTrust(t *testing.T) {
	path, identity := writeRecordingInspectTestCast(t)
	for _, test := range []struct {
		name               string
		expectedProducerId string
		trusted            bool
	}{
		{name: "self-signed", trusted: false},
		{name: "trusted", expectedProducerId: identity.ProducerId().String(), trusted: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			require.NoError(t, doRecordingInspect(&recordingInspectOpts{file: path, expectedProducerId: test.expectedProducerId}, &stdout))
			var result recordingInspectOutput
			require.NoError(t, json.Unmarshal(stdout.Bytes(), &result))
			require.Equal(t, recordingInspectionSchema, result.Schema)
			require.Equal(t, recording.FormatCast, result.Format)
			require.Equal(t, "full", result.VerificationScope)
			require.True(t, result.Signature.Valid)
			require.Equal(t, test.trusted, result.Signature.Trusted)
			require.Equal(t, identity.ProducerId().String(), result.ProducerId)
			require.Equal(t, recording.CastStatusCompleted, result.Status)
			require.NotNil(t, result.Cast)
			require.Equal(t, uint64(1), result.Cast.OutputEvents)
			require.NotContains(t, stdout.String(), "sensitive terminal output")
			require.NotContains(t, stdout.String(), "connectionId")
			require.NotContains(t, stdout.String(), "sessionId")
			require.NotContains(t, stdout.String(), "operationId")
			require.NotContains(t, stdout.String(), "reason")
		})
	}
}

func TestRecordingInspectReportsContainerFormatsWithoutContent(t *testing.T) {
	for _, test := range []struct {
		name              string
		write             func(*testing.T) string
		format            recording.Format
		encrypted         bool
		verificationScope string
		cast              bool
	}{
		{name: "cast-zstd", write: writeRecordingInspectTestCastZstd, format: recording.FormatCastZstd, verificationScope: "full", cast: true},
		{name: "becast", write: writeRecordingInspectTestBECast, format: recording.FormatBECast, encrypted: true, verificationScope: "outer"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			require.NoError(t, doRecordingInspect(&recordingInspectOpts{file: test.write(t)}, &stdout))
			var result recordingInspectOutput
			require.NoError(t, json.Unmarshal(stdout.Bytes(), &result))
			require.Equal(t, test.format, result.Format)
			require.True(t, result.Compressed)
			require.Equal(t, test.encrypted, result.Encrypted)
			require.Equal(t, test.verificationScope, result.VerificationScope)
			require.Equal(t, test.cast, result.Cast != nil)
			require.Positive(t, result.ChunkCount)
			if test.encrypted {
				require.Empty(t, result.Status)
				require.Empty(t, result.CastDigest)
				require.NotEmpty(t, result.ClaimedCastDigest)
			}
			require.NotContains(t, stdout.String(), "sensitive terminal output")
		})
	}
}

func TestRecordingInspectNativeVerificationScopes(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	for _, test := range []struct {
		name, path string
		format     recording.Format
		scope      string
	}{
		{"clear", fixture.nativeClearPath, recording.FormatBcast, "full"},
		{"encrypted", fixture.nativeEncryptedPath, recording.FormatBECastCBOR, "outer"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			require.NoError(t, doRecordingInspect(&recordingInspectOpts{file: test.path, expectedProducerId: fixture.identity.ProducerId().String()}, &stdout))
			var result recordingInspectOutput
			require.NoError(t, json.Unmarshal(stdout.Bytes(), &result))
			require.Equal(t, test.format, result.Format)
			require.Equal(t, test.scope, result.VerificationScope)
			require.True(t, result.Signature.Trusted)
			require.True(t, result.Compressed)
			require.Equal(t, test.scope == "outer", result.Encrypted)
			require.Positive(t, result.CastBytes)
			require.Positive(t, result.ChunkCount)
			require.Nil(t, result.Cast)
			require.NotContains(t, stdout.String(), "sensitive terminal output")
			if test.scope == "outer" {
				require.NotContains(t, stdout.String(), `"castDigest":`)
				require.NotContains(t, stdout.String(), `"status":`)
				require.Empty(t, result.CastDigest)
				require.Empty(t, result.Status)
				require.NotEmpty(t, result.ClaimedCastDigest)
				require.Equal(t, recording.CastStatusCompleted, result.ClaimedStatus)
				require.NotEmpty(t, result.RecipientFingerprint)
			} else {
				require.NotEmpty(t, result.CastDigest)
				require.Equal(t, recording.CastStatusCompleted, result.Status)
				require.Empty(t, result.ClaimedCastDigest)
			}
		})
	}
}

func TestRecordingInspectNativeRejectsCorruptionAndWrongProducer(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	for _, path := range []string{fixture.nativeClearPath, fixture.nativeEncryptedPath} {
		var stdout bytes.Buffer
		err := doRecordingInspect(&recordingInspectOpts{file: path, expectedProducerId: newRecordingExportTestIdentity(t).ProducerId().String()}, &stdout)
		require.ErrorContains(t, err, "producer mismatch")
		require.Empty(t, stdout.Bytes())
		contents, err := stdos.ReadFile(path)
		require.NoError(t, err)
		contents[len(contents)/2] ^= 1
		require.NoError(t, stdos.WriteFile(path, contents, 0600))
		err = doRecordingInspect(&recordingInspectOpts{file: path}, &stdout)
		require.Error(t, err)
		require.Empty(t, stdout.Bytes())
	}
}

func TestRecordingInspectProducesNoOutputOnVerificationFailure(t *testing.T) {
	path, _ := writeRecordingInspectTestCast(t)
	file, err := stdos.OpenFile(path, stdos.O_APPEND|stdos.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = file.WriteString("trailing data\n")
	require.NoError(t, err)
	require.NoError(t, file.Close())
	var stdout bytes.Buffer
	err = doRecordingInspect(&recordingInspectOpts{file: path}, &stdout)
	require.Error(t, err)
	require.Empty(t, stdout.Bytes())
}

func TestRecordingInspectRejectsUnsafeAndUnsupportedInputs(t *testing.T) {
	root := t.TempDir()
	var stdout bytes.Buffer
	require.ErrorContains(t, doRecordingInspect(&recordingInspectOpts{file: "-"}, &stdout), "requires a file path")
	require.ErrorContains(t, doRecordingInspect(&recordingInspectOpts{file: root}, &stdout), "regular non-symlink")
	unsupported := filepath.Join(root, "recording.bin")
	require.NoError(t, stdos.WriteFile(unsupported, []byte("unsupported"), 0600))
	require.ErrorContains(t, doRecordingInspect(&recordingInspectOpts{file: unsupported}, &stdout), "unsupported Recording format")
	require.Empty(t, stdout.Bytes())

	cast, _ := writeRecordingInspectTestCast(t)
	symlink := filepath.Join(root, "recording.cast")
	if err := stdos.Symlink(cast, symlink); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	require.ErrorContains(t, doRecordingInspect(&recordingInspectOpts{file: symlink}, &stdout), "regular non-symlink")
}

func TestRecordingInspectRejectsWrongTrustAnchorAndWriterFailure(t *testing.T) {
	path, _ := writeRecordingInspectTestCast(t)
	_, otherPrivate, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	privateKey, err := bfcrypto.PrivateKeyFromSdk(otherPrivate)
	require.NoError(t, err)
	otherIdentity, err := audit.NewIdentity(privateKey)
	require.NoError(t, err)
	var stdout bytes.Buffer
	err = doRecordingInspect(&recordingInspectOpts{file: path, expectedProducerId: otherIdentity.ProducerId().String()}, &stdout)
	require.Error(t, err)
	require.Empty(t, stdout.Bytes())
	require.ErrorContains(t, doRecordingInspect(&recordingInspectOpts{file: path}, recordingInspectErrorWriter{}), "cannot write Recording inspection")
}

type recordingInspectErrorWriter struct{}

func (recordingInspectErrorWriter) Write([]byte) (int, error) {
	return 0, fmt.Errorf("injected write failure")
}

func writeRecordingInspectTestCast(t *testing.T) (string, *audit.Identity) {
	t.Helper()
	identity, header, metadata := newRecordingInspectTestValues(t)
	var content bytes.Buffer
	writer, err := recording.NewCastWriter(&content, identity, header, metadata)
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(time.Second, recording.OutputStreamStdout, []byte("sensitive terminal output\n")))
	exitStatus := uint32(0)
	_, err = writer.Seal(2*time.Second, recording.CastResult{Status: recording.CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, &exitStatus)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), metadata.RecordingId.String()+".cast")
	require.NoError(t, stdos.WriteFile(path, content.Bytes(), 0600))
	return path, identity
}

func writeRecordingInspectTestCastZstd(t *testing.T) string {
	t.Helper()
	identity, header, metadata := newRecordingInspectTestValues(t)
	var content bytes.Buffer
	writer, err := recording.NewCastZstdWriter(&content, identity, header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(time.Second, recording.OutputStreamStdout, []byte("sensitive terminal output\n")))
	exitStatus := uint32(0)
	_, err = writer.Seal(2*time.Second, recording.CastResult{Status: recording.CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, &exitStatus)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), metadata.RecordingId.String()+".cast.zst")
	require.NoError(t, stdos.WriteFile(path, content.Bytes(), 0600))
	return path
}

func writeRecordingInspectTestBECast(t *testing.T) string {
	t.Helper()
	identity, header, metadata := newRecordingInspectTestValues(t)
	_, encryptionPrivate, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	encryptionKey, err := bfcrypto.PrivateKeyFromSdk(encryptionPrivate)
	require.NoError(t, err)
	recipient, err := bfcrypto.NewAgeSshRecipient(encryptionKey.PublicKey().ToSsh())
	require.NoError(t, err)
	var content bytes.Buffer
	writer, err := recording.NewBECastWriter(&content, identity, recipient, header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(time.Second, recording.OutputStreamStdout, []byte("sensitive terminal output\n")))
	exitStatus := uint32(0)
	_, err = writer.Seal(2*time.Second, recording.CastResult{Status: recording.CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, &exitStatus)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), metadata.RecordingId.String()+".becast")
	require.NoError(t, stdos.WriteFile(path, content.Bytes(), 0600))
	return path
}

func newRecordingInspectTestValues(t *testing.T) (*audit.Identity, recording.CastHeader, recording.CastMetadata) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	privateKey, err := bfcrypto.PrivateKeyFromSdk(private)
	require.NoError(t, err)
	identity, err := audit.NewIdentity(privateKey)
	require.NoError(t, err)
	recordingId, err := recording.NewId()
	require.NoError(t, err)
	connectionId, err := connection.NewId()
	require.NoError(t, err)
	sessionId, err := session.NewId()
	require.NoError(t, err)
	startedAt := time.Now().UTC().Truncate(time.Second)
	metadata := recording.CastMetadata{
		RecordingId: recordingId, ConnectionId: connectionId, SessionId: sessionId, OperationId: uuid.New(),
		Flow: configuration.FlowName("inspect-test"), Task: audit.SessionTaskExec, ProducerId: identity.ProducerId(), StartedAt: startedAt,
	}
	header := recording.CastHeader{
		Version: recording.CastVersion, Terminal: recording.CastTerminal{Columns: 80, Rows: 24}, Timestamp: startedAt.Unix(),
	}
	return identity, header, metadata
}
