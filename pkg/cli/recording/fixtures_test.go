package recording

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	bfRecording "github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

type recordingFixture struct {
	clear, encrypted, identityFile string
	identity                       *audit.Identity
	id                             bfRecording.Id
}

func createRecordingFixture(t *testing.T) recordingFixture {
	t.Helper()
	_, signingKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	private, err := bfcrypto.PrivateKeyFromSdk(signingKey)
	require.NoError(t, err)
	identity, err := audit.NewIdentity(private)
	require.NoError(t, err)
	id, err := bfRecording.NewId()
	require.NoError(t, err)
	connectionID, err := connection.NewId()
	require.NoError(t, err)
	sessionID, err := session.NewId()
	require.NoError(t, err)
	start := time.Now().UTC().Truncate(time.Second)
	metadata := bfRecording.CastMetadata{
		RecordingId: id, ConnectionId: connectionID, SessionId: sessionID, OperationId: uuid.New(),
		Flow: configuration.FlowName("recording-test"), Task: audit.SessionTaskExec,
		ProducerId: identity.ProducerId(), StartedAt: start,
	}
	header := bfRecording.CastHeader{
		Version: bfRecording.CastVersion, Terminal: bfRecording.CastTerminal{Columns: 80, Rows: 24}, Timestamp: start.Unix(),
	}
	_, encryptionKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	key, err := bfcrypto.PrivateKeyFromSdk(encryptionKey)
	require.NoError(t, err)
	recipient, err := bfcrypto.NewAgeSshRecipient(key.PublicKey().ToSsh())
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(encryptionKey, "recording-test")
	require.NoError(t, err)
	root := t.TempDir()
	result := recordingFixture{identity: identity, id: id, identityFile: filepath.Join(root, "decrypt.key")}
	require.NoError(t, bfcrypto.WriteBootstrapFile(result.identityFile, pem.EncodeToMemory(block), false))
	for _, encrypted := range []bool{false, true} {
		var target *bfcrypto.AgeSshRecipient
		name := "clear.bcast"
		if encrypted {
			target = recipient
			name = "encrypted.becast"
		}
		var content bytes.Buffer
		writer, err := bfRecording.NewNativeRecordingWriter(&content, identity, target, header, metadata, 300, bfRecording.NativeRecordingWriterLimits{})
		require.NoError(t, err)
		require.NoError(t, writer.WriteOutput(time.Second, bfRecording.OutputStreamStdout, []byte("sensitive terminal output\n")))
		_, err = writer.Checkpoint()
		require.NoError(t, err)
		exitStatus := uint32(0)
		_, err = writer.Seal(2*time.Second, bfRecording.CastResult{Status: bfRecording.CastStatusCompleted, EndedAt: start.Add(2 * time.Second)}, &exitStatus)
		require.NoError(t, err)
		path := filepath.Join(root, name)
		require.NoError(t, os.WriteFile(path, content.Bytes(), 0600))
		if encrypted {
			result.encrypted = path
		} else {
			result.clear = path
		}
	}
	return result
}
