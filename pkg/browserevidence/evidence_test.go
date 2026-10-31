package browserevidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
	"github.com/engity-com/bifroest/pkg/crypto/keydata"
	"github.com/engity-com/bifroest/pkg/management/protocol"
)

const producerPin = "95b9aca00d322047048950d19cc5aece6fa757edd9104a5521446a168792b298"
const recipientPin = "SHA256:ZsrOVCtcb1bouzun0GIHz5vL5oCjVhVIQ3jfIBIgZ8g"
const recordingID = "34e34ab8-7457-4d88-a5e4-c57791775c3a"

func asset(t *testing.T, directory, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "assets", directory, name))
	require.NoError(t, err)
	return data
}

func recipientPrivate(t *testing.T, password string) []byte {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	var block *pem.Block
	var err error
	if password == "" {
		block, err = ssh.MarshalPrivateKey(key, "public test fixture")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "public test fixture", []byte(password))
	}
	require.NoError(t, err)
	return pem.EncodeToMemory(block)
}

func auditFiles(t *testing.T, encrypted bool) []File {
	t.Helper()
	name, hashText := "baudit-v1", "fe793ee92c2547663fbd50dec41971378d3d837bb2e6237fe06d6009d0ce9bc5"
	extension := ".baudit"
	if encrypted {
		name, hashText, extension = "beaudit-v1", "917fba80141b65171aa763ee878d45e67c9852aaa227fad87d89eb9451c3ff57", ".beaudit"
	}
	var hash evidence.Hash
	require.NoError(t, hash.UnmarshalText([]byte(hashText)))
	return []File{
		{Name: evidence.AuditSegmentName(1, hash, encrypted), Data: asset(t, "audit-format-vectors/v1", name+extension)},
		{Name: "head.cbor", Data: asset(t, "audit-format-vectors/v1", name+"-head.cbor")},
	}
}

func TestBrowserEvidenceRecordingUsesFrozenOuterPrivateAndByteExactExports(t *testing.T) {
	request := protocol.ArtifactRequest{Operation: protocol.DownloadRecording, Auditlog: "vector", ID: recordingID}
	for _, encrypted := range []bool{false, true} {
		name, recipient := "bcast-v1.bcast", ""
		if encrypted {
			name, recipient = "becast-v1.becast", recipientPin
		}
		data := asset(t, "recording-format-vectors/native-v1", name)
		files := []File{{Name: "recording", Data: data}}
		outer, err := Verify(t.Context(), request, files, Options{Producer: producerPin, Recipient: recipient, Level: "outer"}, nil, nil)
		require.NoError(t, err)
		require.Equal(t, "outer", outer.Validation)
		require.Equal(t, "pinned", outer.Trust)
		require.Empty(t, outer.Output)
		if encrypted {
			require.Equal(t, "not-checked", outer.Decryption)
		} else {
			require.Equal(t, "not-encrypted", outer.Decryption)
		}
		var private, password []byte
		if encrypted {
			private, password = recipientPrivate(t, "tab secret"), []byte("tab secret")
		}
		full, err := Verify(t.Context(), request, files, Options{Producer: producerPin, Recipient: recipient, Level: "private", Export: true}, private, password)
		require.NoError(t, err)
		require.Equal(t, "private", full.Validation)
		require.Equal(t, recordingID, full.RecordingID)
		require.Equal(t, "cast", full.OutputFormat)
		require.Equal(t, asset(t, "recording-format-vectors/native-v1", "bcast-v1.cast"), full.Output)
		if encrypted {
			require.Equal(t, "authenticated", full.Decryption)
		}
		require.Equal(t, data, files[0].Data)
		if encrypted {
			for _, pass := range [][]byte{nil, []byte("wrong secret")} {
				failed, err := Verify(t.Context(), request, files, Options{Producer: producerPin, Recipient: recipient, Level: "private", Export: true}, private, pass)
				require.ErrorIs(t, err, ErrKey)
				require.Nil(t, failed)
				require.NotContains(t, err.Error(), "secret")
			}
		}
	}
	castBytes := asset(t, "recording-format-vectors/native-v1", "bcast-v1.cast")
	verified, err := Verify(t.Context(), request, []File{{Name: "recording", Data: castBytes}}, Options{Producer: producerPin, Level: "private", Export: true}, nil, nil)
	require.NoError(t, err)
	require.Equal(t, castBytes, verified.Output)
}

func TestBrowserEvidenceAuditSeparatesRedactionPrivateValidationAndProducerTrust(t *testing.T) {
	request := protocol.ArtifactRequest{Operation: protocol.DownloadAudit, Auditlog: "vector"}
	for _, encrypted := range []bool{false, true} {
		files := auditFiles(t, encrypted)
		recipient, prefix := "", "baudit-v1"
		if encrypted {
			recipient, prefix = recipientPin, "beaudit-v1"
		}
		options := Options{Producer: producerPin, Recipient: recipient, Level: "outer", AuditScope: "complete"}
		outer, err := Verify(t.Context(), request, files, options, nil, nil)
		require.NoError(t, err)
		require.Equal(t, "2", outer.Records)
		require.Equal(t, "pinned", outer.Trust)
		if encrypted {
			require.Equal(t, "0", outer.PrivateRecords)
		}
		for _, sensitive := range []bool{false, true} {
			options.Level, options.Export, options.Sensitive = "private", true, sensitive
			var private []byte
			if encrypted {
				private = recipientPrivate(t, "")
			}
			result, err := Verify(t.Context(), request, files, options, private, nil)
			require.NoError(t, err)
			require.Equal(t, "2", result.PrivateRecords)
			suffix := "-redacted.jsonl"
			if sensitive {
				suffix = "-with-sensitive.jsonl"
			}
			require.Equal(t, asset(t, "audit-format-vectors/v1", prefix+suffix), result.Output)
			if !sensitive {
				require.NotContains(t, string(result.Output), "fixture-flow")
			}
			if encrypted {
				require.Equal(t, "authenticated", result.Decryption)
			}
		}
		options.Level, options.Export, options.Sensitive = "outer", false, false
		options.Producer, options.AllowUntrusted = "", true
		untrusted, err := Verify(t.Context(), request, files, options, nil, nil)
		require.NoError(t, err)
		require.Equal(t, "untrusted", untrusted.Trust)
		options.AllowUntrusted = false
		failed, err := Verify(t.Context(), request, files, options, nil, nil)
		require.ErrorIs(t, err, ErrInput)
		require.Nil(t, failed)
	}
}

func TestBrowserEvidenceFailureBoundariesReleaseNoOutput(t *testing.T) {
	request := protocol.ArtifactRequest{Operation: protocol.DownloadRecording, Auditlog: "vector", ID: recordingID}
	data := asset(t, "recording-format-vectors/native-v1", "becast-v1.becast")
	base := Options{Producer: producerPin, Recipient: recipientPin, Level: "private", Export: true}
	for _, scenario := range []string{"producer", "recipient", "id", "trailing", "truncated", "tampered", "missing key", "outer export", "unused key"} {
		options, selected := base, request
		content := bytes.Clone(data)
		private := recipientPrivate(t, "")
		switch scenario {
		case "producer":
			options.Producer = strings.Repeat("a", 64)
		case "recipient":
			options.Recipient = "SHA256:" + strings.Repeat("A", 43)
		case "id":
			selected.ID = "6d05798f-b877-4191-8aa0-4576a30411ad"
		case "trailing":
			content = append(content, 0)
		case "truncated":
			content = content[:len(content)-1]
		case "tampered":
			content[len(content)/2] ^= 1
		case "missing key":
			private = nil
		case "outer export":
			options.Level = "outer"
		case "unused key":
			options.Recipient = ""
		}
		result, err := Verify(t.Context(), selected, []File{{Name: "recording", Data: content}}, options, private, nil)
		require.Error(t, err, scenario)
		require.Nil(t, result)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, err := Verify(ctx, request, []File{{Name: "recording", Data: data}}, base, recipientPrivate(t, ""), nil)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, result)
	for _, name := range []string{"../head.cbor", "segment-1.baudit", "foreign", "active.beaudit"} {
		files := auditFiles(t, false)
		files = append(files, File{Name: name, Data: []byte("untrusted")})
		result, err := Verify(t.Context(), protocol.ArtifactRequest{Operation: protocol.DownloadAudit, Auditlog: "vector"}, files, Options{Producer: producerPin, Level: "private", Export: true, AuditScope: "complete"}, nil, nil)
		require.Error(t, err, name)
		require.Nil(t, result)
	}
}

func TestBrowserEvidenceLogicalAliasAndOutputBoundsDoNotClaimFilesystemProof(t *testing.T) {
	files := auditFiles(t, false)
	files = append(files, File{Name: "active.baudit", Data: bytes.Clone(files[0].Data)})
	result, err := Verify(t.Context(), protocol.ArtifactRequest{Operation: protocol.DownloadAudit, Auditlog: "vector"}, files, Options{Producer: producerPin, Level: "private", AuditScope: "complete"}, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "2", result.Records)
	var output boundedOutput
	_, readerFrom := any(&output).(io.ReaderFrom)
	require.False(t, readerFrom)
	output.data.Grow(8)
	_, err = output.Write([]byte("verified"))
	require.NoError(t, err)
	// Check the bound without allocating a full result: setting the internal
	// buffer to the exact cap is safe test data, not a source/verification stub.
	output.data = *bytes.NewBuffer(make([]byte, MaximumOutputBytes))
	_, err = output.Write([]byte{0})
	require.ErrorIs(t, err, ErrLimit)
}

func TestBrowserEvidenceBoundedRSAKeyImportUsesExistingAgeImplementation(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	public, err := ssh.NewPublicKey(private.Public())
	require.NoError(t, err)
	recipient, err := keydata.NewAgeSshRecipient(public)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "public RSA test fixture", []byte("local RSA secret"))
	require.NoError(t, err)
	keys, err := privateIdentities(pem.EncodeToMemory(block), []byte("local RSA secret"), recipient.Fingerprint())
	require.NoError(t, err)
	var ciphertext bytes.Buffer
	writer, err := recipient.Encrypt(&ciphertext)
	require.NoError(t, err)
	_, err = writer.Write([]byte("client-only evidence"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	reader, err := keys.DecryptForFingerprint(bytes.NewReader(ciphertext.Bytes()), recipient.Fingerprint())
	require.NoError(t, err)
	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, []byte("client-only evidence"), plain)
}
