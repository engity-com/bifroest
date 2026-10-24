//go:build !js

package browserauth

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Optional native WebCrypto interoperability, without a Node runtime dependency
// in Bifröst or in the portable core. Set BIFROEST_TEST_NODE for a required run.
// This is NOT browser/IndexedDB/UI coverage.
func TestChallengeInteroperatesWithNonExportableWebCryptoSigningKey(t *testing.T) {
	node := os.Getenv("BIFROEST_TEST_NODE")
	if node == "" {
		var err error
		node, err = exec.LookPath("node")
		if err != nil {
			t.Skip("Node/WebCrypto unavailable")
		}
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		if exec.CommandContext(ctx, node, "--version").Run() != nil {
			t.Skip("Node/WebCrypto runtime is not configured")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, node, "--input-type=module", "-e", webCryptoProofTestScript)
	stdin, err := command.StdinPipe()
	require.NoError(t, err)
	stdout, err := command.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, command.Start())
	t.Cleanup(func() { _ = stdin.Close(); _ = command.Process.Kill(); _ = command.Wait() })
	scanner := bufio.NewScanner(stdout)
	require.True(t, scanner.Scan(), "WebCrypto did not create its independent non-exportable keys")
	var initial struct {
		PublicKey             PublicKey `json:"publicKey"`
		SigningExtractable    bool      `json:"signingExtractable"`
		EncryptionExtractable bool      `json:"encryptionExtractable"`
		ExportDenied          bool      `json:"exportDenied"`
	}
	require.NoError(t, json.Unmarshal(scanner.Bytes(), &initial))
	require.False(t, initial.SigningExtractable)
	require.False(t, initial.EncryptionExtractable)
	require.True(t, initial.ExportDenied)
	challenge, err := NewChallenge(initial.PublicKey, proofTestContext())
	require.NoError(t, err)
	require.NoError(t, json.NewEncoder(stdin).Encode(base64.StdEncoding.EncodeToString(challenge.Bytes())))
	require.True(t, scanner.Scan(), "WebCrypto did not return a possession signature")
	var encoded string
	require.NoError(t, json.Unmarshal(scanner.Bytes(), &encoded))
	signature, err := base64.StdEncoding.Strict().DecodeString(encoded)
	require.NoError(t, err)
	require.Len(t, signature, 64)
	require.NoError(t, challenge.Verify(signature))
	require.NoError(t, stdin.Close())
	require.NoError(t, command.Wait())
}

const webCryptoProofTestScript = `
import { webcrypto } from 'node:crypto';
import { createInterface } from 'node:readline';
const { subtle } = webcrypto;
const signing = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
const encryption = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
let exportDenied = true;
for (const [format, key] of [['pkcs8', signing.privateKey], ['raw', encryption]]) {
  try { await subtle.exportKey(format, key); exportDenied = false; } catch (error) {
    if (error.name !== 'InvalidAccessException' && error.name !== 'InvalidAccessError') throw error;
  }
}
console.log(JSON.stringify({ publicKey: Buffer.from(await subtle.exportKey('raw', signing.publicKey)).toString('base64'), signingExtractable: signing.privateKey.extractable, encryptionExtractable: encryption.extractable, exportDenied }));
for await (const line of createInterface({ input: process.stdin })) {
  const payload = Buffer.from(JSON.parse(line), 'base64');
  const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signing.privateKey, payload);
  console.log(JSON.stringify(Buffer.from(signature).toString('base64')));
  break;
}
`
