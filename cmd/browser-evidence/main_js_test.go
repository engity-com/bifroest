//go:build js && wasm

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"syscall/js"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/browserevidence"
)

func testBuffer(t *testing.T, data []byte) js.Value {
	t.Helper()
	value := js.Global().Get("Uint8Array").New(len(data))
	require.Equal(t, len(data), js.CopyBytesToJS(value, data))
	return value
}

func TestEvidenceBridgeUsesFrozenNativeCoreAndNeverReturnsPlaintextOnFailure(t *testing.T) {
	root := filepath.Join("..", "..", "docs", "assets", "recording-format-vectors", "native-v1")
	data, err := os.ReadFile(filepath.Join(root, "becast-v1.becast"))
	require.NoError(t, err)
	golden, err := os.ReadFile(filepath.Join(root, "becast-v1.cast"))
	require.NoError(t, err)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "public bridge test key", []byte("tab secret"))
	require.NoError(t, err)
	key := pem.EncodeToMemory(block)
	options := browserevidence.Options{Producer: "95b9aca00d322047048950d19cc5aece6fa757edd9104a5521446a168792b298", Recipient: "SHA256:ZsrOVCtcb1bouzun0GIHz5vL5oCjVhVIQ3jfIBIgZ8g", Level: "private", Export: true}
	for _, scenario := range []string{"success", "wrong passphrase", "wrong producer", "outer export", "truncated", "unknown option"} {
		used = false
		requested, content, password := options, bytes.Clone(data), []byte("tab secret")
		switch scenario {
		case "wrong passphrase":
			password = []byte("private wrong secret")
		case "wrong producer":
			requested.Producer = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		case "outer export":
			requested.Level = "outer"
		case "truncated":
			content = content[:len(content)-1]
		}
		encoded, err := json.Marshal(requested)
		require.NoError(t, err)
		if scenario == "unknown option" {
			encoded = append(encoded[:len(encoded)-1], []byte(`,"url":"https://forbidden.invalid"}`)...)
		}
		files := js.Global().Get("Array").New()
		files.Call("push", map[string]any{"name": "recording", "data": testBuffer(t, content)})
		result := verify(js.Undefined(), []js.Value{js.ValueOf("recording"), js.ValueOf("vector"), js.ValueOf("34e34ab8-7457-4d88-a5e4-c57791775c3a"), js.ValueOf(string(encoded)), files, testBuffer(t, key), testBuffer(t, password)}).(map[string]any)
		if scenario == "success" {
			require.Equal(t, true, result["ok"])
			var metadata browserevidence.Result
			require.NoError(t, json.Unmarshal([]byte(result["metadata"].(string)), &metadata))
			require.Equal(t, "pinned", metadata.Trust)
			require.Equal(t, "private", metadata.Validation)
			require.Equal(t, "authenticated", metadata.Decryption)
			output := result["output"].(js.Value)
			copied := make([]byte, output.Get("byteLength").Int())
			require.Equal(t, len(copied), js.CopyBytesToGo(copied, output))
			require.Equal(t, golden, copied)
		} else {
			require.Equal(t, false, result["ok"])
			require.NotContains(t, result, "output")
			require.NotContains(t, result, "metadata")
			raw, err := json.Marshal(result)
			require.NoError(t, err)
			require.NotContains(t, string(raw), "secret")
		}
		require.Equal(t, map[string]any{"ok": false, "code": "verification"}, verify(js.Undefined(), nil), "one worker must never reuse imported keys or completed verification")
	}
}
