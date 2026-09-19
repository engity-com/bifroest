package recording

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	recordingFormatVectorSchema                  = "bifroest.recording-format-vectors/v1"
	recordingFormatVectorSigningSeedHex          = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	recordingFormatVectorBECastRecipientSeedByte = byte(0x42)
)

type recordingFormatVectorManifest struct {
	Schema                 string                          `json:"schema"`
	SigningSeedHex         string                          `json:"signingSeedHex"`
	BECastRecipientSeedHex string                          `json:"becastRecipientSeedHex"`
	Artifacts              []recordingFormatVectorArtifact `json:"artifacts"`
}

type recordingFormatVectorArtifact struct {
	Path         string `json:"path"`
	Format       string `json:"format"`
	Description  string `json:"description"`
	Bytes        int    `json:"bytes"`
	SHA256       string `json:"sha256"`
	Reproducible bool   `json:"reproducible"`
}

func TestRecordingFormatVectorManifest(t *testing.T) {
	payload := recordingFormatVector(t, "manifest.json")
	require.NoError(t, rejectDuplicateJSONFields(payload))
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var manifest recordingFormatVectorManifest
	require.NoError(t, decoder.Decode(&manifest))
	require.ErrorIs(t, decoder.Decode(&struct{}{}), io.EOF)
	require.Equal(t, recordingFormatVectorSchema, manifest.Schema)
	require.Equal(t, recordingFormatVectorSigningSeedHex, manifest.SigningSeedHex)
	require.Equal(t, hex.EncodeToString(bytes.Repeat([]byte{recordingFormatVectorBECastRecipientSeedByte}, 32)), manifest.BECastRecipientSeedHex)

	expected := map[string]recordingFormatVectorArtifact{
		"cast-v3.cast":          {Format: "asciicast/v3", Description: "Deterministic signed plain Cast", Reproducible: true},
		"cast-zstd-v1.cast":     {Format: "asciicast/v3", Description: "Plain Cast exported from the Cast Zstandard vector", Reproducible: true},
		"cast-zstd-v1.cast.zst": {Format: "cast-zstd/v1", Description: "Deterministic signed Cast Zstandard container", Reproducible: true},
		"becast-v1.cast":        {Format: "asciicast/v3", Description: "Plain Cast decrypted from the BECast vector", Reproducible: true},
		"becast-v1.becast":      {Format: "becast/v1", Description: "Frozen signed BECast decoder vector with randomized age ciphertext", Reproducible: false},
		"becast-header.unit":    {Format: "becast/v1-header-unit", Description: "Deterministic synthetic BECast header encoding vector", Reproducible: true},
		"becast-chunk.unit":     {Format: "becast/v1-chunk-unit", Description: "Deterministic synthetic BECast chunk encoding vector", Reproducible: true},
		"becast-seal.unit":      {Format: "becast/v1-seal-unit", Description: "Deterministic synthetic BECast seal encoding vector", Reproducible: true},
	}
	actual := make([]string, 0, len(manifest.Artifacts))
	seen := make(map[string]struct{}, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		require.Equal(t, filepath.Base(artifact.Path), artifact.Path)
		_, duplicate := seen[artifact.Path]
		require.False(t, duplicate, "duplicate artifact %q", artifact.Path)
		seen[artifact.Path] = struct{}{}
		actual = append(actual, artifact.Path)
		content := recordingFormatVector(t, artifact.Path)
		digest := sha256.Sum256(content)
		require.Equal(t, len(content), artifact.Bytes, artifact.Path)
		require.Equal(t, hex.EncodeToString(digest[:]), artifact.SHA256, artifact.Path)
		expectedArtifact, exists := expected[artifact.Path]
		require.True(t, exists, artifact.Path)
		require.Equal(t, expectedArtifact.Format, artifact.Format, artifact.Path)
		require.Equal(t, expectedArtifact.Description, artifact.Description, artifact.Path)
		require.Equal(t, expectedArtifact.Reproducible, artifact.Reproducible, artifact.Path)
	}
	sort.Strings(actual)
	expectedNames := make([]string, 0, len(expected))
	for name := range expected {
		expectedNames = append(expectedNames, name)
	}
	sort.Strings(expectedNames)
	require.Equal(t, expectedNames, actual)

	entries, err := os.ReadDir(recordingFormatVectorDirectory())
	require.NoError(t, err)
	published := make([]string, 0, len(entries))
	for _, entry := range entries {
		require.Zero(t, entry.Type()&os.ModeSymlink, entry.Name())
		info, infoErr := entry.Info()
		require.NoError(t, infoErr)
		require.True(t, info.Mode().IsRegular(), entry.Name())
		published = append(published, entry.Name())
	}
	sort.Strings(published)
	require.Equal(t, append(expectedNames, "manifest.json"), published)
}

func TestPublishedBECastFormatVector(t *testing.T) {
	container := recordingFormatVector(t, "becast-v1.becast")
	expectedCast := recordingFormatVector(t, "becast-v1.cast")
	generated := newBECastVerifierFixture(t)
	require.Equal(t, expectedCast, generated.plaintext)
	identity, _, _ := castTestValues(t, true)
	_, identities := newBECastTestEncryption(t)
	outer, err := VerifyBECast(bytes.NewReader(container), int64(len(container)), BECastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.True(t, outer.Trusted)
	require.Nil(t, outer.Cast)

	var exported bytes.Buffer
	verification, err := DecryptBECast(bytes.NewReader(container), int64(len(container)), identities, &exported, BECastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, expectedCast, exported.Bytes())
	require.NotNil(t, verification.Cast)
	require.True(t, verification.Trusted)
	require.True(t, verification.Cast.Trusted)
	require.Equal(t, verification.Summary.Digest, verification.Cast.Digest)
}

func recordingFormatVector(t *testing.T, name string) []byte {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(recordingFormatVectorDirectory(), name))
	require.NoError(t, err)
	return payload
}

func recordingFormatVectorDirectory() string {
	return filepath.Join("..", "..", "docs", "assets", "recording-format-vectors", "v1")
}
