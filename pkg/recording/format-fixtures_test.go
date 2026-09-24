package recording

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	recordingFormatVectorSigningSeedHex          = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	recordingFormatVectorBECastRecipientSeedByte = byte(0x42)
)

type recordingFormatVectorArtifact struct {
	Path         string `json:"path"`
	Format       string `json:"format"`
	Description  string `json:"description"`
	Bytes        int    `json:"bytes"`
	SHA256       string `json:"sha256"`
	Reproducible bool   `json:"reproducible"`
}

func recordingFormatVector(t *testing.T, name string) []byte {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(recordingFormatVectorDirectory(), name))
	require.NoError(t, err)
	return payload
}

func recordingFormatVectorDirectory() string {
	return filepath.Join("..", "..", "docs", "assets", "recording-format-vectors")
}
