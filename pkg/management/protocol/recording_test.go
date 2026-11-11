package protocol

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// This frozen, independent pre-extraction layout pins all field names/order and
// tags, including the absence of explicit CBOR tags and its time representation.
type legacyRecordingView struct {
	Auditlog             string    `json:"auditlog" yaml:"auditlog"`
	ID                   string    `json:"id" yaml:"id"`
	ProducerID           string    `json:"producerId" yaml:"producerId"`
	Format               string    `json:"format" yaml:"format"`
	Status               string    `json:"status" yaml:"status"`
	StartedAt            time.Time `json:"startedAt" yaml:"startedAt"`
	EndedAt              time.Time `json:"endedAt" yaml:"endedAt"`
	ContainerBytes       int64     `json:"containerBytes" yaml:"containerBytes"`
	ChunkCount           uint64    `json:"chunkCount" yaml:"chunkCount"`
	Encrypted            bool      `json:"encrypted" yaml:"encrypted"`
	RecipientFingerprint string    `json:"recipientFingerprint,omitempty" yaml:"recipientFingerprint,omitempty"`
	VerificationScope    string    `json:"verificationScope" yaml:"verificationScope"`
}

func TestPortableRecordingViewPreservesLegacyEncodings(t *testing.T) {
	for _, recipient := range []string{"", "SHA256:fixture"} {
		legacy := legacyRecordingView{Auditlog: "default", ID: "recording-id", ProducerID: "producer", Format: "native", Status: "sealed", StartedAt: time.Unix(1700000000, 123456789).UTC(), EndedAt: time.Unix(1700000001, 987654321).UTC(), ContainerBytes: 1 << 34, ChunkCount: 4, Encrypted: recipient != "", RecipientFingerprint: recipient, VerificationScope: "outer"}
		current := RecordingView{Auditlog: legacy.Auditlog, ID: legacy.ID, ProducerID: legacy.ProducerID, Format: legacy.Format, Status: legacy.Status, StartedAt: legacy.StartedAt, EndedAt: legacy.EndedAt, ContainerBytes: legacy.ContainerBytes, ChunkCount: legacy.ChunkCount, Encrypted: legacy.Encrypted, RecipientFingerprint: legacy.RecipientFingerprint, VerificationScope: legacy.VerificationScope}
		for _, encode := range []func(any) ([]byte, error){json.Marshal, yaml.Marshal, cbor.Marshal} {
			want, err := encode(legacy)
			require.NoError(t, err)
			actual, err := encode(current)
			require.NoError(t, err)
			require.Equal(t, want, actual)
		}
	}
}
