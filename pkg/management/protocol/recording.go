package protocol

import "time"

// MaximumRecordingPageSize is shared by sealed-artifact selection and its wire
// decoder. It is not the smaller HTTP metadata page size.
const MaximumRecordingPageSize uint = 1000

// RecordingView preserves the existing CLI/CBOR data shape, without importing
// CLI, configuration, storage or recording producers into portable clients.
type RecordingView struct {
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

// RecordingSummary extends only the authenticated management catalog. The
// legacy CLI RecordingView and its UUID-ordered streaming contract stay intact.
// Older recordings lack a requesting user; target accounts are not recorded.
// Missing context stays unknown rather than being inferred from live accounts.
type RecordingSummary struct {
	RecordingView
	Flow                string `json:"flow,omitempty"`
	SessionID           string `json:"sessionId,omitempty"`
	User                string `json:"user,omitempty"`
	Target              string `json:"target,omitempty"`
	MetadataUnavailable bool   `json:"metadataUnavailable,omitempty"`
}
